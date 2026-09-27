"""Base classes for detection tool adapters — ABC, dataclasses, execution logic."""

from __future__ import annotations

import contextlib
import logging
import os
import platform
import signal
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.json_utils import load_file as json_load_file
from app.json_utils import loads as json_loads


def apply_registry_prefix(image: str) -> str:
    """``image`` served from REGISTRY_PREFIX instead of its default registry.

    For a network with no route to Docker Hub that does run a mirror. Empty by default;
    `./logstotal bundle` is the answer for a network with no registry at all.

    Read from the environment rather than ``app.config.Settings`` on purpose: this module
    is a tool adapter, and the convention here is that adapters import nothing but pure
    helpers — the same reason ``DOCKER_HOST_WORKDIR`` is read this way below.

    The digest is preserved. A mirror serving different content under the same digest is
    not a mirror, so a pull through one is verified exactly as a pull from the origin is.
    An image that already names a registry host is left alone: it has been told where to
    come from. Docker's own rule for that is what is implemented — the part before the
    FIRST SLASH is a host only if it contains a dot or a colon (or is `localhost`) *and*
    there is a slash at all. The `and` is load-bearing: `redis:7-alpine` is a name and a
    tag, not a host and a port, and treating its colon as a registry would leave every
    library image unprefixed.
    """
    prefix = os.environ.get("REGISTRY_PREFIX", "").strip().rstrip("/")
    if not prefix or not image:
        return image
    head, slash, _ = image.partition("/")
    if slash and ("." in head or ":" in head or head == "localhost"):
        return image
    return f"{prefix}/{image}"


def apply_bundled_images(image: str) -> str:
    """``image`` without its digest, when this host's images came from a bundle.

    A digest-pinned reference cannot survive ``docker save``: the tarball records
    ``RepoTags:null`` (a digest is not a tag), so ``docker load`` on the far side yields a
    dangling image with empty RepoTags AND RepoDigests. Running the workflow's reference then
    goes to the network for a manifest an air-gapped host cannot reach — the Windows path
    failing hours after an install that reported green.

    The pin is not discarded, it moves: ``scripts/bundle.sh`` resolves the digest against the
    real registry when the bundle is BUILT, on a machine that has a network, and the bundle
    carries a sha256 of itself from there. Verify-at-build instead of verify-at-run is the
    air-gap trade, and it is only taken where it is the difference between working and not —
    LOGSTOTAL_BUNDLED_IMAGES is set by the deploy on hosts that were loaded from a bundle,
    and nowhere else. An ordinary install keeps the digest and pulls normally.

    Read from the environment for the reason ``apply_registry_prefix`` documents.
    """
    if os.environ.get("LOGSTOTAL_BUNDLED_IMAGES", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return image
    head, sep, _ = image.partition("@sha256:")
    return head if sep else image


_log = logging.getLogger(__name__)

# Thread cap passed to CPU-bound tools when a workflow task omits ``threads:``.
# LogsTotal always sends an explicit cap so tools never grab every logical core.
DEFAULT_TOOL_THREADS = 1

# Sentinel error string for tools aborted by job cancellation; the worker maps
# it to TaskStatus.CANCELLED (see app/workers/tasks.py::_persist_tool_result).
CANCELLED_ERROR = "cancelled"


def _kill_process_group(proc: subprocess.Popen) -> None:
    """SIGKILL the child's whole process group.

    ``start_new_session=True`` makes the child a session/group leader
    (pgid == pid), so this also kills grandchildren that would otherwise
    survive and keep the output pipes open."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        proc.kill()


@lru_cache(maxsize=1)
def _current_arch() -> str:
    """Return normalised ``{machine}-{system}`` string for the running host.

    ARM variants (``arm64`` on macOS, ``aarch64`` on Linux) are both
    normalised to ``aarch64`` so workflow YAMLs only need one key.
    """
    machine = platform.machine().lower()
    if machine == "arm64":
        machine = "aarch64"
    system = platform.system().lower()
    return f"{machine}-{system}"


def resolve_tool_path(raw: str | dict[str, str] | None) -> tuple[str | None, str | None]:
    """Resolve a workflow ``tool_path`` value which may be a plain string or
    an arch-keyed dict.

    Returns ``(resolved_path, skip_reason)``.  When the value is a dict and
    the current architecture has no entry, *resolved_path* is ``None`` and
    *skip_reason* explains why.
    """
    if raw is None:
        return None, None
    if isinstance(raw, str):
        return raw, None
    if isinstance(raw, dict):
        arch = _current_arch()
        path = raw.get(arch)
        if path:
            return path, None
        # Try common aliases (arm64 <-> aarch64)
        alt = arch.replace("aarch64", "arm64") if "aarch64" in arch else arch.replace("arm64", "aarch64")
        path = raw.get(alt)
        if path:
            return path, None
        available = ", ".join(sorted(raw.keys())) or "(none)"
        return None, f"No binary for architecture {arch} (available: {available})"
    return None, f"Invalid tool_path type: {type(raw).__name__}"


@dataclass
class NormalizedFinding:
    """Tool-agnostic finding produced by a ToolAdapter.normalize() call."""

    rule_name: str
    severity: str  # critical / high / medium / low / informational
    count: int = 1
    rule_id: str = ""
    tags: list[str] = field(default_factory=list)
    details: list[dict] = field(default_factory=list)  # sample matched events (cap: the adapter's max_details, from SiteSettings.max_finding_details)
    rule_content: str = ""  # original rule YAML/definition (optional)


@dataclass
class ToolOutput:
    """Return value of ToolAdapter.run() — success flag, findings, and diagnostics."""

    success: bool
    findings: list[NormalizedFinding] = field(default_factory=list)
    error: str = ""
    duration_ms: int = 0
    stdout: str = ""
    stderr: str = ""


class ToolAdapter(ABC):
    """Base class for all detection tool adapters.

    Supports three execution modes selected by workflow config keys:

    - **tool_path**: run a local binary / script directly.
    - **docker_image**: run inside a pre-built Docker image.
    - **dockerfile**: build an image from a Dockerfile, then run it.

    Subclasses implement ``_build_local_cmd`` and ``_docker_tool_args``
    for tool-specific command-line arguments, ``_output_filename`` for the
    expected output file name, and ``normalize`` for findings extraction.
    Override ``_load_output`` when the tool emits JSONL instead of JSON.
    """

    name: str = "base"
    SUPPORTED_TYPES: set[str] | None = None  # override in subclass to restrict by log type

    _CONTAINER_CASE = "/case"
    _CONTAINER_RULES = "/rules"
    _CONTAINER_OUT = "/out"

    def __init__(self, config: dict[str, Any]):
        self.config = config
        # `rules_path` accepts a string or a list of strings, mirroring the str-or-dict
        # shape `tool_path` has. Chainsaw is the reason: SigmaHQ splits its rules across
        # `rules/`, `rules-emerging-threats/` and `rules-threat-hunting/`, and pointing at
        # their common parent sweeps in `deprecated/`, `unsupported/`, `rules-placeholder/`
        # and `regression_data/` as well, none of which are rules that should fire.
        #
        # `rules_path` is the *first* entry, for single-path consumers (the Docker mount,
        # zircolite's sibling-config resolution, hayabusa); `rules_paths` is
        # the full list, and only an adapter that knows what to do with more than one reads
        # it. `_build_rule_index` scans them all, or a finding from a rule in the second
        # directory would come back with empty `rule_content`.
        raw_rules = config.get("rules_path", "sigma_rules")
        if isinstance(raw_rules, str) and raw_rules:
            self.rules_paths: list[str] = [raw_rules]
        elif isinstance(raw_rules, list) and raw_rules and all(isinstance(p, str) and p for p in raw_rules):
            self.rules_paths = list(raw_rules)
        else:
            raise ValueError(f"Task '{self.name}' has invalid rules_path: expected a non-empty string or list of non-empty strings.")
        self.rules_path: str = self.rules_paths[0]
        self.max_details: int = int(config.get("max_finding_details", 10))
        self._timeout_seconds: int = self._normalize_timeout(config.get("timeout", 300))
        extra_args = config.get("extra_args", [])
        if not isinstance(extra_args, list) or any(not isinstance(arg, str) for arg in extra_args):
            raise ValueError(f"Task '{self.name}' has invalid extra_args: expected list[str].")
        self._extra_args: list[str] = extra_args
        threads = config.get("threads")
        self._threads: int = int(threads) if threads is not None else DEFAULT_TOOL_THREADS
        # Set by run() before command construction; safe because the worker creates
        # one adapter instance per task (see app/workers/tasks.py get_adapter call).
        self._log_type: str | None = None
        self._input_path: Path | None = None
        self._cancel_event: threading.Event | None = None

    # ── public entry point ───────────────────────────────────────────────

    def run(
        self,
        file_path: Path,
        output_dir: Path,
        log_type: str | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ToolOutput:
        """Route to local or Docker execution based on config."""
        supported = getattr(self.__class__, "SUPPORTED_TYPES", None)
        if supported is not None and log_type is not None and log_type not in supported:
            return ToolOutput(success=False, error="not supported")
        self._cancel_event = cancel_event
        if cancel_event is not None and cancel_event.is_set():
            return ToolOutput(success=False, error=CANCELLED_ERROR)
        self._log_type = log_type
        # The host path of the file being analysed. Adapters building *container*
        # arguments still sometimes need to look at the real bytes — Zircolite picks
        # between two mutually exclusive XML parsers by sniffing the root element.
        self._input_path = file_path
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / self._output_filename(file_path)

        raw_tool_path = self.config.get("tool_path")
        if raw_tool_path is not None:
            resolved, skip_reason = resolve_tool_path(raw_tool_path)
            if skip_reason:
                return ToolOutput(success=False, error=f"arch:skip:{skip_reason}")
            if resolved:
                self.config["tool_path"] = resolved
                return self._run_local(file_path, output_file)

        if self.config.get("docker_image") or self.config.get("dockerfile"):
            return self._run_docker(file_path, output_file, output_dir)

        return ToolOutput(
            success=False,
            error=(f"Workflow task for {self.name} must set tool_path, docker_image, or dockerfile"),
        )

    # ── local execution ──────────────────────────────────────────────────

    def _run_local(self, file_path: Path, output_file: Path) -> ToolOutput:
        tool_path = Path(self.config["tool_path"])
        cmd, err = self._build_local_cmd(tool_path, file_path, output_file)
        if err:
            return ToolOutput(success=False, error=err)
        return self._execute_and_parse(cmd, output_file)

    def _build_local_cmd(
        self,
        tool_path: Path,
        file_path: Path,
        output_file: Path,
    ) -> tuple[list[str] | None, str]:
        """Build the local command line.  Override in subclass."""
        return None, f"{self.name} does not support local execution"

    # ── docker execution ─────────────────────────────────────────────────

    def _run_docker(
        self,
        file_path: Path,
        output_file: Path,
        output_dir: Path,
    ) -> ToolOutput:
        image, err = self._resolve_docker_image()
        if err:
            return ToolOutput(success=False, error=err)

        abs_file = file_path.resolve()
        abs_rules = Path(self.rules_path).resolve()
        abs_out = output_dir.resolve()

        # The Docker runner binds exactly one rules path at /rules. A multi-path task would
        # otherwise run against only the first, quietly, and report a clean result from a
        # fraction of the ruleset — the worst possible failure on a detection platform.
        if len(self.rules_paths) > 1:
            return ToolOutput(
                success=False,
                error=f"Task '{self.name}' lists {len(self.rules_paths)} rules paths, but the Docker runner binds only one. Use a single rules_path for Docker-executed tools.",
            )

        if not abs_rules.exists():
            return ToolOutput(success=False, error=f"Rules path not found: {abs_rules}")

        if abs_rules.is_file():
            rules_bind_src = str(abs_rules.parent)
            container_rules = f"{self._CONTAINER_RULES}/{abs_rules.name}"
        else:
            rules_bind_src = str(abs_rules)
            container_rules = self._CONTAINER_RULES

        container_log = f"{self._CONTAINER_CASE}/{abs_file.name}"
        container_out = f"{self._CONTAINER_OUT}/{output_file.name}"

        try:
            tool_args = self._docker_tool_args(container_log, container_rules, container_out)
        except NotImplementedError as exc:
            return ToolOutput(success=False, error=str(exc))

        volumes = {
            self._to_host_path(abs_file.parent): {"bind": self._CONTAINER_CASE, "mode": "ro"},
            self._to_host_path(Path(rules_bind_src)): {"bind": self._CONTAINER_RULES, "mode": "ro"},
            self._to_host_path(abs_out): {"bind": self._CONTAINER_OUT, "mode": "rw"},
        }
        docker_options = self.config.get("docker_options", [])
        if not isinstance(docker_options, list) or any(not isinstance(opt, str) for opt in docker_options):
            return ToolOutput(success=False, error=f"Task '{self.name}' has invalid docker_options: expected list[str].")
        for extra in docker_options:
            parts = extra.split(":")
            if len(parts) >= 2:
                volumes[parts[0]] = {"bind": parts[1], "mode": parts[2] if len(parts) > 2 else "rw"}

        t0 = time.monotonic()
        stdout = stderr = ""
        run_timeout = self._timeout_seconds
        try:
            import docker as _docker_sdk

            # Use create + start + wait(timeout) so workflow timeout is a real runtime cap.
            # from_env(timeout=...) is only for API client operations, not container runtime.
            client = _docker_sdk.from_env(timeout=run_timeout + 60)
            try:
                client.images.get(image)
            except _docker_sdk.errors.ImageNotFound:
                client.images.pull(image)
            container = client.containers.create(
                image,
                tool_args,
                volumes=volumes,
                detach=True,
            )
            container.start()
            deadline = time.monotonic() + run_timeout
            exit_code: int | None = None
            while exit_code is None:
                cancelled = self._cancel_event is not None and self._cancel_event.is_set()
                remaining = deadline - time.monotonic()
                if cancelled or remaining <= 0:
                    with contextlib.suppress(Exception):
                        container.kill()
                    with contextlib.suppress(Exception):
                        container.remove(force=True)
                    duration_ms = int((time.monotonic() - t0) * 1000)
                    return ToolOutput(
                        success=False,
                        error=CANCELLED_ERROR if cancelled else f"Container timed out after {run_timeout}s",
                        duration_ms=duration_ms,
                    )
                try:
                    result = container.wait(timeout=min(2, remaining))
                    exit_code = result.get("StatusCode", -1)
                except Exception:
                    # Per-tick timeout (docker SDK raises requests read timeouts).
                    # Also masks a genuine API error until the deadline — bounded.
                    continue
            try:
                out_bytes = container.logs(stdout=True, stderr=True)
                stdout = out_bytes.decode("utf-8", errors="replace") if out_bytes else ""
            finally:
                container.remove(force=True)

            if exit_code != 0 and not output_file.exists():
                duration_ms = int((time.monotonic() - t0) * 1000)
                return ToolOutput(success=False, error=stdout or f"Container exited with code {exit_code}", duration_ms=duration_ms)
        except Exception as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            err = str(exc)
            if "No such file or directory" in err:
                err += (
                    " — Docker tools need the host daemon socket inside this container "
                    "(mount /var/run/docker.sock) and DOCKER_HOST_WORKDIR set to the host project path; "
                    "see the worker service in docker-compose.yml / docker-compose.worker.yml."
                )
            return ToolOutput(success=False, error=err, duration_ms=duration_ms)

        duration_ms = int((time.monotonic() - t0) * 1000)

        if not output_file.exists():
            return ToolOutput(success=True, findings=[], stdout=stdout, stderr=stderr, duration_ms=duration_ms)

        try:
            raw = self._load_output(output_file)
            findings = self.normalize(raw)
            return ToolOutput(success=True, findings=findings, stdout=stdout, stderr=stderr, duration_ms=duration_ms)
        except Exception as exc:
            return ToolOutput(success=False, error=f"Failed to parse output: {exc}", stdout=stdout, stderr=stderr, duration_ms=duration_ms)

    def _docker_tool_args(
        self,
        container_log: str,
        container_rules: str,
        container_out: str,
    ) -> list[str]:
        """Return tool-specific arguments for the Docker entrypoint.
        Override in subclass."""
        raise NotImplementedError(f"{self.name} does not define Docker tool arguments")

    def _resolve_docker_image(self) -> tuple[str | None, str]:
        """Resolve Docker image: build from Dockerfile or use registry image.
        Returns ``(image_tag, "")`` on success, ``(None, error)`` on failure.
        """
        dockerfile = self.config.get("dockerfile")
        docker_image = self.config.get("docker_image")

        if dockerfile:
            path = Path(dockerfile)
            if not path.is_absolute():
                path = (Path.cwd() / path).resolve()
            if not path.exists():
                return None, f"Dockerfile not found: {path}"

            context = self.config.get("docker_build_context")
            if context:
                ctx_path = Path(context)
                if not ctx_path.is_absolute():
                    ctx_path = (Path.cwd() / ctx_path).resolve()
                if not ctx_path.is_dir():
                    return None, (f"Build context not found or not a directory: {ctx_path}")
            else:
                ctx_path = path.parent

            tag = self.config.get("docker_build_tag") or f"logstotal-{self.name}:local"
            build_timeout = self.config.get("docker_build_timeout", 600)
            rc, stdout, stderr = self._exec(
                ["docker", "build", "-t", tag, "-f", str(path), str(ctx_path)],
                timeout=build_timeout,
                cancel_event=self._cancel_event,
            )
            if rc != 0:
                return None, f"docker build failed: {stderr or stdout}"
            return tag, ""

        if docker_image:
            return apply_registry_prefix(apply_bundled_images(docker_image)), ""

        return None, f"No docker_image or dockerfile configured for {self.name}"

    # ── common execute-and-parse pattern ─────────────────────────────────

    def _execute_and_parse(
        self,
        cmd: list[str],
        output_file: Path,
    ) -> ToolOutput:
        """Run *cmd*, load the output file, normalize, return ToolOutput."""
        t0 = time.monotonic()
        rc, stdout, stderr = self._exec(
            cmd,
            timeout=self._timeout_seconds,
            cancel_event=self._cancel_event,
        )
        duration_ms = int((time.monotonic() - t0) * 1000)

        # Timed-out (rc == -1) or other failure: treat as failure even if partial output exists.
        if rc != 0:
            return ToolOutput(
                success=False,
                error=stderr or stdout or (f"Command timed out after {self._timeout_seconds}s" if rc == -1 else f"Exit code {rc}"),
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
            )

        if not output_file.exists():
            return ToolOutput(
                success=True,
                findings=[],
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
            )

        try:
            raw = self._load_output(output_file)
            findings = self.normalize(raw)
            return ToolOutput(
                success=True,
                findings=findings,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
            )
        except Exception as exc:
            return ToolOutput(
                success=False,
                error=f"Failed to parse output: {exc}",
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
            )

    # ── output loading ───────────────────────────────────────────────────

    def _load_output(self, path: Path) -> Any:
        """Load tool output file.  Default: JSON.  Override for JSONL."""
        return self._load_json(path)

    @abstractmethod
    def _output_filename(self, file_path: Path) -> str:
        """Return the expected output filename for this tool."""
        ...

    @abstractmethod
    def normalize(self, raw: Any) -> list[NormalizedFinding]: ...

    # ── shared helpers ───────────────────────────────────────────────────

    # Shared across all adapters: {newline-joined resolved rules paths: {rule_id: filepath}}
    _rule_index_cache: dict[str, dict[str, str]] = {}

    def _lookup_rule_yaml(self, rule_id: str) -> str:
        """Find a YAML rule file matching rule_id in any of self.rules_paths.
        Returns raw YAML text, or empty string if not found.
        Uses a shared cache keyed on all of those paths to avoid repeated dir scans.
        """
        if not rule_id:
            return ""
        if not hasattr(self, "_rule_index"):
            self._rule_index = self._get_or_build_rule_index()
        path = self._rule_index.get(rule_id)
        if path:
            try:
                return Path(path).read_text(encoding="utf-8")
            except OSError:
                return ""
        return ""

    def _get_or_build_rule_index(self) -> dict[str, str]:
        """Return cached rule index for these rules paths, building it on first access."""
        # Keyed on every path, not just the first: two tasks sharing a first directory but
        # differing after it would otherwise collide in the cache and one would silently
        # serve the other's index.
        resolved = "\n".join(str(Path(p).resolve()) for p in self.rules_paths)
        if resolved not in ToolAdapter._rule_index_cache:
            ToolAdapter._rule_index_cache[resolved] = self._build_rule_index()
        return ToolAdapter._rule_index_cache[resolved]

    def _build_rule_index(self) -> dict[str, str]:
        """Scan every rules path for YAML files and build a {rule_id: filepath} map."""
        from app.yaml_utils import safe_load as yaml_safe_load

        index: dict[str, str] = {}
        for rules_path in self.rules_paths:
            rules_dir = Path(rules_path)
            if not rules_dir.is_dir():
                continue
            for yml_file in rules_dir.rglob("*.yml"):
                try:
                    with open(yml_file, encoding="utf-8") as f:
                        data = yaml_safe_load(f)
                    if isinstance(data, dict) and data.get("id"):
                        index[data["id"]] = str(yml_file)
                except Exception:
                    continue
        return index

    @staticmethod
    def _to_host_path(abs_path: Path) -> str:
        """Translate a container-internal absolute path to the host path used
        when mounting volumes in sibling containers (Docker-outside-of-Docker).

        When DOCKER_HOST_WORKDIR is set (e.g. to ${PWD} in docker-compose),
        paths under /app (the Dockerfile WORKDIR) are remapped to the host
        project directory. In local dev the env var is absent and paths are
        returned unchanged."""
        host_workdir = os.environ.get("DOCKER_HOST_WORKDIR", "")
        if not host_workdir:
            return str(abs_path)
        try:
            rel = abs_path.relative_to("/app")
            return str(Path(host_workdir) / rel)
        except ValueError:
            return str(abs_path)

    @staticmethod
    def _normalize_timeout(value: Any) -> int:
        """Return workflow timeout in seconds; clamp to [1, 86400]. Invalid values become 300."""
        try:
            sec = int(value) if value is not None else 300
        except (TypeError, ValueError):
            return 300
        return max(1, min(86400, sec))

    @staticmethod
    def _check_binary_executable(path: Path) -> str | None:
        """Return None if *path* exists and is executable, else an error."""
        if not path.exists():
            return f"Binary not found: {path}"
        if not os.access(path, os.X_OK):
            return f"Binary is not executable: {path}. Try: chmod +x {path}"
        return None

    @staticmethod
    def _exec(cmd: list[str], timeout: int = 300, cancel_event: threading.Event | None = None) -> tuple[int, str, str]:
        """Run a subprocess and return (returncode, stdout, stderr).

        The child runs in its own process group so the timeout (or a job
        cancellation) kills the whole tree — ``subprocess.run(timeout=...)``
        only kills the direct child, and a grandchild inheriting the output
        pipes then blocks the drain indefinitely.
        """
        if cancel_event is not None and cancel_event.is_set():
            return -1, "", CANCELLED_ERROR
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,  # Security invariant: never execute tool commands via a shell.
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            return -1, "", f"Executable not found: {exc}"
        except PermissionError:
            binary_path = cmd[0] if cmd else "?"
            return (
                -1,
                "",
                f"Binary is not executable: {binary_path}. Try: chmod +x {binary_path}",
            )

        deadline = time.monotonic() + timeout
        while True:
            # communicate(timeout=tick), never wait(): wait() with full pipe
            # buffers deadlocks; communicate() is safely re-callable after
            # TimeoutExpired and keeps draining in reader threads.
            tick = max(0.05, min(1.0, deadline - time.monotonic()))
            try:
                stdout, stderr = proc.communicate(timeout=tick)
                return proc.returncode, stdout, stderr
            except subprocess.TimeoutExpired:
                cancelled = cancel_event is not None and cancel_event.is_set()
                if not cancelled and time.monotonic() < deadline:
                    continue
                _kill_process_group(proc)
                try:
                    proc.communicate(timeout=5)  # group is dead → pipes close → fast drain
                except subprocess.TimeoutExpired:
                    # A double-forked daemon escaped the group and still holds
                    # the pipes — give up on output rather than block the worker.
                    for stream in (proc.stdout, proc.stderr):
                        if stream is not None:
                            with contextlib.suppress(Exception):
                                stream.close()
                if cancelled:
                    return -1, "", CANCELLED_ERROR
                return -1, "", f"Command timed out after {timeout}s"

    @staticmethod
    def _normalize_severity(raw: Any) -> str:
        """Map a tool's severity string onto ours, defaulting to ``informational``.

        Takes ``Any``, not ``str``: every caller feeds it a value straight out of parsed
        tool output, where a null level or a numeric one is ordinary. ``raw.lower()`` on
        those would raise ``AttributeError`` out of ``normalize()`` and take the whole
        file's findings with it.
        """
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "med": "medium",
            "low": "low",
            "informational": "informational",
            "info": "informational",
            "notice": "informational",
        }
        if not isinstance(raw, str):
            raw = "" if raw is None else str(raw)
        return mapping.get(raw.lower(), "informational")

    @classmethod
    def _dict_records(cls, raw: Any) -> list[dict]:
        """The dict records of a parsed output file, with everything else dropped.

        A tool writes NDJSON incrementally, so a truncated final line, a stray scalar or a
        null is the normal shape of output from a process that was killed or ran out of
        disk. Handing one of those to ``event.get(...)`` would raise, and because
        ``ToolAdapter.run`` catches around the whole of ``normalize()``, the tool would report
        **0 findings** — which in a detection product reads as *clean*, not *broken*.
        """
        if not isinstance(raw, list):
            return []
        records = [r for r in raw if isinstance(r, dict)]
        dropped = len(raw) - len(records)
        if dropped:
            _log.warning("%s: skipped %d malformed record(s) in tool output", cls.__name__, dropped)
        return records

    @staticmethod
    def _load_json(path: Path) -> Any:
        return json_load_file(path)

    @staticmethod
    def _load_jsonl(path: Path) -> list[Any]:
        """Load NDJSON / JSONL (one JSON object per line).
        Malformed lines are silently skipped.
        """
        out: list[Any] = []
        with open(path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json_loads(line))
                except (ValueError, KeyError):
                    continue
        return out
