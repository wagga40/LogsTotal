"""Run a child process under a deadline, a cancel flag and an optional watchdog.

Extracted from `ToolAdapter._exec`, which delegates here unchanged, so the event-store build
gets the same guarantees the detection tools have:

- The child runs in its own session, so a timeout or a cancel kills the **whole process
  group**. `subprocess.run(timeout=)` kills only the direct child, and a grandchild that
  inherited the pipes then blocks the drain indefinitely.
- `communicate(timeout=tick)`, never `wait()`: wait() with full pipe buffers deadlocks, while
  communicate() can be re-called after TimeoutExpired and keeps draining.
- `on_tick(proc)` runs between ticks; returning a reason kills the group and reports it. The
  store build uses it as an RSS watchdog: an address-space rlimit would trip false OOMs on
  allocators that reserve far more than they touch.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path

CANCELLED = "cancelled"


def kill_process_group(proc: subprocess.Popen) -> None:
    """SIGKILL the child's whole process group (start_new_session makes pgid == pid)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        proc.kill()


def rss_bytes(pid: int) -> int | None:
    """Resident set size of *pid* from /proc (Linux); None where that is not available."""
    try:
        with open(f"/proc/{pid}/status", encoding="ascii", errors="replace") as status:
            for line in status:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def run_supervised(
    cmd: list[str],
    *,
    timeout: float,
    cancel_event: threading.Event | None = None,
    stdout_path: Path | None = None,
    env: dict[str, str] | None = None,
    on_tick: Callable[[subprocess.Popen], str | None] | None = None,
    cwd: str | Path | None = None,
) -> tuple[int, str, str]:
    """(returncode, stdout, stderr); -1 with the reason in stderr when the child was stopped."""
    if cancel_event is not None and cancel_event.is_set():
        return -1, "", CANCELLED
    with contextlib.ExitStack() as stack:
        stdout_file = stack.enter_context(stdout_path.open("wb")) if stdout_path is not None else subprocess.PIPE
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=stdout_file,
                env=env,
                cwd=cwd,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,  # Security invariant: never execute a command via a shell.
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            return -1, "", f"Executable not found: {exc}"
        except PermissionError:
            binary_path = cmd[0] if cmd else "?"
            return -1, "", f"Binary is not executable: {binary_path}. Try: chmod +x {binary_path}"

        deadline = time.monotonic() + timeout
        while True:
            tick = max(0.05, min(1.0, deadline - time.monotonic()))
            try:
                stdout, stderr = proc.communicate(timeout=tick)
                return proc.returncode, stdout or "", stderr
            except subprocess.TimeoutExpired:
                cancelled = cancel_event is not None and cancel_event.is_set()
                reason = on_tick(proc) if on_tick is not None and not cancelled else None
                if not cancelled and reason is None and time.monotonic() < deadline:
                    continue
                kill_process_group(proc)
                try:
                    proc.communicate(timeout=5)  # group is dead → pipes close → fast drain
                except subprocess.TimeoutExpired:
                    # A double-forked daemon escaped the group and still holds the pipes:
                    # give up on output rather than block the worker.
                    for stream in (proc.stdout, proc.stderr):
                        if stream is not None:
                            with contextlib.suppress(Exception):
                                stream.close()
                if cancelled:
                    return -1, "", CANCELLED
                if reason is not None:
                    return -1, "", reason
                return -1, "", f"Command timed out after {timeout:g}s"
