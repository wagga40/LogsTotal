"""Application settings loaded from environment variables and .env file."""

from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The four ways the bundled Caddy profile can terminate TLS. Shared with
# docker-caddy-entrypoint.sh (which validates independently — it is a separate container and
# a separate language) and with scripts/proxy_enable.py.
PROXY_TLS_MODES = frozenset({"acme", "internal", "custom", "off"})


def version_from_manifest(text: str) -> str | None:
    """The `version:` value from a VERSION manifest, or None.

    Tolerant by design, and the tolerance is the point: a host upgraded from 0.9.3 still
    carries the four-key manifest an older release stamped (version / git_sha /
    git_branch / build_date). Nothing writes those, but the file on disk survives
    until the next release lands on that host, so every unknown key has to fall through
    rather than raise. Kept as a line loop for the same reason — a whole-file regex would
    not degrade the same way on a manifest shape nobody has thought of yet.
    """
    for line in text.splitlines():
        key, _, value = line.partition(":")
        value = value.strip()
        if key == "version" and value:
            return value
    return None


class Settings(BaseSettings):
    """Pydantic-settings model; auto-derives SYNC_DATABASE_URL when not set."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    app_name: str = "LogsTotal"
    app_version: str = "1.0.0"
    secret_key: str = "change-me-in-production"  # noqa: S105  # placeholder; model_validator refuses to boot with it
    debug: bool = False
    # When DEBUG=false, auth cookies are Secure (HTTPS only). Set COOKIE_INSECURE=true for plain
    # HTTP (localhost:8000, Docker without reverse-proxy TLS) so login works in the browser.
    cookie_insecure: bool = False
    log_level: str = "INFO"
    # `text` (human) or `json` (one object per line, for a log shipper). Both the web and
    # worker processes honour it, and LOG_LEVEL.
    log_format: str = "text"
    # One structured access line per request, with a duration and the correlation id.
    # Off by default: it is a real per-request cost and most operators want it only while
    # diagnosing. /static/ and /health are never logged either way.
    request_log_enabled: bool = False
    disable_csp: bool = False
    enable_hsts: bool = False
    hsts_max_age: int = 63072000  # 2 years
    # How the bundled Caddy profile terminates TLS. `acme` (the default) is Let's Encrypt
    # against a public DOMAIN; `internal` uses Caddy's own CA (no DNS, no port 80, no
    # internet), for an internal or air-gapped network; `custom` serves the
    # operator's certificate; `off` serves plain HTTP, for a network where something in
    # front already terminates TLS. The app reads it — rather than leaving it to
    # docker-caddy-entrypoint.sh alone — because the cookie and HSTS advice in
    # app/system_checks.py is actively wrong under `off` otherwise.
    proxy_tls: str = "acme"
    login_rate_limit_per_minute: int = 20
    resubmit_rate_limit_per_minute: int = 10

    # Database
    database_url: str = "sqlite+aiosqlite:///./logstotal.db"
    sync_database_url: str | None = None
    # Run Alembic migrations automatically at startup (web/init only, never workers).
    # Set false as an escape hatch to boot on the legacy create_all path while
    # investigating a failed migration.
    auto_migrate: bool = True

    # Redis / Huey
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""
    redis_url: str | None = None
    redis_expose: str | None = None
    postgres_expose: str | None = None
    garage_expose: str | None = None
    compose_profiles: str = ""

    # Storage
    upload_dir: Path = Path("uploads")
    max_upload_size_mb: int = 500
    storage_backend: str = "local"  # "local" or "s3"
    s3_endpoint: str | None = None
    s3_bucket: str = "logstotal"
    s3_access_key: str | None = None
    s3_secret_key: str | None = None
    s3_region: str = "logstotal"

    # Analytics entity extraction (job detail view)
    analytics_fields_path: Path = Path("config/analytics_fields.yaml")

    # Threat detection heuristic patterns
    threat_detection_config_path: Path = Path("config/threat_detection.yaml")

    # PostgreSQL connection pool (ignored when using SQLite)
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_recycle: int = 300

    # A registry to pull tool images from, instead of Docker Hub.
    #
    # For a network that has no route to Docker Hub but does run a mirror. Prepended to
    # every `docker_image:` a workflow names, so `wagga40/zircolite:3.8.1@sha256:...`
    # becomes `registry.internal/wagga40/zircolite:3.8.1@sha256:...`.
    #
    # The digest is preserved deliberately: a mirror that serves different content under
    # the same digest is not a mirror, and keeping it means a pull through one is checked
    # exactly as a pull from the origin would be.
    #
    # Empty by default: images come from Docker Hub. The other answer for a closed network
    # is `task bundle`, which needs no registry at all.
    registry_prefix: str = ""

    # Worker tuning
    tool_max_workers: int = 2
    max_log_output_bytes: int = 50 * 1024  # 50 KB cap on stored stdout/stderr per task
    # Huey queue expiry: tasks not picked up within this many seconds are discarded.
    # NOT an execution timeout — per-task runtime is controlled by ``timeout`` in workflow YAML.
    huey_queue_expiry: int = 1800  # 30 min default
    huey_task_timeout: int | None = None  # deprecated alias for huey_queue_expiry
    worker_name: str | None = None
    worker_ip: str | None = None
    worker_heartbeat_ttl: int = 60  # seconds before a heartbeat key expires in Redis
    worker_heartbeat_interval: int = 30  # seconds between heartbeat refreshes
    worker_alive_ttl: int = 180  # seconds before an idle worker disappears from fleet view

    # Age at which a job's raw tool outputs are removed, by the daily sweep
    # (`cleanup_job_outputs_periodic`) and by `POST /admin/cleanup-outputs`. 0 = keep
    # forever. Findings, analytics and the events timeline all survive — they are already
    # in the database; what goes is the raw output that "Recalculate analytics", the
    # process tree and the RAW ZIP export read from disk.
    #
    # Non-zero by default: at 0 an unattended public instance grows raw outputs without
    # bound until the volume fills — and a full volume stops SQLite writes, so it takes the
    # application down rather than just the uploads.
    job_output_retention_days: int = 90

    # Upper bound on matched events read from one job's raw tool output in a single
    # analytics pass. Bounds the worker's CPU and — for the process tree, which still
    # materialises — its memory. Raising it makes analytics, entities and the timelines
    # describe more of a very large job; findings are unaffected either way, since those
    # come from the tools.
    max_parse_events: int = 250_000

    # Anonymous uploads per client IP per minute, shared through Redis (0 = no limit).
    upload_rate_limit_per_minute: int = 30
    authenticated_upload_rate_limit_per_minute: int = 60
    preview_rate_limit_per_minute: int = 120
    upload_max_concurrent: int = 4
    # Proxy/client-IP handling (safe default: trust direct peer only)
    trust_proxy_headers: bool = False
    # Comma-separated CIDRs for proxies allowed to supply forwarded headers.
    # Use "*" only when the app is reachable solely through trusted ingress.
    trusted_proxy_cidrs: str = "127.0.0.1/32,::1/128"

    # API tokens, enrichment encryption, TAXII
    # Separate key for at-rest encryption of EnrichmentService.api_token_encrypted.
    # Defaults to secret_key when unset; rotating either breaks existing encrypted blobs.
    enrichment_encryption_key: str | None = None
    # Rate limit for token-authenticated IOC feed + TAXII requests.
    api_token_rate_limit_per_minute: int = 120
    # Enable the optional TAXII 2.1 read-only server at /taxii2/. Off by default.
    taxii_enabled: bool = False
    # Live-enrichment outbound request rate limit per service per minute (0 = unlimited).
    enrichment_rate_limit_per_minute: int = 30
    # Restrict live-enrichment endpoints to globally-routable addresses.
    #
    # **Defaults to true, unlike its two siblings**, and the asymmetry is the point: a
    # webhook receiver and an AI provider are normally something you run yourself (the
    # reference AI setup is an Ollama on localhost), while an enrichment service is by
    # definition a third-party threat-intel API on the public internet. Loopback and RFC1918
    # are therefore the expected case for those two and a red flag for this one.
    #
    # Set false to point a service at a host on your own network — a self-hosted MISP or
    # OpenCTI, or a local stub while you are working out a template. Metadata
    # addresses stay blocked either way, and the connection is still pinned to a validated
    # IP so a DNS rebind cannot slip past afterwards.
    enrichment_require_public_host: bool = True
    # Watch-rule webhooks. Users enter their own URL and private/internal hosts are allowed
    # by default so self-hosted receivers (Mattermost, n8n, an internal SIEM) work. Set
    # webhook_require_public_host=true on deployments with untrusted members — see
    # docs/security.md.
    webhook_require_public_host: bool = False
    webhook_timeout_seconds: int = 5
    webhook_rate_limit_per_minute: int = 10
    webhook_max_retries: int = 3
    webhook_delivery_retention_days: int = 30
    # Per-user cap on enabled watch rules, so one account cannot fan a job out unboundedly.
    watch_rules_max_per_user: int = 50

    # A rule list can name a source URL and be re-fetched on a schedule. Stricter than the
    # webhook twin above and deliberately so: this is fetched with nobody watching, and the
    # reason to point a *feed* at an internal address is much rarer than the reason to point
    # a webhook receiver at one. Set false for an internal mirror of a public list.
    rule_list_require_public_host: bool = True
    rule_list_fetch_timeout_seconds: int = 15
    # A list holds at most 2,000 values of 200 characters, so a legitimate feed is well
    # under this; the cap is what stops a mistyped URL streaming a disk image into a worker.
    rule_list_fetch_max_bytes: int = 1024 * 1024

    # AI job and case analysis. Providers are configured per-row on /admin/ai (base URL, model,
    # token, timeout); only the deployment-wide policy lives here.
    # An AI endpoint is admin-configured infrastructure, so private/internal hosts are
    # allowed by default — the reference setup is an Ollama on localhost, which a
    # public-only guard would reject outright. Twin of webhook_require_public_host; set
    # true on deployments where an admin account is not fully trusted.
    ai_require_public_host: bool = False
    # Per-user cap on analysis runs started per minute (0 = unlimited). One click costs
    # money or a GPU, so this is lower than the other limits by design.
    ai_rate_limit_per_minute: int = 10
    # Default evidence-brief limit in characters. Providers can override it separately for
    # jobs and cases; the system prompt is separate. Oversized briefs are truncated.
    ai_max_prompt_chars: int = 60_000

    # Activity log. Capture itself is a SiteSettings toggle (runtime, no restart); only the
    # retention window lives here, alongside the other prune windows. `0` keeps forever —
    # deliberate, since some deployments must retain an audit trail for a fixed period and
    # silently deleting it would be the worst possible default.
    activity_retention_days: int = 90
    # How long finished BackgroundTask rows are kept — one row per backfill, cleanup and
    # recalculation, so without a window the table only grows.
    background_task_retention_days: int = 30
    # Age at which an uploaded log file and its jobs are deleted. **0 (off) by default**,
    # unlike every other retention window: the others remove derived data, this removes the
    # evidence a user submitted, and doing that on a schedule must be switched on rather
    # than inherited.
    upload_retention_days: int = 0

    @model_validator(mode="after")
    def _check_and_derive(self) -> "Settings":
        if not self.secret_key or len(self.secret_key) < 8:
            raise ValueError('SECRET_KEY must be at least 8 characters. Generate one with: python3 -c "import secrets; print(secrets.token_hex(32))"')
        if self.secret_key.startswith("change-me") or self.secret_key in (
            "change-me-in-production",
            "change-me-to-a-long-random-string-in-production",
        ):
            raise ValueError('SECRET_KEY must be changed from the placeholder value. Generate one with: python3 -c "import secrets; print(secrets.token_hex(32))"')

        # Normalised and validated here rather than by a field_validator so the failure
        # reads like the SECRET_KEY one above: refusing to boot on a typo beats serving
        # plain HTTP because someone wrote PROXY_TLS=internl.
        self.proxy_tls = self.proxy_tls.strip().lower()
        if self.proxy_tls not in PROXY_TLS_MODES:
            raise ValueError(f"PROXY_TLS={self.proxy_tls!r} is not one of: {', '.join(sorted(PROXY_TLS_MODES))}.")

        # Deprecated alias: HUEY_TASK_TIMEOUT → huey_queue_expiry
        if self.huey_task_timeout is not None:
            self.huey_queue_expiry = self.huey_task_timeout

        # Auto-derive sync URL from database_url when not explicitly set
        if self.sync_database_url is None:
            url = self.database_url
            url = url.replace("+asyncpg", "").replace("+aiosqlite", "")
            self.sync_database_url = url

        # VERSION file (repo root) is the canonical source of app_version when present;
        # `task release:prepare` writes it, and it ships in every release archive.
        # Falls back silently to the in-code default if the file is missing or unreadable.
        version_file = Path(__file__).resolve().parent.parent / "VERSION"
        try:
            declared = version_from_manifest(version_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            declared = None
        if declared:
            self.app_version = declared

        return self

    def production_warnings(self) -> list[str]:
        """Return warnings for risky config combinations in a production/exposed deployment."""
        warnings: list[str] = []
        if self.debug:
            warnings.append("DEBUG=true exposes /api/docs and disables Secure cookies. Set DEBUG=false for internet-facing deployments.")
        if self.disable_csp:
            warnings.append("DISABLE_CSP=true removes Content-Security-Policy headers. Re-enable CSP for internet-facing deployments.")
        if self.cookie_insecure and not self.debug:
            warnings.append("COOKIE_INSECURE=true with DEBUG=false: auth cookies lack the Secure flag. Use HTTPS and set COOKIE_INSECURE=false for public deployments.")
        if self.trust_proxy_headers and self.trusted_proxy_cidrs.strip() == "*":
            warnings.append("TRUSTED_PROXY_CIDRS=* trusts forwarded headers from any peer. Restrict to actual proxy CIDRs unless behind a fully trusted ingress.")
        if len(self.secret_key) < 32:
            warnings.append('SECRET_KEY is shorter than 32 characters. Use a longer key for production: python3 -c "import secrets; print(secrets.token_hex(32))"')
        if self.upload_rate_limit_per_minute == 0:
            warnings.append("UPLOAD_RATE_LIMIT_PER_MINUTE=0 disables upload rate limiting. Set a positive value for internet-facing deployments.")
        if self.login_rate_limit_per_minute == 0:
            warnings.append("LOGIN_RATE_LIMIT_PER_MINUTE=0 disables login rate limiting. Set a positive value for internet-facing deployments.")
        if self.garage_expose and self._has_placeholder_s3_keys():
            warnings.append("GARAGE_EXPOSE is set with default placeholder S3 keys. Rotate S3_ACCESS_KEY and S3_SECRET_KEY before exposing Garage off-host.")
        return warnings

    # Placeholder Garage keys shipped in docker-compose.yml / .env.example. Kept in code so the
    # fail-fast check in app.main catches them even when operators copy either file verbatim.
    _PLACEHOLDER_S3_ACCESS_KEYS = frozenset(
        {
            "GKa1b2c3d4e5f6a7b8c9d0e0f1",
        }
    )
    _PLACEHOLDER_S3_SECRET_KEYS = frozenset(
        {
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        }
    )

    def _has_placeholder_s3_keys(self) -> bool:
        ak = self.s3_access_key or ""
        sk = self.s3_secret_key or ""
        return ak in self._PLACEHOLDER_S3_ACCESS_KEYS or sk in self._PLACEHOLDER_S3_SECRET_KEYS

    def _redis_exposed_offhost(self) -> bool:
        """True when REDIS_EXPOSE binds Redis beyond loopback (multi-server layouts).

        REDIS_EXPOSE is a bind address like ``10.0.0.1:6379`` or ``[::1]:6379``;
        the compose default ``127.0.0.1:6379`` stays host-local and is safe.
        """
        import ipaddress
        from urllib.parse import urlparse

        raw = (self.redis_expose or "").strip()
        if not raw:
            return False
        host = urlparse(f"//{raw}").hostname or ""
        if not host:
            return False
        try:
            return not ipaddress.ip_address(host).is_loopback
        except ValueError:
            return host.lower() != "localhost"

    def _redis_has_auth(self) -> bool:
        """True when Redis connections carry a password (REDIS_PASSWORD or credentials in REDIS_URL)."""
        from urllib.parse import urlparse

        if self.redis_password:
            return True
        if self.redis_url:
            return bool(urlparse(self.redis_url).password)
        return False

    def production_errors(self) -> list[str]:
        """Return fail-fast conditions: combinations too dangerous to boot with."""
        errors: list[str] = []
        # DISABLE_CSP is a dev-only escape hatch. Refuse to start in prod-shaped configs
        # unless the operator explicitly opts in via a second env var.
        import os as _os

        ack = _os.environ.get("I_ACCEPT_DISABLE_CSP_IN_PROD", "").lower() in ("1", "true", "yes")
        if self.disable_csp and not self.debug and not ack:
            errors.append("DISABLE_CSP=true with DEBUG=false refuses to start. Re-enable CSP, or set I_ACCEPT_DISABLE_CSP_IN_PROD=true to bypass this guard (not recommended).")
        # Garage placeholder keys are public (checked into VCS). If the service is being
        # exposed off-host, require real keys.
        if self.garage_expose and self._has_placeholder_s3_keys():
            errors.append(
                "GARAGE_EXPOSE is set but S3_ACCESS_KEY / S3_SECRET_KEY are still the placeholder values shipped in docker-compose.yml. Generate fresh keys before exposing Garage."
            )
        # Exposing Redis beyond loopback without auth hands the task queue (and
        # everything reachable through it) to the network. Mirror the Garage guard.
        if self._redis_exposed_offhost() and not self._redis_has_auth():
            errors.append(
                "REDIS_EXPOSE binds Redis to a non-loopback address but REDIS_PASSWORD is empty. Set REDIS_PASSWORD (./logstotal gen-secrets -- --write) before exposing Redis to the network."
            )
        return errors

    @property
    def proxy_profile_enabled(self) -> bool:
        """Whether the bundled Caddy service is in COMPOSE_PROFILES.

        Split on commas rather than tested as a substring: `"proxy" in compose_profiles`
        also matches a profile called `myproxy`.
        """
        return "proxy" in {p.strip() for p in self.compose_profiles.split(",") if p.strip()}

    @property
    def https_terminated_locally(self) -> bool:
        """Whether the bundled proxy is on AND terminates TLS itself.

        The distinction the cookie and HSTS checks need: PROXY_TLS=off puts Caddy in front
        on plain HTTP, so the proxy profile alone no longer implies HTTPS.
        """
        return self.proxy_profile_enabled and self.proxy_tls != "off"

    @property
    def cookie_secure(self) -> bool:
        """Whether the auth cookie uses the Secure flag (HTTPS-only in browsers)."""
        if self.debug:
            return False
        return not self.cookie_insecure

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024


settings = Settings()
