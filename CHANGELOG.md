# Changelog

All notable changes to LogsTotal are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Before upgrading, read [Upgrade and roll back](docs/runbooks/upgrading.md) — it covers the
backup step, migration ordering, and rollback for each deployment path.

## [Unreleased]

### Added

- Stored execution fingerprints for each analysis: input, effective workflow, engine
  binary or container, rules and configuration. Historical runs retain unknown provenance.
- Downloadable analysis reports and comparisons between visible runs of identical file
  content, grouped by engine and rule identity, with counts and severity changes.
- Per-engine completion diagnostics and partial results. Usable findings survive malformed
  output or interrupted engines; incomplete coverage is explicitly labelled.

- A daily database optimisation (04:10 UTC). On SQLite it refreshes planner statistics and
  returns free pages to the filesystem once they pass `DB_VACUUM_FREELIST_PERCENT`
  (default 25). The first reclaim is a full `VACUUM`, run automatically only up to 256 MB,
  that switches the file to incremental auto-vacuum. The development database was 27% free
  pages (42.9 MB, 31.4 MB after `VACUUM`). The storage page now shows free pages, WAL size,
  auto-vacuum mode and the last vacuum.

- **Compress Stored Blobs** on the Maintenance tab (`/admin/backfill-compress-db`) encodes
  the finding events, evidence samples, analytics and rule texts written before they were
  stored compressed. Run it once after upgrading, then Vacuum.

- Event stores, the groundwork for Explore, **off by default** (`EVENTS_ENABLED`). With it
  on, every upload's events are parsed by LogsTotal itself (EVTX, JSON, winlogbeat,
  EVTX-XML, Sysmon for Linux, auditd, journald, syslog) into Parquet, in a subprocess
  beside the detection tools. It is built once per file, rebuilt on demand, and evicted
  by `EVENTS_RETENTION_DAYS` and `EVENTS_MAX_TOTAL_MB`. A 213 MB EVTX took 6.5 s and
  became an 11.5 MB store.

### Fixed

- Missing or unreadable engine output no longer becomes a successful zero-match result.
- Zircolite matches are dated again in the events timeline and the activity histogram.
  Zircolite writes the event time as a root `SystemTime`, which was never read, so every
  match counted as undated. Recalculate analytics, or run the analytics backfill, to
  re-date existing jobs.
- The storage page no longer counts uploads with no database row as reclaimable. Purge
  never deletes them, and its finished task now reports only the bytes it deleted.
- Vacuum checkpoints the SQLite WAL and reports the space freed across the database
  file and its WAL; it read the main file alone and could report nothing reclaimed.
- Regex timeouts cannot consume the budget granted to later events.
- Refreshed Sigma files invalidate cached rule metadata, including `.yaml` files.
- Zero-match reports describe observed results without declaring an input safe.
- Rules-only updates no longer change the engine version recorded for a pinned container.
- Zircolite versions are captured from the engine's startup banner when the image is
  not catalog-pinned; existing reports can recover missing versions from their saved logs.
- A fleet `upgrade:rollback` checks the control plane's database before stopping any host,
  as the single-host rollback always has. It used to restore code that could not start on
  a database at a newer migration.

### Updated

- RSigma 0.25.0 and Zircolite 4.7.0, with refreshed rules and a digest-pinned
  Zircolite image for AMD64 and ARM64.
  Chainsaw 2.17.1 and Hayabusa 4.2.0 have refreshed rule snapshots. ChopChopGo stays at 1.1.0.
- Tool updates accept exact release tags and rule refs for reproducible maintenance.
- Job pages poll lighter: the jobs list, the recent-jobs panel and the job status poll no
  longer load each job's analytics blob (1.3 MB per 20-row page in development) or every
  tool's full log. A failed tool's log is still shown to admins.
- Finding sample events, relationship evidence samples and job analytics are stored
  zstd-compressed (4.8x and 20x on the development data). Rows written before this read
  unchanged and are compressed when rewritten.
- The case timeline's histogram and the Processes tab read results the analytics pass
  stored once per job, instead of re-parsing every raw tool output on each cache miss
  (2.5 s + 0.9 s and about 1 GB of memory for one development job). Both now outlive
  output retention. Jobs analysed earlier fall back to the old path until recalculated.
- Raw tool outputs are stored zstd-compressed once a job's analytics are computed
  (`RAW_OUTPUT_COMPRESSION`, default on): one development job went from 276 MB to 7 MB.
  Readers and the raw ZIP export handle plain and compressed outputs alike; **Compress Tool
  Outputs** on the Maintenance tab compresses existing ones, on local disk or S3.
- Each rule's source text is stored once in a shared `rule_text` table instead of on every
  finding (1,705 findings shared 496 texts in development). With the compression
  backfill and a vacuum, the development database went from 42.9 MB to 14.6 MB.
- Twenty single-column indexes that a composite index already covered are dropped, and
  lists that relied on their order (findings, tags, case links, rule matches) are now
  explicitly ordered. SQLite connections use memory-mapped reads, in-memory temp storage
  and a bounded WAL.
- Job actions use visible buttons, offer comparisons only when an eligible earlier run
  exists, and group Artifact, Raw and JSON downloads in one menu. Analytics export
  sections start unchecked.
- Comparison baselines are selected from eligible earlier runs instead of entering
  a job ID manually.
- Analysis details expand from a button beside Show logs, keeping tool rows compact.
- Run comparisons open before results load, then fetch 100 rules per page with database
  aggregation and asynchronous pagination instead of loading both runs in full.
- Python dependencies, same-major browser libraries, and the pinned GitHub Actions
  updates proposed in PR #10.

### Upgrade notes

- Migration `b8d46f1e932a` adds the `PARTIAL` task status, which older workers cannot read.
  `./logstotal upgrade` stops every worker before migrating; stop them yourself if you
  upgrade any other way.
- Migration `f3a91c2e7d40` moves every finding's rule text into `rule_text` and drops
  `finding.rule_content`. It is listed with the rollback-unsafe migrations; its own
  downgrade writes the text back, so run it from the new code before installing older code.
- Migration `e064602640a4` drops the twenty redundant indexes, quickly and without data
  changes. Its downgrade recreates them.
- `./logstotal upgrade:rollback` refuses to cross this migration. Restore the pre-upgrade
  backup, or downgrade the schema first to keep newer jobs — see
  [Rolling back the analysis-confidence migration](docs/runbooks/upgrading.md#rolling-back-the-analysis-confidence-migration).

## [1.1.0] — 2026-10-10

A security release. It fixes the nineteen vulnerabilities reported privately against 1.0.0,
listed under **Security**, and adds the RSigma engine and an account menu. Read **Upgrade
notes** before upgrading: everyone is signed out once, and two API behaviours change.

### Upgrade notes

- **Everyone is signed out once.** Browser sessions are now bound to the account's password,
  and cookies issued by 1.0.0 carry no binding. API tokens are unaffected.
- **`PATCH /api/users/me` requires `current_password`** to change the password or the email.
  Updates that change neither are unaffected.
- **`GET /api/v1/jobs` shows a failed job's error detail to administrators only.** Other
  callers, the submitter included, get a generic message, as on the job page.
- **Login refuses a mismatched `Origin` or `Referer`.** A reverse proxy that rewrites `Host`
  without rewriting `Origin` now breaks login too, not only authenticated writes — see
  [CSRF protection](docs/security.md#csrf-protection).
- **Tighten the secret files 1.0.0 wrote.** New and regenerated `.env`, `deploy-envs/*` and
  per-host env files are created owner-only, but existing ones keep their mode until
  something rewrites them. Run `chmod 600 .env deploy-envs/*` where they exist, and on each
  host's installed `.env`. Rotate the secrets if other local users could read them.
- **A fleet record adopted with `FLEET_FROM` or `fleet:pull` is validated** and refused if it
  carries shell syntax, names `local` when it did not come from `local`, or gives an install
  path that is not a plain absolute path.
- **`deploy:smoke` with internal or custom TLS and basic auth** no longer sends the password
  over an unverified certificate. Install the CA on the machine running it or set
  `SMOKE_CACERT`; otherwise the authenticated checks are skipped.
- **`db:to-postgres` reads its target from `POSTGRES_TARGET_URL`.** `--postgres-url` still
  works for a URL without a password.
- **The `.env` administrator is created only while the instance has none.** Changing
  `ADMIN_EMAIL` no longer adds an administrator at the next start; use the
  [lockout-recovery](docs/runbooks/account-recovery.md#lockout-recovery) command.
- **Behavioural heuristics may report themselves incomplete**, with an amber note on the
  Threat Detection card, when crafted input exhausts their time limit. Sigma findings are
  unaffected.

### Security

All nineteen advisories were reported by @elhoim through private vulnerability reporting.

- GHSA-49jf-3jjc-cxjc (high): a fleet record adopted from another machine could inject
  shell commands on the operator's workstation. Records are validated, and only
  allow-listed, shell-safe options are imported.
- GHSA-gvh8-rjm3-x6rh (high): `deploy:start` and `docker:up` ran the offline-bundle marker,
  which the web container can write, as shell code as root. It is parsed as data.
- GHSA-vrm5-j754-mrr8 (high): generated `.env` and fleet secret files were world-readable,
  or made private only after the secrets were written. They are created owner-only and
  replaced atomically.
- GHSA-gh9q-rj4w-gmm4 (high): polynomial backtracking in the shipped threat-detection
  patterns let a crafted upload stall a worker. Each match has a 20 ms timeout, inside a
  per-analysis budget that grows with the events checked and stops at 120 s.
- GHSA-p777-46h6-j6fc (medium): sessions stayed valid for up to 24 hours after a password
  change or an administrator reset. They are now revoked.
- GHSA-jxjh-wvj9-wcjp (medium): `PATCH /api/users/me` changed the password and email
  without the current password.
- GHSA-9xfh-hmrh-4pr2 (medium): deploy scripts staged secrets and release archives, and
  placed the SSH control socket, at predictable `/tmp` paths. They use private temporary
  directories, and the control socket only a directory the operator owns.
- GHSA-4f3q-g376-hcgf (low): a hostile page could sign a visitor into another account
  (login CSRF).
- GHSA-3gjr-wr8j-9vr4 (low): the outbound guard blocked only `169.254.169.254`. Webhooks, AI
  providers, rule-list feeds and live enrichment share one block list covering the other
  cloud metadata endpoints, whatever `*_REQUIRE_PUBLIC_HOST` is set to.
- GHSA-ccp7-crq7-4h9j (low): a Mermaid `init` directive in a note or comment could restyle
  a diagram to cover the whole page for other users.
- GHSA-8x85-vh2h-6r24 (low): log values containing line breaks could forge the structure
  of an AI job brief. Sample events are single-line JSON.
- GHSA-xfr9-gp6v-wj78 (low): `GET /api/v1/jobs` returned raw worker errors to anonymous
  callers.
- GHSA-5cwm-4ph5-hrjw (low): a rule list's feed URL, where an API key may live, and its
  fetch error were shown to every member.
- GHSA-6v2g-qcqc-9h6f (low): the graph's near-clique count included private jobs.
- GHSA-f2wg-286c-56g4 (low): the AI pane named the account that started a run to anonymous
  visitors of a public job.
- GHSA-p4h8-5mhf-8rgv (low): the process-tree and events-timeline endpoints ignored the
  site switches that hide those panels.
- GHSA-6gfg-mgvp-qgx2 (low): `deploy:smoke` sent basic-auth credentials with TLS
  verification turned off.
- GHSA-ffqv-xfpg-6fq9 (low): backup, restore and the deploy configuration review put
  database and basic-auth passwords on process command lines.
- GHSA-qqmc-jwjj-87c9 (low): `test:pg` published a PostgreSQL superuser on every interface,
  and `db:to-postgres` took the password on its command line.

Also fixed:

- An administrator's re-run of another user's private file created a public job, readable
  by anonymous visitors (#8, @elhoim).
- The Compose Redis healthcheck put `REDIS_PASSWORD` on a command line every five seconds.
- An administrator who changed their email address got a second administrator, with the
  `.env` password, at the next start.

### Added

- RSigma 0.23.0 in Windows Full Analysis, with native binaries, an independent Windows
  Sigma snapshot, and mappings for EVTX, EVTX JSON and Winlogbeat. Matches retain raw
  evidence for timelines, entities, relationships and process trees; incomplete scans fail.
- A shared tool catalog and adapter-owned raw readers, used by runtime registration,
  diagnostics, scaling, updates and artifact checks. See the expanded contributor checklist
  for adding engines without changing the analytics parser.
- Typed output mappings shared by finding aggregation and raw-event readers, with explicit
  compatibility policies preserving existing counts, samples, timelines and analytics.
- Optional workflow profiles for shared tool paths, rules and pinned container images.
  Existing explicit workflow tasks retain their behavior and can override profile defaults.
- An account menu under your email address in the navigation: change your own email or
  password, both of which require the current password, and log out.

### Fixed

- Timeline markers use tool and rule ID to link to the correct finding when engines
  report rules with the same title.
- A job or tool result finalised by one process (a cancel, the recovery sweep, a failed
  enqueue) is no longer overwritten by another, and a duplicate queue message no longer
  deletes the running worker's heartbeat or cancel flag (#4, #9, @elhoim).
- A job where no detection engine succeeded is marked failed with a reason, instead of
  completed with no findings. A crashed container run is reported failed even when it left
  partial output, and cancelled or recovered jobs keep correct finding totals.
- Watching a job: losing an insert race no longer loses the comment, tag or AI run that
  raised the event (#7, @elhoim).
- Upload retention ages a file by its newest job, so a re-upload or a resubmit no longer
  takes the new job with it (#6, @elhoim).
- A fleet deployed with an IPv6 control-plane address writes a fleet record that its own
  tooling accepts. An invalid record on the control plane is ignored with a warning
  instead of stopping deploy and upgrade without a message.

### Documentation

- The security model states that the entity list is instance-wide: private jobs hide the
  job, not the observables extracted from it (#5, @elhoim).
- The `show_entities` and timeline settings describe what they actually hide.

## [1.0.0] — 2026-09-27

The first public release. LogsTotal is a self-hosted platform for analysing security logs:
upload a log file, and several detection engines report what each of them found, side by
side, with the context an analyst needs to act on it.

### Highlights

- **Several engines, one report.** Zircolite, Chainsaw, Hayabusa and ChopChopGo run over the
  same file, with SigmaHQ, Hayabusa and Chainsaw rule sets included. Findings are grouped by
  severity, each names its rule and the rule's author, and a detection score shows how many
  engines agreed.
- **Windows and Linux logs.** EVTX, Windows Event XML, Winlogbeat and EVTX JSON, Sysmon for
  Linux, auditd, syslog and journald exports, detected automatically; drop many files at
  once.
- **Context.** MITRE ATT&CK heatmap and timelines, a zoomable events timeline, extracted
  entities (users, hosts, IPs, hashes, executables, domains…) across every analysis, their
  relationships as a graph, and the process tree behind a detection.
- **Investigation.** Cases that gather jobs and entities with notes, a timeline and a graph;
  tags, discussions and watched jobs; rules that tag, alert or call a webhook when an entity
  or a job matches; exports to STIX 2.1, MISP, IOC packs and a TAXII 2.1 feed; an optional
  AI analysis of a job through your own OpenAI-compatible or Anthropic endpoint.
- **Built to be run.** One command to install on a server (`./logstotal quickstart`), HTTPS
  with Caddy, a multi-server fleet with PostgreSQL, S3 storage and a private WireGuard
  network deployed from your workstation, offline bundles for closed networks, verified
  backups, and upgrades that take a rollback point first. Every operation is
  `./logstotal <name>` and needs nothing installed beforehand.
- **Documentation** at <https://wagga40.github.io/LogsTotal/>.

### Changed since the last pre-release

- `./logstotal` replaces `task`: it runs the pinned Task binary that every release archive
  carries, so no host needs Task installed — fleet hosts no longer get it at all. An
  installed Task 3.39 or later still works as `task <name>`.
- The operator documentation is a website, rewritten and reorganised: one page per topic,
  every command checked against the code.
- The vendored SigmaHQ snapshot for Chainsaw keeps only its rule sets and licence (41 MB
  smaller); `./logstotal tools:update` keeps the same subset.
- Findings name their rule's author, on the rule panel and in `findings.json`, as the
  Detection Rule License 1.1 asks of anything that reports Sigma matches.
- The API tokens page warns when the instance sits behind HTTP basic auth, which tokens
  cannot pass.

### Fixed since the last pre-release

- `GARAGE_RPC_SECRET` and `GARAGE_ADMIN_TOKEN` from `.env` now reach the bundled Garage
  service; before, it always ran on the built-in defaults. Garage restarts on the new
  secrets after the upgrade, with its data, bucket and access key unaffected.
- A manual re-run of the release workflow tested the default branch instead of the tag it
  was rebuilding.
- Submitting a single file no longer stops on the browser's "leave this page?" prompt.
- The activity log's pager no longer sticks on page 2: from the second page on, every
  button led back to it.
- `./logstotal doctor:docker`, `./logstotal docker:shell` and a fleet upgrade's migration and
  check steps ran against an empty SQLite file inside the container rather than the real
  database; they now see what the application sees.
- An upgrade or deploy no longer deletes a `docker-compose.override.yml` in the install
  directory.
- `./logstotal deploy:env-scaffold` generates the Garage secrets.

[Unreleased]: https://github.com/wagga40/LogsTotal/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/wagga40/LogsTotal/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/wagga40/LogsTotal/releases/tag/v1.0.0
