# Changelog

All notable changes to LogsTotal are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Before upgrading, read [Upgrade and roll back](docs/runbooks/upgrading.md) — it covers the
backup step, migration ordering, and rollback for each deployment path.

## [Unreleased]

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

[Unreleased]: https://github.com/wagga40/LogsTotal/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/wagga40/LogsTotal/releases/tag/v1.0.0
