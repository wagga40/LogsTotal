# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/wagga40/LogsTotal/security/advisories/new)
form. That opens a draft advisory only you and the maintainers can see.

Useful things to include, as far as you have them:

- what an attacker gains, and what access they need to start;
- the affected version (`./logstotal version`, or the footer of any page);
- how the instance is deployed — [single host, fleet or offline](docs/install/prerequisites.md),
  and whether it is behind a reverse proxy;
- steps to reproduce, or a proof of concept.

You should get an acknowledgement within **7 days**, and an assessment with a fix plan or
a reasoned rejection within **30 days**. LogsTotal is maintained by one person in their
own time, so please treat those as good-faith targets rather than an SLA. Credit in the
advisory and the changelog is offered unless you would rather stay anonymous.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes — the latest release |

Fixes land on the latest release; there are no backport branches. Upgrading is one command,
`./logstotal upgrade`.

## Scope

LogsTotal is **self-hosted software, not a hosted service**: there is no instance to test
against, so please do not scan or attack a deployment you do not own. Run your own —
`./logstotal quickstart` gets you one in a few minutes.

In scope: anything in this repository, including the Docker and multi-server deployment
scripts, and the security-relevant defaults they ship with.

Out of scope, because they are known and documented trade-offs rather than defects —
[docs/security.md](docs/security.md#security-trade-offs-to-understand) explains the
reasoning for each:

- **Anonymous upload and viewing.** A default instance lets anyone submit a file and read
  the results. That is the shared, multi-engine model the project exists to provide; deployments
  that need otherwise put it behind authentication at the proxy.
- **Watch-rule webhooks may target internal hosts.** A self-hosted SOC usually posts to an
  internal chat or SIEM, so this is permitted by default and is a blind-SSRF primitive for
  members. `WEBHOOK_REQUIRE_PUBLIC_HOST=true` restricts it. The cloud metadata endpoints
  are blocked either way — a bypass of *that* is in scope.
- **The existence of a typed entity relationship is not visibility-filtered**, while
  everything derived from it is. [docs/security.md](docs/security.md) states the boundary
  precisely; a leak of the *derived* data is in scope.
- Findings that require an admin account, or a deliberate misconfiguration the
  documentation warns against (`TRUSTED_PROXY_CIDRS=*` on untrusted ingress, `DEBUG=true`
  in production, a shared `SECRET_KEY`).

Reports that a security scanner flagged something, with no analysis of how it is reachable
in this application, are not usually actionable.

## Hardening

Before exposing an instance to anything but a trusted network, work through the
[production hardening checklist](docs/security.md#production-hardening-checklist) and run
`./logstotal doctor`.
