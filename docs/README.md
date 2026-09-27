# LogsTotal documentation

LogsTotal is a self-hosted log analysis platform: upload a log file and several detection
engines (Zircolite, Chainsaw, Hayabusa, ChopChopGo) report what each of them found, grouped
by severity, with MITRE ATT&CK context and the entities they involve.

These pages are for the people who **install and run** an instance, and for contributors.
The guide for analysts using it is built into the application, at `/docs`.

Every command here is run from the install directory as `./logstotal <name>`. It needs
nothing installed first: see [Prerequisites](install/prerequisites.md).

## Get started

| You want to | Read |
|---|---|
| Try it, or run it on one server | [Single-host installation](install/single-host.md) |
| Put HTTPS in front of it | [HTTPS with Caddy](install/https.md) |
| Spread analysis over several machines | [Fleet installation](install/fleet.md) |
| Install where there is no internet access | [Offline installation](install/offline.md) |

Start with the [prerequisites](install/prerequisites.md), and go through the
[security checklist](security.md#production-hardening-checklist) before anyone else can
reach your instance.

## Operate

- [Health, logs and the first day](runbooks/health-and-logs.md)
- [Change the configuration](runbooks/configuration-changes.md)
- [Workers and stuck jobs](runbooks/workers.md)
- [Storage and retention](runbooks/storage.md)
- [Detection tools and workflows](runbooks/detection-tools.md)
- [Back up and restore](runbooks/backup-and-restore.md)
- [Upgrade and roll back](runbooks/upgrading.md)
- [Database migrations](runbooks/migrations.md)
- [Move from SQLite to PostgreSQL](runbooks/sqlite-to-postgres.md)
- [Recover administrator access](runbooks/account-recovery.md)
- [Troubleshooting](troubleshooting.md)

## Reference

- [Commands](reference/commands.md)
- [Configuration (environment variables)](configuration.md)
- [Admin pages and settings](reference/admin-ui.md)
- [Fleet options and day-2 commands](reference/fleet.md) · [Manual fleet installation](install/fleet-manual.md)
- [Ingestion API](reference/ingestion-api.md)
- [Security](security.md) · [Capacity planning](scaling.md) · [Known limitations](limitations.md)

## Contribute

- [Local development](contribute/local-development.md)
- [Development guide](contribute/development.md)
- [Releasing](contribute/releasing.md)
- [How to contribute](https://github.com/wagga40/LogsTotal/blob/main/CONTRIBUTING.md)
