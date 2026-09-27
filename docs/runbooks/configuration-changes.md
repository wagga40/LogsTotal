# Apply configuration changes

How to change a setting in `.env` and make the running services pick it up.

Run the commands on each affected host, from the install directory. Save a copy of the current `.env` somewhere safe before editing it; it contains secrets, so keep the copy out of release archives and version control. [Arguments and execution context](../reference/commands.md#arguments-and-execution-context) explains how environment variables and command arguments reach a command.

## Single host (Docker)

Check the key names, then recreate the services so they read the new environment:

```bash
./logstotal env:diff
docker compose up -d --no-build web worker
./logstotal doctor:docker
./logstotal health
```

`./logstotal env:diff` compares `.env` with `.env.example`: it lists keys your `.env` sets that LogsTotal does not know (usually a typo, which would otherwise be ignored silently) and documented keys your `.env` has never mentioned. It prints key names only, never values.

`./logstotal docker:restart` restarts containers with the environment they already have, so it does not apply `.env` edits. Changes to published ports, proxy settings, or the database or Redis services need those services recreated too. Use `./logstotal docker:up` when you also want to rebuild the application image.

On an offline installation from a bundle, use `./logstotal docker:up`: it starts the saved bundle images and never builds or pulls. A missing image is an error to repair from the bundle.

Settings changed on the admin **Settings** page take effect on the next request and need no restart.

## Fleet

On the machine you deploy from, the per-host files are in `deploy-envs/`. Keys you add to those files are kept when they are regenerated; the keys `./logstotal deploy:env` manages are rewritten from `deploy.env` each time, so change those in `deploy.env`. You can also edit a host's `.env` directly on that host.

`./logstotal deploy:env` installs the files. It replaces a host's `.env` only if that file is unchanged since it was last pushed; a file edited on the host is kept, and the command lists the key names that would be lost. Reconcile the two, then set `DEPLOY_ENV_PUSH_FORCE=yes` to overwrite. See the [Fleet reference](../reference/fleet.md) for the `DEPLOY_*` variables.

Recreate the control plane and check its health before restarting the affected workers. On a worker host:

```bash
docker compose -f docker-compose.worker.yml up -d --no-build
```

Changing a password in `.env` does not change it in PostgreSQL, Redis or Garage. Rotate the credential on the server and update every client that uses it at the same time.

## Verify or revert

Check `/health`, `/admin/workers`, and the behaviour the setting controls. If something is wrong, restore the saved `.env` and recreate the same services.

---

**Related:** [Configuration](../configuration.md) · [Health, logs and first-day checks](health-and-logs.md) · [Troubleshooting](../troubleshooting.md)
