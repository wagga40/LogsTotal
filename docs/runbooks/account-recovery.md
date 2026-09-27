# Accounts and lockout recovery

The user roles, how to change them, and how to get back in when no administrator can sign in.

## User and role management

Three roles, plus anonymous visitors:

| Role | Access |
|------|--------|
| `admin` | Everything: `/admin`, `/workflows`, all of Intel, job downloads, backfills |
| `member` | Upload, jobs, docs and all of Intel. **No** `/admin` and no workflow editing |
| `user` | Upload, jobs and docs only. **No** Intel |
| anonymous | Upload, jobs and docs. Cannot make a submission private |

### Change a user's role

On `/admin/users`, pick `user`, `member` or `admin` in the user's role menu.

### Lockout recovery

If another administrator can sign in, ask them to reset your password on `/admin/users`.

Otherwise, create a recovery administrator with a **new email address**. The bootstrap skips accounts that already exist, so changing `ADMIN_PASSWORD` in `.env` does not reset any password.

On a Docker deployment, run this on the deployment host, from the install directory, while the stack is running. It prompts for the new address and password:

```bash
docker compose run --rm --no-deps web python3 -c 'import asyncio, getpass, os; os.environ["ADMIN_EMAIL"] = input("New recovery admin email: "); os.environ["ADMIN_PASSWORD"] = getpass.getpass("New password: "); import init_db; asyncio.run(init_db.main())'
```

On a development checkout, run the same command through PDM:

```bash
pdm run python3 -c 'import asyncio, getpass, os; os.environ["ADMIN_EMAIL"] = input("New recovery admin email: "); os.environ["ADMIN_PASSWORD"] = getpass.getpass("New password: "); import init_db; asyncio.run(init_db.main())'
```

Expect `Admin user created:` followed by the new address. Sign in with it, reset the original account's password on `/admin/users`, sign in as the original account, and delete the recovery account. If the command says the address already exists, choose another one: it has not changed that account's password. The command also reloads the shipped workflows and rules, as every web service start does.

---

**Related:** [Admin UI reference](../reference/admin-ui.md) · [Security](../security.md) · [Troubleshooting](../troubleshooting.md)
