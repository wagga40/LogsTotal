#!/usr/bin/env bash
#
# Print the admin login for this deployment.
#
# Usage:
#   bash scripts/show-admin-password.sh
#
# Configuration:
#   ENV_FILE   Which file to read (default: .env). For a fleet, point it at the control
#              plane's generated file: deploy-envs/<host>.env
#
# The password is generated once and printed once, into scrollback, at the end of a
# quickstart that may have been days ago. This reads it back, rather than leaving the
# operator to grep deploy-envs/*.env for ADMIN_PASSWORD.
#
# It prints a secret to the terminal, deliberately and only when asked. It never writes
# one anywhere, and it never touches the database: this reports what the .env says, which
# is what init_db.py used to create the account. If the password was changed in the app
# afterwards, this value is stale — and it says so rather than pretending otherwise.

set -eu

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

ENV_FILE="${ENV_FILE:-.env}"

if [ ! -f "$ENV_FILE" ]; then
  die "${ENV_FILE} not found.
For a single host, run this from the install directory.
For a fleet, name the control plane's file:
  ENV_FILE=deploy-envs/<host>.env ./logstotal show-admin-password"
fi

# The active line only — a commented example is documentation, not configuration.
read_key() {
  grep -E "^[[:space:]]*$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | sed "s/^['\"]//; s/['\"]$//"
}

EMAIL=$(read_key ADMIN_EMAIL || true)
PASSWORD=$(read_key ADMIN_PASSWORD || true)

if [ -z "$PASSWORD" ]; then
  die "no ADMIN_PASSWORD in ${ENV_FILE}.
It is set by ./logstotal quickstart, ./logstotal setup, and ./logstotal deploy:env. If this deployment
predates those, reset the password instead — any admin can do it at /admin/users."
fi

printf '\n'
printf '  %s\n' "$ENV_FILE"
printf '  Admin login:  %s\n' "${EMAIL:-admin@example.com}"
printf '  Password:     %s\n' "$PASSWORD"
printf '\n'
printf '  This is what the account was CREATED with. If it was changed in the app since,\n'
printf '  the real password is not recorded anywhere — reset it at /admin/users.\n'
printf '\n'
