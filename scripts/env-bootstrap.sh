#!/usr/bin/env bash
# Create .env from .env.example on a fresh checkout and fill in the two secrets that
# must never ship as placeholders. Called by `task setup`.
#
# Usage: bash scripts/env-bootstrap.sh
#
# Idempotent: an existing .env is never rewritten, so re-running setup cannot rotate
# SECRET_KEY out from under live sessions.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

if [ ! -f .env ]; then
  [ -f .env.example ] || die ".env.example not found — run this from the project root."
  cp .env.example .env
  # gen_secrets.py --write fills only empty/placeholder keys and prints the admin
  # password once. Using it here rather than a second generator means `task gen-secrets`
  # and `task setup` agree by construction about what a placeholder is and which keys
  # count as secrets.
  run_py scripts/gen_secrets.py --write
  ok "created $(value .env) from .env.example"
  info "change ADMIN_EMAIL in .env before init if you want a different admin account"
else
  ok ".env already exists — skipping"
fi

# The dev server is plain HTTP on localhost:8000, where the browser silently drops
# a Secure auth cookie: you log in, get redirected, and are logged out again with
# no error anywhere. Appended only when the key is absent, so an explicit choice is kept.
if ! grep -qE '^COOKIE_INSECURE=' .env; then
  printf '\n# Set by task setup: the dev server is plain HTTP on :8000, and a Secure\n# cookie is silently dropped there. Set to false once TLS is in front.\nCOOKIE_INSECURE=true\n' >> .env
  ok "set COOKIE_INSECURE=true (dev serves plain HTTP)"
fi

mkdir -p uploads
