#!/usr/bin/env bash
#
# Print the fleet's reachability matrix — what must accept what, and why.
#
# Usage:
#   bash scripts/deploy-network.sh
#
# Configuration (env vars from the caller always override deploy.env values):
#   DEPLOY_HOSTS       Comma-separated host list; the first is the control plane.
#   DEPLOY_VPN         wireconf moves the relays onto the tunnel.
#   DEPLOY_VPN_PORT    WireGuard listen port (default 51820).
#   DEPLOY_DOMAIN      Setting it means Caddy is in front, so 80/443 replace 8000.
#   DEPLOY_PROXY_TLS   acme | internal | custom | off — decides whether a certificate
#                      authority has to reach port 80.
#   DEPLOY_ENV_FILE    Path to defaults file (default: deploy.env in cwd).
#   FORMAT             text (default) or json.
#
# A thin dispatcher on purpose. The logic is scripts/deploy_network_plan.py, which is pure
# and tested as data; this only resolves the configuration the same way every other deploy
# command does. It lives here rather than inline in Taskfile.yml because go-task runs its
# cmds under mvdan/sh, which has no BASH_SOURCE — and common.sh locates the module through
# it, so an inline form would silently print nothing at all.

set -eu

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

deploy_env_load DEPLOY_HOSTS DEPLOY_VPN DEPLOY_VPN_PORT DEPLOY_DOMAIN DEPLOY_PROXY_TLS

[ -n "${DEPLOY_HOSTS:-}" ] || die "DEPLOY_HOSTS is required (comma-separated host list; the first is the control plane)."

vpn_mode
network_plan "${FORMAT:-text}"
