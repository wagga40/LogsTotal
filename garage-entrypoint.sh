#!/bin/sh
set -eu

CONFIG="/tmp/garage.toml"

# docker-compose.yml passes the operator's secrets as LT_GARAGE_*, never under Garage's own
# names: Garage reads GARAGE_RPC_SECRET and GARAGE_ADMIN_TOKEN from the environment as
# overrides of this file, so an empty one — an .env without the key — would replace the
# default below with "" and stop the node (and its healthcheck) from starting. The GARAGE_*
# names still work for anyone running this image by hand.
RPC_SECRET="${LT_GARAGE_RPC_SECRET:-${GARAGE_RPC_SECRET:-}}"
ADMIN_TOKEN="${LT_GARAGE_ADMIN_TOKEN:-${GARAGE_ADMIN_TOKEN:-}}"

cat > "$CONFIG" <<EOF
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"

db_engine = "sqlite"
replication_factor = 1
compression_level = 1

rpc_bind_addr = "[::]:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "${RPC_SECRET:-4a0e4c2c3f9e2a7d8b1c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f50}"

[s3_api]
s3_region = "${S3_REGION:-logstotal}"
api_bind_addr = "[::]:3900"
root_domain = ".s3.garage.localhost"

[s3_web]
bind_addr = "[::]:3902"
root_domain = ".web.garage.localhost"

[admin]
api_bind_addr = "[::]:3903"
admin_token = "${ADMIN_TOKEN:-logstotal-garage-admin}"
EOF

# Warn about default secrets (acceptable for single-node Docker, not for exposed deployments)
# Use ${VAR:-} so tests work with set -u when vars are omitted from the environment.
if [ -z "$RPC_SECRET" ]; then
  echo "WARNING: GARAGE_RPC_SECRET not set — using built-in default. Set it in .env for exposed deployments."
fi
if [ -z "$ADMIN_TOKEN" ]; then
  echo "WARNING: GARAGE_ADMIN_TOKEN not set — using built-in default. Set it in .env for exposed deployments."
fi

echo "Generated $CONFIG (region=${S3_REGION:-logstotal})"

G="/garage -c $CONFIG"

$G server &
GARAGE_PID=$!

for i in $(seq 1 30); do
  if $G node id -q 2>/dev/null; then break; fi
  echo "Waiting for Garage RPC... ($i/30)"
  sleep 2
done
$G node id -q || { echo "Garage RPC not ready after 60s"; kill $GARAGE_PID; exit 1; }

if $G status 2>&1 | grep -q 'NO ROLE ASSIGNED'; then
  NODE_ID=$($G node id -q | cut -c1-16)
  $G layout assign "$NODE_ID" -z local -c 1G
  $G layout apply --version 1
  echo "Layout assigned."
fi

$G key import --yes -n logstotal "$S3_ACCESS_KEY" "$S3_SECRET_KEY" || true
$G bucket create "$S3_BUCKET" || true
$G bucket allow "$S3_BUCKET" --key logstotal --read --write --owner || true
echo "Garage ready: bucket=$S3_BUCKET"

wait $GARAGE_PID
