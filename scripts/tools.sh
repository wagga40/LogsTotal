#!/usr/bin/env bash
# Detection-tool updates use structured release metadata and staged installations.
set -eu
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$SCRIPT_DIR/detection_tools.py" "$@"
