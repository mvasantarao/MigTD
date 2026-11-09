#!/usr/bin/env bash
# Compatibility entry point; all artifact inputs must now be declared explicitly.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec "$root/tools/snp/build-emulator-bundle.sh" "$@"
