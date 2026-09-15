#!/usr/bin/env bash
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.14.7}"
JOBS="${JOBS:-2}"
OUTDIR="${OUTDIR:-$PWD/output}"

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

SOURCE_DIR="/tmp/wazuh-source"
rm -rf "$SOURCE_DIR"

echo "==> Building Wazuh agent ${WAZUH_VERSION} for /opt/ossec"
git clone --depth 1 --branch "v${WAZUH_VERSION}" https://github.com/wazuh/wazuh.git "$SOURCE_DIR"
cd "$SOURCE_DIR/packages"

./generate_package.sh \
  -t agent \
  -a amd64 \
  -p /opt/ossec \
  --system rpm \
  -j "$JOBS" \
  -s "$OUTDIR" \
  -c

shopt -s nullglob
rpms=("$OUTDIR"/*.rpm)
if (( ${#rpms[@]} == 0 )); then
  echo "ERROR: no RPM was generated" >&2
  exit 1
fi

printf '\nGenerated package(s):\n'
ls -lh "${rpms[@]}"
