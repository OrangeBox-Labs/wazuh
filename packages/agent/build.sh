#!/usr/bin/env bash
set -euo pipefail

# Versión de Wazuh a construir. Si no dices nada, usamos la definida acá.
WAZUH_VERSION="${WAZUH_VERSION:-4.14.7}"
JOBS="${JOBS:-2}"
OUTDIR="${OUTDIR:-$PWD/output}"

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

SOURCE_DIR="/tmp/wazuh-source"
rm -rf "$SOURCE_DIR"

echo "==> Construyendo agente Wazuh ${WAZUH_VERSION} para /opt/ossec"
echo "==> Porque /var/ossec ya tiene suficiente drama con Imunify."

git clone --depth 1 --branch "v${WAZUH_VERSION}" https://github.com/wazuh/wazuh.git "$SOURCE_DIR"
cd "$SOURCE_DIR/packages"

# Usamos el generador oficial de Wazuh. Nada de mover archivos después a la fuerza.
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
  echo "ERROR: Wazuh no generó ningún RPM. Se acabó la fiesta." >&2
  exit 1
fi

printf '\nRPM generado:\n'
ls -lh "${rpms[@]}"
