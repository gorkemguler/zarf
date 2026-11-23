#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing zarf binary to ${PREFIX}/bin/zarf ..."
sudo install -Dm755 "${SCRIPT_DIR}/zarf" "${PREFIX}/bin/zarf"

if [ -f "${SCRIPT_DIR}/zarf.desktop" ]; then
  sudo install -Dm644 "${SCRIPT_DIR}/zarf.desktop" /usr/share/applications/zarf.desktop
fi
if [ -f "${SCRIPT_DIR}/zarf.svg" ]; then
  sudo install -Dm644 "${SCRIPT_DIR}/zarf.svg" /usr/share/icons/hicolor/scalable/apps/zarf.svg
fi

echo "Done! Run 'zarf --help' or 'zarf app' (or launch Zarf from your desktop application menu)."
