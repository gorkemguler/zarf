#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-0.1.0}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist"
STAGE="${DIST}/.stage"

rm -rf "${DIST}"
mkdir -p "${DIST}" "${STAGE}"

echo "==> Building Zarf v${VERSION} release packages (100% pure Go, CGO_ENABLED=0)"

build_bin() {
  local goos="$1"
  local goarch="$2"
  local out="$3"
  echo "  -> compiling ${goos}/${goarch}"
  CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
    go build -trimpath -ldflags="-s -w" -o "${out}" "${ROOT}/cmd/zarf"
}

# 1. Cross-compile binaries
build_bin darwin  arm64 "${STAGE}/zarf_darwin_arm64"
build_bin darwin  amd64 "${STAGE}/zarf_darwin_amd64"
build_bin windows amd64 "${STAGE}/zarf_windows_amd64.exe"
build_bin windows arm64 "${STAGE}/zarf_windows_arm64.exe"
build_bin linux   amd64 "${STAGE}/zarf_linux_amd64"
build_bin linux   arm64 "${STAGE}/zarf_linux_arm64"

# Ensure samples exist on disk
"${STAGE}/zarf_$(go env GOOS)_$(go env GOARCH)" demo --export-dir "${ROOT}/samples" >/dev/null

# 2. macOS CLI tarballs
for arch in arm64 amd64; do
  pkg="${STAGE}/zarf_${VERSION}_darwin_${arch}"
  mkdir -p "${pkg}"
  cp "${STAGE}/zarf_darwin_${arch}" "${pkg}/zarf"
  chmod +x "${pkg}/zarf"
  cp "${ROOT}/README.md" "${ROOT}/README.tr.md" "${ROOT}/LICENSE" "${pkg}/"
  cp -R "${ROOT}/samples" "${pkg}/samples"
  tar -C "${STAGE}" -czf "${DIST}/zarf_${VERSION}_darwin_${arch}.tar.gz" "zarf_${VERSION}_darwin_${arch}"
done

# 3. macOS Universal .app bundle + .dmg (when running on macOS with lipo + hdiutil)
if [ "$(uname -s)" = "Darwin" ]; then
  echo "  -> assembling macOS Universal Zarf.app & DMG"
  APP_DIR="${STAGE}/Zarf.app"
  mkdir -p "${APP_DIR}/Contents/MacOS" "${APP_DIR}/Contents/Resources"

  lipo -create \
    "${STAGE}/zarf_darwin_arm64" \
    "${STAGE}/zarf_darwin_amd64" \
    -output "${APP_DIR}/Contents/MacOS/zarf"
  chmod +x "${APP_DIR}/Contents/MacOS/zarf"

  # Lightweight launcher script inside Zarf.app/Contents/MacOS/ZarfLauncher
  cat > "${APP_DIR}/Contents/MacOS/ZarfLauncher" <<'EOF'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec "${DIR}/zarf" app "$@"
EOF
  chmod +x "${APP_DIR}/Contents/MacOS/ZarfLauncher"

  sed "s/__VERSION__/${VERSION}/g" "${ROOT}/packaging/macos/Info.plist" > "${APP_DIR}/Contents/Info.plist"

  # Build crisp macOS .icns icon from assets/icon.svg
  ICONSET="${STAGE}/Zarf.iconset"
  mkdir -p "${ICONSET}"
  ICON_PNG="${STAGE}/icon_1024.png"
  if command -v magick >/dev/null 2>&1; then
    magick -background none "${ROOT}/assets/icon.svg" -resize 1024x1024 "${ICON_PNG}"
  else
    qlmanage -t -s 1024 -o "${STAGE}" "${ROOT}/assets/icon.svg" >/dev/null 2>&1
    mv "${STAGE}/icon.svg.png" "${ICON_PNG}"
  fi
  for sz in 16 32 128 256 512; do
    sips -z "${sz}" "${sz}" "${ICON_PNG}" --out "${ICONSET}/icon_${sz}x${sz}.png" >/dev/null
    sz2=$((sz * 2))
    sips -z "${sz2}" "${sz2}" "${ICON_PNG}" --out "${ICONSET}/icon_${sz}x${sz}@2x.png" >/dev/null
  done
  iconutil -c icns "${ICONSET}" -o "${APP_DIR}/Contents/Resources/Zarf.icns"

  # Ad-hoc sign so Apple Silicon macOS runs the local universal bundle cleanly
  if command -v codesign >/dev/null 2>&1; then
    codesign --force --deep --sign - "${APP_DIR}" >/dev/null 2>&1 || true
  fi

  # Zip the Zarf.app bundle
  (cd "${STAGE}" && zip -rq "${DIST}/Zarf_${VERSION}_macos_universal_app.zip" "Zarf.app")

  # Create drag-to-Applications DMG
  DMG_STAGE="${STAGE}/dmg_root"
  mkdir -p "${DMG_STAGE}"
  cp -R "${APP_DIR}" "${DMG_STAGE}/Zarf.app"
  ln -s /Applications "${DMG_STAGE}/Applications"
  cp "${ROOT}/README.md" "${ROOT}/README.tr.md" "${DMG_STAGE}/"
  hdiutil create \
    -volname "Zarf ${VERSION}" \
    -srcfolder "${DMG_STAGE}" \
    -ov -format UDZO \
    "${DIST}/Zarf_${VERSION}_macos_universal.dmg" >/dev/null
fi

# 4. Windows application .zip packages (amd64 + arm64)
for arch in amd64 arm64; do
  pkg="${STAGE}/zarf_${VERSION}_windows_${arch}"
  mkdir -p "${pkg}"
  cp "${STAGE}/zarf_windows_${arch}.exe" "${pkg}/zarf.exe"
  cp "${ROOT}/packaging/windows/Start-Zarf-App.cmd" "${pkg}/"
  cp "${ROOT}/packaging/windows/Inspect-EML-DragDrop.cmd" "${pkg}/"
  cp "${ROOT}/README.md" "${ROOT}/README.tr.md" "${ROOT}/LICENSE" "${pkg}/"
  cp -R "${ROOT}/samples" "${pkg}/samples"
  (cd "${STAGE}" && zip -rq "${DIST}/zarf_${VERSION}_windows_${arch}.zip" "zarf_${VERSION}_windows_${arch}")
done

# 5. Linux .tar.gz + Debian .deb packages (amd64 + arm64 / Raspberry Pi)
for arch in amd64 arm64; do
  pkg="${STAGE}/zarf_${VERSION}_linux_${arch}"
  mkdir -p "${pkg}"
  cp "${STAGE}/zarf_linux_${arch}" "${pkg}/zarf"
  chmod +x "${pkg}/zarf"
  cp "${ROOT}/packaging/linux/zarf.desktop" "${pkg}/zarf.desktop"
  cp "${ROOT}/packaging/linux/install.sh" "${pkg}/install.sh"
  chmod +x "${pkg}/install.sh"
  cp "${ROOT}/assets/icon.svg" "${pkg}/zarf.svg"
  cp "${ROOT}/README.md" "${ROOT}/README.tr.md" "${ROOT}/LICENSE" "${pkg}/"
  cp -R "${ROOT}/samples" "${pkg}/samples"
  tar -C "${STAGE}" -czf "${DIST}/zarf_${VERSION}_linux_${arch}.tar.gz" "zarf_${VERSION}_linux_${arch}"

  python3 "${ROOT}/scripts/make_deb.py" \
    "${VERSION}" \
    "${arch}" \
    "${STAGE}/zarf_linux_${arch}" \
    "${ROOT}/packaging/linux/zarf.desktop" \
    "${ROOT}/assets/icon.svg" \
    "${DIST}/zarf_${VERSION}_linux_${arch}.deb"
done

# 6. Clean stage & generate SHA256SUMS.txt
rm -rf "${STAGE}"
(
  cd "${DIST}"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- * > SHA256SUMS.txt
  else
    sha256sum -- * > SHA256SUMS.txt
  fi
)

echo ""
echo "==> Release artifacts built in ${DIST}:"
ls -lh "${DIST}"
