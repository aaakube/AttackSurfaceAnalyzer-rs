#!/usr/bin/env bash
# Builds the bundle to carry onto the air-gapped Windows workstation:
#   dist/asa-<version>-windows-x64.zip   asa.exe, default rules, README, licenses, SHA256SUMS
#   dist/asa-<version>-windows-x64.zip.sha256
# On Windows, check the zip before extracting:
#   (Get-FileHash .\asa-<version>-windows-x64.zip -Algorithm SHA256).Hash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
TARGET=x86_64-pc-windows-gnu
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
NAME="asa-$VERSION-windows-x64"
STAGE="dist/$NAME"

cargo test -q
cargo build --release --locked --target $TARGET
rm -rf "$STAGE" "dist/$NAME.zip"
mkdir -p "$STAGE/rules"
cp "target/$TARGET/release/asa.exe" "$STAGE/"
cp rules/default.yaml "$STAGE/rules/"
cp README.md LICENSE THIRD_PARTY_NOTICES.md "$STAGE/"
(cd "$STAGE" && sha256sum asa.exe rules/default.yaml README.md LICENSE THIRD_PARTY_NOTICES.md > SHA256SUMS)
python3 -I - "$STAGE" "dist/$NAME.zip" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
base = os.path.dirname(src)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for d, _, files in os.walk(src):
        for f in sorted(files):
            p = os.path.join(d, f)
            z.write(p, os.path.relpath(p, base))
PY
(cd dist && sha256sum "$NAME.zip" > "$NAME.zip.sha256")
echo "built dist/$NAME.zip"
cat "dist/$NAME.zip.sha256"
