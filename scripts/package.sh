#!/usr/bin/env bash
# Builds the release bundles:
#   dist/asa-<version>-windows-x64.zip       asa.exe, rules, README, docs, licenses, SHA256SUMS
#   dist/asa-<version>-linux-x64.tar.gz      asa (static, musl: runs on any x86-64 Linux), same files
#   and a .sha256 next to each.
# Check before extracting:
#   Windows: (Get-FileHash .\asa-<version>-windows-x64.zip -Algorithm SHA256).Hash
#   Linux:   sha256sum -c asa-<version>-linux-x64.tar.gz.sha256
# ASA_TARGETS=windows or ASA_TARGETS=linux builds only one.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
TARGETS="${ASA_TARGETS:-windows linux}"
DOCS=(README.md LICENSE THIRD_PARTY_NOTICES.md)

# Unit tests run on the build host first, unless ASA_SKIP_TESTS=1 (CI runs them per platform).
[[ ${ASA_SKIP_TESTS:-} == 1 ]] || cargo test -q
mkdir -p dist

# stage DIR BINARY: the files every bundle carries, plus SHA256SUMS.
stage() {
    local dir=$1 bin=$2
    rm -rf "$dir"
    mkdir -p "$dir/rules"
    cp "$bin" "$dir/"
    cp rules/default.yaml rules/linux.yaml "$dir/rules/"
    cp "${DOCS[@]}" "$dir/"
    mkdir -p "$dir/docs"
    cp docs/*.md "$dir/docs/"
    (cd "$dir" && sha256sum "$(basename "$bin")" rules/*.yaml "${DOCS[@]}" docs/*.md > SHA256SUMS)
}

if [[ " $TARGETS " == *" windows "* ]]; then
    target=x86_64-pc-windows-gnu
    name="asa-$VERSION-windows-x64"
    cargo build --release --locked --target $target
    stage "dist/$name" "target/$target/release/asa.exe"
    rm -f "dist/$name.zip"
    python3 -I - "dist/$name" "dist/$name.zip" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
base = os.path.dirname(src)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for d, _, files in os.walk(src):
        for f in sorted(files):
            p = os.path.join(d, f)
            z.write(p, os.path.relpath(p, base))
PY
    (cd dist && sha256sum "$name.zip" > "$name.zip.sha256")
    echo "built dist/$name.zip"
    cat "dist/$name.zip.sha256"
fi

if [[ " $TARGETS " == *" linux "* ]]; then
    # musl links everything statically, so the binary does not depend on the
    # target machine's glibc version. Needs musl-gcc (Debian/Ubuntu: musl-tools)
    # for the bundled SQLite.
    target=x86_64-unknown-linux-musl
    name="asa-$VERSION-linux-x64"
    command -v musl-gcc >/dev/null || { echo "musl-gcc not found: install musl-tools" >&2; exit 1; }
    cargo build --release --locked --target $target
    stage "dist/$name" "target/$target/release/asa"
    # Reproducible-ish: sorted entries, fixed owner, no extended attributes.
    tar --sort=name --owner=0 --group=0 --numeric-owner --no-xattrs \
        -czf "dist/$name.tar.gz" -C dist "$name"
    (cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
    echo "built dist/$name.tar.gz"
    cat "dist/$name.tar.gz.sha256"
fi
