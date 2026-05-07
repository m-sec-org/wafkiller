#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE_DIR="$ROOT_DIR/release/windows-amd64"
BUILD_DIR="$ROOT_DIR/.build/windows-amd64"

mkdir -p "$RELEASE_DIR" "$RELEASE_DIR/plugins" "$RELEASE_DIR/data" "$BUILD_DIR"
rm -f "$RELEASE_DIR/wafbps.exe"
find "$RELEASE_DIR/plugins" -type f -delete

cp "$ROOT_DIR/config.release.json" "$RELEASE_DIR/config.json"
cp "$ROOT_DIR/waf.yaml" "$RELEASE_DIR/waf.yaml"
cp "$ROOT_DIR"/plugins/* "$RELEASE_DIR/plugins/"

GOCACHE="$ROOT_DIR/.gocache" \
GOMODCACHE="$ROOT_DIR/.gomodcache" \
GOOS=windows \
GOARCH=amd64 \
CGO_ENABLED=1 \
CC=x86_64-w64-mingw32-gcc \
go build -mod=vendor -o "$RELEASE_DIR/wafbps.exe" .

printf 'release ready: %s\n' "$RELEASE_DIR"
