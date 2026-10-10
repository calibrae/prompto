#!/usr/bin/env bash
# Download, verify and decompress the FreeBSD BASIC-CLOUDINIT image to a local
# cache file (libvirt cannot ingest .xz). Mirrors up-bsd.sh. Idempotent.
# usage: fetch-freebsd-base.sh <release e.g. 14.5-RELEASE> <out.qcow2>
set -euo pipefail
REL=$1 OUT=$2
[[ -s $OUT ]] && exit 0
URL=https://download.freebsd.org/releases/VM-IMAGES/$REL/amd64/Latest
IMG=FreeBSD-$REL-amd64-BASIC-CLOUDINIT-ufs.qcow2
w=$(mktemp -d); trap 'rm -rf "$w"' EXIT
curl -fsSL -o "$w/$IMG.xz" "$URL/$IMG.xz"
curl -fsSL -o "$w/CHECKSUM.SHA256" "$URL/CHECKSUM.SHA256"
(cd "$w" && grep -F "($IMG.xz)" CHECKSUM.SHA256 | sha256sum -c -)
xz -d "$w/$IMG.xz"
mkdir -p "$(dirname "$OUT")"
install -m 0644 "$w/$IMG" "$OUT"
