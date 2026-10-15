#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
# SPDX-License-Identifier: LicenseRef-RUB-SecEng
# get_kat.sh - download the official SDitH-v2 KAT files into KAT/.
#
# The KAT files are part of the SDitH-v2 submission package for round 2 of
# the NIST additional signatures process. They are not included in this
# artifact; this script downloads the package from NIST, extracts the six
# PQCsignKAT_*.rsp files and checks them against the SHA-256 checksums of the
# files the artifact was tested with.
#
# If the download no longer works, copy the KAT folder of the round-2
# SDitH-v2 submission package into the artifact root by hand, so that the
# files end up as KAT/sdith_cat<1|3|5>_<fast|short>/PQCsignKAT_*.rsp. The
# checksums below identify the correct files.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
URL="https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/submission-pkg/sdith-submission-round2.zip"

SHA256SUMS="\
7a2a084ecaffdb987d81c64c3a18e37fe3e03787814292f9c6d08746b1ab02a1  sdith_cat1_fast/PQCsignKAT_163.rsp
e2a66f0be19c6c2a161d1119952d976aa177cd13f78fa92a0cdcb8872d274a6c  sdith_cat1_short/PQCsignKAT_163.rsp
016d037f0331a897375af4118ea882fc789b24b8c71e0de98bdf96692a25b1be  sdith_cat3_fast/PQCsignKAT_232.rsp
6c480eb42b99cea853afc51121fdfb2e743556f1d9929d26a8448bc3ffe5916c  sdith_cat3_short/PQCsignKAT_232.rsp
6afe4dae14c965e644203159727fdd423e158b3f97613465ddcdd4b7943ac016  sdith_cat5_fast/PQCsignKAT_307.rsp
e886e33d4b9b49e3783b847c9116e3d035a9d8447db31c9da2a9bb6790e3f990  sdith_cat5_short/PQCsignKAT_307.rsp"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ZIP="$TMP/sdith-submission-round2.zip"
echo "Downloading $URL"
if command -v curl >/dev/null; then
    curl -fL -o "$ZIP" "$URL" || DL_FAILED=1
else
    wget -O "$ZIP" "$URL" || DL_FAILED=1
fi
if [ -n "${DL_FAILED:-}" ]; then
    echo "ERROR: download failed. Copy the KAT folder of the round-2 SDitH-v2" >&2
    echo "submission package to $ROOT/KAT by hand (see README.md)." >&2
    exit 1
fi

echo "Extracting KAT files"
if command -v unzip >/dev/null; then
    unzip -q "$ZIP" 'SDitH-v2/KAT/*/PQCsignKAT_*.rsp' -d "$TMP"
else
    python3 -m zipfile -e "$ZIP" "$TMP"
fi

while read -r _ f; do
    mkdir -p "$ROOT/KAT/$(dirname "$f")"
    cp "$TMP/SDitH-v2/KAT/$f" "$ROOT/KAT/$f"
done <<< "$SHA256SUMS"

echo "Checking checksums"
(cd "$ROOT/KAT" && sha256sum -c <<< "$SHA256SUMS")
echo "KAT files are in $ROOT/KAT"
