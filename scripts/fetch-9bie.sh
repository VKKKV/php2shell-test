#!/bin/sh
# Fetch the public 109619 RCE PoC at a pinned commit.
#
# The upstream repository has no license file, so it is not vendored here:
# it is cloned into lab/third_party/ (gitignored) at the commit this lab was
# validated against.
set -eu

PIN=4586f5cc120c82fd468b17469202bac629810ad9
URL=https://github.com/9bie/php2shell-bypass-aslr-exp
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DEST=${1:-$ROOT/lab/third_party/9bie}

if [ -d "$DEST/.git" ]; then
    git -C "$DEST" fetch --depth 1 origin "$PIN"
    git -C "$DEST" checkout -q "$PIN"
else
    mkdir -p "$(dirname "$DEST")"
    git clone --filter=blob:none "$URL" "$DEST"
    git -C "$DEST" checkout -q "$PIN"
fi

printf '9bie PoC ready at %s (%s)\n' "$DEST" "$PIN"
