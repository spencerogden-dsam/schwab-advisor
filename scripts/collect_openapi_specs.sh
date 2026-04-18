#!/usr/bin/env bash
# Move Schwab OpenAPI specs downloaded by scripts/download_openapi_specs.js
# from ~/Downloads into docs/.
#
# Usage: bash scripts/collect_openapi_specs.sh

set -euo pipefail

DL="${HOME}/Downloads"
DEST="$(cd "$(dirname "$0")/.." && pwd)/docs"

shopt -s nullglob
files=("$DL"/schwab-*-openapi*.json)

if [ ${#files[@]} -eq 0 ]; then
  echo "No schwab-*-openapi*.json files in $DL — did the browser snippet run?"
  exit 1
fi

mkdir -p "$DEST"
for f in "${files[@]}"; do
  name="$(basename "$f")"
  # Chrome may append " (1)", " (2)" to duplicates — strip those.
  clean="${name// (1)/}"
  clean="${clean// (2)/}"
  clean="${clean// (3)/}"
  mv -v "$f" "$DEST/$clean"
done

echo
echo "Specs now in $DEST:"
ls -1 "$DEST"/schwab-*-openapi.json
