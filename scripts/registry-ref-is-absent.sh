#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: registry-ref-is-absent.sh <exact-reference> <stderr-file>" >&2
  exit 2
fi

registry_reference="$1"
error_file="$2"

if [ ! -f "$error_file" ]; then
  echo "registry inspection error file does not exist: $error_file" >&2
  exit 2
fi

if grep -Eqi 'manifest unknown|MANIFEST_UNKNOWN|status code: 404|unexpected status[^[:cntrl:]]*404|404 Not Found' "$error_file"; then
  exit 0
fi

while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"
  if [ "$line" = "$registry_reference: not found" ] || [ "$line" = "ERROR: $registry_reference: not found" ]; then
    exit 0
  fi
done < "$error_file"

exit 1
