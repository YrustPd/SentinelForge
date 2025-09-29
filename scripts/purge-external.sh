#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

TARGET_ROOT=${1:-$(pwd)}
BAD_DIRS=(SafeMe ssh-audit vps-audit vps-harden)

printf 'Scanning %s for external directories...\n' "$TARGET_ROOT"

present=()
for dir in "${BAD_DIRS[@]}"; do
  if [[ -d "$TARGET_ROOT/$dir" ]]; then
    present+=("$TARGET_ROOT/$dir")
  fi
done

if ((${#present[@]} == 0)); then
  echo 'No external directories detected.'
  exit 0
fi

echo 'Found:'
for path in "${present[@]}"; do
  echo "  - $path"
done

read -r -p 'Remove these directories? (y/N): ' reply || exit 1
if [[ $reply =~ ^[Yy]$ ]]; then
  for path in "${present[@]}"; do
    rm -rf "$path"
    echo "Removed $path"
  done
else
  echo 'Aborted.'
fi
