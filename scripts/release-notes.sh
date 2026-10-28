#!/usr/bin/env bash
# Prints the CHANGELOG.md section of one version. Fails when there is none.
# Usage: scripts/release-notes.sh VERSION   (without the leading v)
set -euo pipefail

version=${1:?version}
notes=$(awk -v v="$version" '
  /^## \[/ { if (found) exit; if (index($0, "## [" v "]") == 1) { found = 1; next } }
  /^\[[^]]*\]: / { if (found) exit }
  found { print }
' CHANGELOG.md)
if [ -z "${notes//[[:space:]]/}" ]; then
  echo "CHANGELOG.md has no section for $version" >&2
  exit 1
fi
printf '%s\n' "$notes"
