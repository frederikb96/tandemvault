#!/usr/bin/env bash
# Installs a sops release binary into /usr/local/bin after checking it against
# the release's published checksums. Usage: scripts/install-sops.sh VERSION ARCH
set -euo pipefail

version=${1:?version, e.g. v3.13.3}
arch=${2:?arch: amd64 or arm64}
file="sops-${version}.linux.${arch}"
base="https://github.com/getsops/sops/releases/download/${version}"

tmp=$(mktemp -d)
curl -fsSL -o "${tmp}/${file}" "${base}/${file}"
curl -fsSL -o "${tmp}/checksums.txt" "${base}/sops-${version}.checksums.txt"
(cd "$tmp" && grep " ${file}\$" checksums.txt | sha256sum --check --strict)
sudo install -m 0755 "${tmp}/${file}" /usr/local/bin/sops
sops --version
