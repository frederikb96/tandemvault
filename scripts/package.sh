#!/usr/bin/env bash
# Builds the binary, the tarball and the .deb, .rpm and Arch packages for one architecture.
# Usage: scripts/package.sh VERSION ARCH OUTDIR    (ARCH: amd64 or arm64)
# Runs natively on that architecture: the 1Password SDK's desktop integration needs CGO.
set -euo pipefail

version=${1:?version}
arch=${2:?arch}
out=${3:?outdir}

case "$(uname -m)" in
  x86_64) native=amd64 ;;
  aarch64) native=arm64 ;;
  *) native=unknown ;;
esac
if [ "$arch" != "$native" ]; then
  echo "package.sh builds natively only: asked for $arch on $native" >&2
  exit 1
fi

mkdir -p "$out" build
CGO_ENABLED=1 go build -trimpath \
  -ldflags "-s -w -X main.version=${version}" \
  -o build/tandemvault ./cmd/tandemvault
./build/tandemvault version

name="tandemvault_${version}_linux_${arch}"
mkdir -p "build/${name}"
cp build/tandemvault LICENSE README.md "build/${name}/"
tar -C build -czf "${out}/${name}.tar.gz" "${name}"

for packager in deb rpm archlinux; do
  case "$packager" in
    deb) ext=deb ;;
    rpm) ext=rpm ;;
    archlinux) ext=pkg.tar.zst ;;
  esac
  VERSION="$version" ARCH="$arch" nfpm package --config nfpm.yaml --packager "$packager" \
    --target "${out}/tandemvault_${version}_${arch}.${ext}"
done
ls -l "$out"
