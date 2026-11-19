#!/usr/bin/env bash
# Build release archives for every supported platform into dist/.
#
#   scripts/build-release.sh v1.2.3
#
# Each archive holds a statically linked rdpcli binary (CGO disabled), the
# README and the licence; dist/SHA256SUMS lists their checksums. Builds are
# reproducible: -trimpath, no build ID, and archive timestamps and owners
# fixed to the commit's.
set -euo pipefail
umask 022 # file modes are part of the archives; fix them for reproducibility

version=${1:?usage: $0 VERSION}
targets=(
	linux/amd64 linux/arm64 linux/arm
	darwin/amd64 darwin/arm64
	windows/amd64 windows/arm64
	freebsd/amd64
)

cd "$(dirname "$0")/.."
rm -rf dist
mkdir -p dist
mtime=$(git log -1 --format=%cI 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)

for t in "${targets[@]}"; do
	os=${t%/*} arch=${t#*/}
	name=rdpcli_${version#v}_${os}_${arch}
	stage=dist/$name
	mkdir -p "$stage"
	exe=rdpcli
	[[ $os == windows ]] && exe=rdpcli.exe
	echo "building $name" >&2
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOARM=7 go build -trimpath -buildvcs=false \
		-ldflags "-s -w -buildid= -X main.version=$version" -o "$stage/$exe" ./cmd/rdpcli
	cp README.md LICENSE "$stage/"
	touch -d "$mtime" "$stage" "$stage"/*
	if [[ $os == windows ]]; then
		(cd dist && find "$name" -print | sort | TZ=UTC zip -qX -@ "$name.zip")
	else
		tar -C dist --sort=name --owner=0 --group=0 --numeric-owner --mtime="$mtime" \
			-czf "dist/$name.tar.gz" "$name"
	fi
	rm -rf "$stage"
done

(cd dist && sha256sum -- *.tar.gz *.zip > SHA256SUMS)
cat dist/SHA256SUMS
