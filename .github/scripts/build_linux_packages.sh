#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --version VERSION --out-dir DIR" >&2
}

version=""
out_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${version}" || -z "${out_dir}" ]]; then
  usage
  exit 2
fi
if [[ "${version}" == v* ]]; then
  echo "package version must not include leading v: ${version}" >&2
  exit 1
fi
if ! command -v nfpm >/dev/null 2>&1; then
  export PATH="$(go env GOPATH)/bin:${PATH}"
fi
if ! command -v nfpm >/dev/null 2>&1; then
  echo "missing required command: nfpm" >&2
  exit 1
fi

mkdir -p "${out_dir}"

work_dir="${RUNNER_TEMP:-/tmp}/flyssh-linux-packages-${version}"
rm -rf "${work_dir}"
mkdir -p "${work_dir}"

ldflags="-s -w -X main.Version=${version}"

build_package() {
  local goarch="$1"
  local deb_arch="$2"
  local rpm_arch="$3"
  local root="${work_dir}/linux-${goarch}"
  local bin="${root}/flyssh"
  local config="${work_dir}/nfpm-${goarch}.yaml"

  mkdir -p "${root}"
  GOOS=linux GOARCH="${goarch}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "${ldflags}" -o "${bin}" .

  cat > "${config}" <<EOF
name: flyssh
arch: ${goarch}
platform: linux
version: ${version}
release: "1"
section: utils
priority: optional
maintainer: FlySSH Maintainers <noreply@github.com>
vendor: FlySSH
homepage: https://github.com/lovitus/flyssh
license: MIT
description: Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh.
contents:
  - src: ${bin}
    dst: /usr/bin/flyssh
EOF

  nfpm pkg --config "${config}" --packager deb \
    --target "${out_dir}/flyssh_${version}_${deb_arch}.deb"
  nfpm pkg --config "${config}" --packager rpm \
    --target "${out_dir}/flyssh-${version}-1.${rpm_arch}.rpm"
}

build_package amd64 amd64 x86_64
build_package arm64 arm64 aarch64
