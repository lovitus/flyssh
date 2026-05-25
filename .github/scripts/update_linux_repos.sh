#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --version VERSION --tag TAG --artifacts DIR --pages-dir DIR" >&2
}

version=""
tag=""
artifacts=""
pages_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --tag)
      tag="${2:-}"
      shift 2
      ;;
    --artifacts)
      artifacts="${2:-}"
      shift 2
      ;;
    --pages-dir)
      pages_dir="${2:-}"
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${version}" || -z "${tag}" || -z "${artifacts}" || -z "${pages_dir}" ]]; then
  usage
  exit 2
fi
if [[ "${version}" == v* ]]; then
  echo "package version must not include leading v: ${version}" >&2
  exit 1
fi
if [[ -z "${PACKAGE_GPG_PRIVATE_KEY:-}" || -z "${PACKAGE_GPG_PASSPHRASE:-}" ]]; then
  echo "PACKAGE_GPG_PRIVATE_KEY and PACKAGE_GPG_PASSPHRASE are required" >&2
  exit 1
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd apt-ftparchive
require_cmd createrepo_c
require_cmd dpkg-scanpackages
require_cmd gpg
require_cmd python3

mkdir -p \
  "${pages_dir}/apt/pool/main/f/flyssh" \
  "${pages_dir}/apt/dists/stable/main/binary-amd64" \
  "${pages_dir}/apt/dists/stable/main/binary-arm64" \
  "${pages_dir}/rpm/x86_64" \
  "${pages_dir}/rpm/aarch64"
touch "${pages_dir}/.nojekyll"

cp "${artifacts}/flyssh_${version}_amd64.deb" "${pages_dir}/apt/pool/main/f/flyssh/"
cp "${artifacts}/flyssh_${version}_arm64.deb" "${pages_dir}/apt/pool/main/f/flyssh/"
cp "${artifacts}/flyssh-${version}-1.x86_64.rpm" "${pages_dir}/rpm/x86_64/"
cp "${artifacts}/flyssh-${version}-1.aarch64.rpm" "${pages_dir}/rpm/aarch64/"

gnupg_home="$(mktemp -d)"
cleanup() {
  rm -rf "${gnupg_home}"
}
trap cleanup EXIT
chmod 700 "${gnupg_home}"
export GNUPGHOME="${gnupg_home}"

printf '%s\n' "${PACKAGE_GPG_PRIVATE_KEY}" | gpg --batch --import
key_id="$(gpg --batch --list-secret-keys --with-colons | awk -F: '/^sec:/ { print $5; exit }')"
if [[ -z "${key_id}" ]]; then
  echo "failed to find imported package signing key" >&2
  exit 1
fi

gpg --batch --yes --export "${key_id}" > "${pages_dir}/apt/flyssh-archive-keyring.gpg"
gpg --batch --yes --armor --export "${key_id}" > "${pages_dir}/rpm/RPM-GPG-KEY-flyssh"

(
  cd "${pages_dir}/apt"
  for arch in amd64 arm64; do
    pkg_dir="dists/stable/main/binary-${arch}"
    dpkg-scanpackages --arch "${arch}" pool /dev/null > "${pkg_dir}/Packages"
    gzip -9 -c "${pkg_dir}/Packages" > "${pkg_dir}/Packages.gz"
  done

  release_conf="$(mktemp)"
  cat > "${release_conf}" <<'EOF'
APT::FTPArchive::Release {
  Origin "FlySSH";
  Label "FlySSH";
  Suite "stable";
  Codename "stable";
  Architectures "amd64 arm64";
  Components "main";
  Description "FlySSH stable package repository";
};
EOF

  apt-ftparchive -c="${release_conf}" release dists/stable > dists/stable/Release
  rm -f "${release_conf}"

  gpg --batch --yes --pinentry-mode loopback --passphrase "${PACKAGE_GPG_PASSPHRASE}" \
    --local-user "${key_id}" --clearsign \
    --output dists/stable/InRelease dists/stable/Release
  gpg --batch --yes --pinentry-mode loopback --passphrase "${PACKAGE_GPG_PASSPHRASE}" \
    --local-user "${key_id}" --armor --detach-sign \
    --output dists/stable/Release.gpg dists/stable/Release
)

for arch in x86_64 aarch64; do
  repo_dir="${pages_dir}/rpm/${arch}"
  createrepo_c --update "${repo_dir}"
  gpg --batch --yes --pinentry-mode loopback --passphrase "${PACKAGE_GPG_PASSPHRASE}" \
    --local-user "${key_id}" --armor --detach-sign \
    --output "${repo_dir}/repodata/repomd.xml.asc" \
    "${repo_dir}/repodata/repomd.xml"
done

state_file="${pages_dir}/latest.json"
should_update_latest="$(
  python3 - "${state_file}" "${version}" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

state = Path(sys.argv[1])
target = sys.argv[2]


def key(version: str) -> tuple[int, ...]:
    out = []
    for part in re.split(r"[.-]", version):
        if part.isdigit():
            out.append(int(part))
        else:
            break
    return tuple(out)


current = ""
if state.exists():
    try:
        data = json.loads(state.read_text(encoding="utf-8"))
        current = data.get("version") if isinstance(data.get("version"), str) else ""
    except json.JSONDecodeError:
        current = ""

print("yes" if not current or key(target) >= key(current) else "no")
PY
)"

if [[ "${should_update_latest}" == "yes" ]]; then
  python3 - "${state_file}" "${version}" "${tag}" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

state = Path(sys.argv[1])
version = sys.argv[2]
tag = sys.argv[3]

state.write_text(
    json.dumps(
        {
            "version": version,
            "tag": tag,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY
else
  echo "latest.json already points to a newer version; preserving it"
fi

cat > "${pages_dir}/index.html" <<'EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>FlySSH package repositories</title>
</head>
<body>
  <h1>FlySSH package repositories</h1>
  <ul>
    <li><a href="apt/">APT repository</a></li>
    <li><a href="rpm/">RPM repository</a></li>
  </ul>
</body>
</html>
EOF
