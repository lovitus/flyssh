#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


REPO = "lovitus/flyssh"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update Homebrew/Scoop manifests.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--checksums", required=True, type=Path)
    return parser.parse_args()


def version_key(version: str) -> tuple[int, ...]:
    parts = re.split(r"[.-]", version)
    key = []
    for part in parts:
        if part.isdigit():
            key.append(int(part))
        else:
            break
    return tuple(key)


def current_scoop_version(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    version = data.get("version")
    return version if isinstance(version, str) else None


def should_update(target_version: str, scoop_path: Path) -> bool:
    current = current_scoop_version(scoop_path)
    if not current:
        return True
    return version_key(target_version) >= version_key(current)


def load_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        checksum, filename = fields
        checksums[filename] = checksum
    return checksums


def checksum(checksums: dict[str, str], filename: str) -> str:
    try:
        return checksums[filename]
    except KeyError as exc:
        raise SystemExit(f"missing checksum for {filename}") from exc


def artifact(version: str, goos: str, goarch: str, ext: str) -> str:
    return f"flyssh-{version}-{goos}-{goarch}.{ext}"


def release_url(version: str, filename: str) -> str:
    return f"https://github.com/{REPO}/releases/download/v{version}/{filename}"


def write_homebrew_formula(version: str, checksums: dict[str, str], path: Path) -> None:
    darwin_arm64 = artifact(version, "darwin", "arm64", "tar.gz")
    darwin_amd64 = artifact(version, "darwin", "amd64", "tar.gz")
    linux_arm64 = artifact(version, "linux", "arm64", "tar.gz")
    linux_amd64 = artifact(version, "linux", "amd64", "tar.gz")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'''class Flyssh < Formula
  desc "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh"
  homepage "https://github.com/{REPO}"
  version "{version}"
  license "MIT"

  on_macos do
    on_arm do
      url "{release_url(version, darwin_arm64)}"
      sha256 "{checksum(checksums, darwin_arm64)}"
    end

    on_intel do
      url "{release_url(version, darwin_amd64)}"
      sha256 "{checksum(checksums, darwin_amd64)}"
    end
  end

  on_linux do
    on_arm do
      url "{release_url(version, linux_arm64)}"
      sha256 "{checksum(checksums, linux_arm64)}"
    end

    on_intel do
      url "{release_url(version, linux_amd64)}"
      sha256 "{checksum(checksums, linux_amd64)}"
    end
  end

  def install
    bin.install Dir["flyssh-*"].first => "flyssh"
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/flyssh --version")
  end
end
''',
        encoding="utf-8",
    )


def scoop_arch(version: str, checksums: dict[str, str], goarch: str) -> dict[str, object]:
    filename = artifact(version, "windows", goarch, "exe.zip")
    exe = f"flyssh-{version}-windows-{goarch}.exe"
    return {
        "url": release_url(version, filename),
        "hash": checksum(checksums, filename),
        "bin": [[exe, "flyssh"]],
    }


def scoop_autoupdate_arch(goarch: str) -> dict[str, object]:
    exe = f"flyssh-$version-windows-{goarch}.exe"
    filename = f"{exe}.zip"
    return {
        "url": f"https://github.com/{REPO}/releases/download/v$version/{filename}",
        "hash": {
            "url": "$baseurl/checksums.txt",
            "regex": f"$sha256\\s+flyssh-$version-windows-{goarch}\\.exe\\.zip",
        },
        "bin": [[exe, "flyssh"]],
    }


def write_scoop_manifest(version: str, checksums: dict[str, str], path: Path) -> None:
    data = {
        "version": version,
        "description": "Portable SSH client with SOCKS, multi-hop, transfer GUI, gateway, and mosh.",
        "homepage": f"https://github.com/{REPO}",
        "license": "MIT",
        "architecture": {
            "64bit": scoop_arch(version, checksums, "amd64"),
            "arm64": scoop_arch(version, checksums, "arm64"),
        },
        "checkver": {
            "github": f"https://github.com/{REPO}",
        },
        "autoupdate": {
            "architecture": {
                "64bit": scoop_autoupdate_arch("amd64"),
                "arm64": scoop_autoupdate_arch("arm64"),
            },
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()
    scoop_path = Path("bucket/flyssh.json")
    if not should_update(args.version, scoop_path):
        print(f"package manifests already point to newer version than {args.version}; skipping")
        return

    checksums = load_checksums(args.checksums)
    write_homebrew_formula(args.version, checksums, Path("Formula/flyssh.rb"))
    write_scoop_manifest(args.version, checksums, scoop_path)


if __name__ == "__main__":
    main()
