#!/usr/bin/env python3
"""Publish a requested tag only after CI for this exact main commit succeeds."""
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    sha = os.environ["GITHUB_SHA"]
    token = os.environ["GH_TOKEN"]
    if os.environ["GITHUB_REF"] != "refs/heads/main":
        raise RuntimeError("Release requests must run on main")
    tag = json.loads(Path(".github/release-request.json").read_text())["tag"]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag):
        raise RuntimeError("Invalid release tag")
    if not any(line == "## " + tag or line.startswith("## " + tag + " ")
               for line in Path("CHANGELOG.md").read_text(encoding="utf-8").splitlines()):
        raise RuntimeError("Requested tag has no changelog section")

    def api(path, method="GET", data=None, missing_ok=False):
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/{path}",
            data=None if data is None else json.dumps(data).encode(),
            method=method,
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing_ok:
                return None
            raise

    required = {".github/workflows/ci.yml", ".github/workflows/windows-gui.yml"}
    deadline = time.monotonic() + 30 * 60
    while True:
        runs = api(f"actions/runs?head_sha={sha}&event=push&per_page=100")["workflow_runs"]
        latest = {}
        for run in sorted(runs, key=lambda r: r["id"], reverse=True):
            if run["path"] in required:
                latest.setdefault(run["path"], run)
        for run in latest.values():
            if run["status"] == "completed" and run["conclusion"] != "success":
                raise RuntimeError(f"Release blocked by {run['name']}: {run['conclusion']} ({run['html_url']})")
        if required == set(latest) and all(r["conclusion"] == "success" for r in latest.values()):
            break
        if time.monotonic() > deadline:
            raise TimeoutError("Timed out waiting for Linux and Windows CI")
        print("Waiting for Linux and Windows CI for " + sha, flush=True)
        time.sleep(20)

    existing = api("git/ref/tags/" + tag, missing_ok=True)
    if existing is not None:
        if existing["object"]["type"] != "commit" or existing["object"]["sha"] != sha:
            raise RuntimeError("Refusing to move an existing tag")
    else:
        api("git/refs", "POST", {"ref": "refs/tags/" + tag, "sha": sha})

    release = api("releases/tags/" + tag, missing_ok=True)
    if release is None:
        before = {r["id"] for r in api("actions/workflows/release.yml/runs?event=workflow_dispatch&per_page=100")["workflow_runs"]}
        # Events made with GITHUB_TOKEN do not recursively trigger a tag-push
        # workflow. Explicit dispatch starts the existing Release workflow.
        api("actions/workflows/release.yml/dispatches", "POST", {"ref": tag, "inputs": {"tag": tag}})
        deadline = time.monotonic() + 30 * 60
        while True:
            runs = api(f"actions/workflows/release.yml/runs?event=workflow_dispatch&head_sha={sha}&per_page=100")["workflow_runs"]
            candidates = [r for r in runs if r["id"] not in before and r["head_branch"] == tag]
            if candidates:
                run = max(candidates, key=lambda r: r["id"])
                if run["status"] == "completed":
                    if run["conclusion"] != "success":
                        raise RuntimeError(f"Release failed: {run['html_url']}")
                    break
            if time.monotonic() > deadline:
                raise TimeoutError("Timed out waiting for Release workflow")
            print("Waiting for existing Release workflow: " + tag, flush=True)
            time.sleep(20)
        release = api("releases/tags/" + tag)
    if release["draft"]:
        raise RuntimeError("Release is still a draft")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"tag={tag}\n")
    print("Published release: " + release["html_url"], flush=True)


if __name__ == "__main__":
    main()
