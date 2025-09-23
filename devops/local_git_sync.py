#!/usr/bin/env python3
# coding=utf-8
"""
Sync a locally cloned GitHub fork with its upstream parent repository, (..updated..)

Modernized for 2025:
- Supports main/master default branches
- Safer subprocess handling with run()
- Clear error messages and exit codes
- Automatic upstream detection via GitHub API
"""

import os
import sys
import subprocess
import requests
from pathlib import Path

DEFAULT_BRANCHES = ["main", "master"]


def run_cmd(cmd, check=True, capture=False):
    """Run a shell command safely."""
    try:
        if capture:
            result = subprocess.run(cmd, check=check, text=True, capture_output=True)
            return result.stdout.strip()
        else:
            subprocess.run(cmd, check=check)
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {' '.join(cmd)}")
        print(e.stderr if e.stderr else e)
        if check:
            sys.exit(1)


def check_git_repo():
    """Ensure current directory is a Git repo."""
    if not Path(".git").exists():
        print("[!] Not a git repository")
        sys.exit(1)


def get_repo_origin_url():
    return run_cmd(["git", "config", "--get", "remote.origin.url"], capture=True)


def get_repo_upstream_url():
    try:
        return run_cmd(["git", "config", "--get", "remote.upstream.url"], capture=True)
    except SystemExit:
        return None


def detect_default_branch():
    """Check if repo uses main or master."""
    for branch in DEFAULT_BRANCHES:
        try:
            run_cmd(["git", "show-ref", "--verify", f"refs/heads/{branch}"], check=True)
            return branch
        except SystemExit:
            continue
    print("[!] Could not detect default branch (main/master). Exiting.")
    sys.exit(1)


def fetch_upstream():
    print("[*] Fetching upstream...")
    run_cmd(["git", "fetch", "upstream"])


def checkout_branch(branch):
    print(f"[*] Checking out {branch}")
    run_cmd(["git", "checkout", branch])


def merge_upstream(branch):
    print(f"[*] Merging upstream/{branch}")
    run_cmd(["git", "merge", f"upstream/{branch}"])


def push_to_origin(branch):
    print(f"[*] Pushing changes to origin/{branch}")
    run_cmd(["git", "push", "origin", branch])


def add_repo_upstream():
    """Derive parent repo via GitHub API and add as upstream."""
    origin_url = get_repo_origin_url()
    if origin_url.startswith("git@github.com:"):
        path = origin_url.split("git@github.com:")[1]
    elif origin_url.startswith("https://github.com/"):
        path = origin_url.split("https://github.com/")[1]
    else:
        print("[!] Unknown origin URL format")
        sys.exit(1)

    user_repo = path.replace(".git", "")
    user, repo = user_repo.split("/")
    url = f"https://api.github.com/repos/{user}/{repo}"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        parent_url = data["parent"]["clone_url"]
    except Exception as e:
        print(f"[!] Failed to get parent repo info: {e}")
        sys.exit(1)

    print(f"[*] Adding upstream: {parent_url}")
    run_cmd(["git", "remote", "add", "upstream", parent_url])


def sync():
    print("=" * 80)
    print(">>> Starting Fork Sync Process <<<".center(80))
    print("=" * 80)

    check_git_repo()
    origin = get_repo_origin_url()
    print(f"[*] Origin: {origin}")

    upstream = get_repo_upstream_url()
    if not upstream:
        print("[!] No upstream found, attempting to add...")
        add_repo_upstream()
        upstream = get_repo_upstream_url()

    print(f"[*] Upstream: {upstream}")

    branch = detect_default_branch()

    fetch_upstream()
    checkout_branch(branch)
    merge_upstream(branch)
    push_to_origin(branch)

    print("=" * 80)
    print(">>> Fork Sync Complete <<<".center(80))
    print("=" * 80)


if __name__ == "__main__":
    repo_path = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    os.chdir(repo_path)
    print(f"[*] Working directory: {os.getcwd()}")
    sync()
##
##
