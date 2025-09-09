#!/usr/bin/env bash
#
# git-helper.sh – Git utilities for syncing repos
#
# Provides two subcommands:
#   1. sync-local      – Add, commit, and push changes in the current repo
#   2. setup-fork-sync – Configure GitHub Action to keep a fork synced with upstream
#
# Author: Combined & modernized version (2025)
# Based on scripts from Himanshu Shekhar and Mathiue Carbou .. (respect) 
#

set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <command> [args...]

Commands:
  sync-local
      Add, commit, and push changes in the current repo.

  setup-fork-sync <fork> <upstream> <branch-to-sync> [domain] [cron]
      Configure GitHub Actions workflow to sync a fork.
      - fork:    your fork repository (e.g. user/myfork)
      - upstream: upstream repository (e.g. org/repo)
      - branch:  branch to sync (e.g. main)
      - domain:  Git host (default: github.com)
      - cron:    cron expression for schedule (default: '0 */2 * * *')

Examples:
  $0 sync-local
  $0 setup-fork-sync user/myfork org/repo main
  $0 setup-fork-sync user/myfork org/repo main github.com '0 */6 * * *'
EOF
  exit 1
}

# ---------------------------
# Subcommand: sync-local
# ---------------------------
sync_local() {
  # Verify we're inside a git repository
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "ERROR: Not inside a Git repository."
    exit 1
  fi

  # Show current status
  echo "Repository status:"
  git status

  # Stage all changes
  git add .

  # Prompt for commit message
  read -r -p "Enter commit message (leave empty to skip commit): " commsg

  if [ -n "$commsg" ]; then
    git commit -m "$commsg" || echo "No changes to commit."
  else
    echo "Commit skipped."
  fi

  # Detect current branch
  branch=$(git symbolic-ref --short HEAD 2>/dev/null || echo "main")
  echo "Pushing to origin/$branch..."
  git push -u origin "$branch"
}

# ---------------------------
# Subcommand: setup-fork-sync
# ---------------------------
setup_fork_sync() {
  if [[ $# -lt 3 || $# -gt 5 ]]; then
    usage
  fi

  fork=$1
  upstream=$2
  branch=$3
  domain="${4:-github.com}"
  cron="${5:-'0 */2 * * *'}"

  # Create temporary directory
  tmp_dir=$(mktemp -d -t git-fork-sync-XXXXXX)
  trap "rm -rf $tmp_dir" EXIT

  echo "Cloning fork into temporary directory: $tmp_dir"
  git clone --depth=1 "git@$domain:$fork.git" "$tmp_dir"

  cd "$tmp_dir"

  # Ensure 'actions' branch exists
  if ! git rev-parse --verify actions >/dev/null 2>&1; then
    echo "Creating 'actions' branch..."
    git checkout --orphan actions
    git rm -rf .
    git commit --allow-empty -m "Initialize actions branch"
    git push origin actions
  else
    git checkout actions
  fi

  # Create workflow
  mkdir -p .github/workflows
  cat > .github/workflows/fork-sync.yml <<EOF
name: "Fork Sync"
on:
  schedule:
    - cron:  $cron
  workflow_dispatch:

jobs:
  sync-$branch:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout $branch
      uses: actions/checkout@v4
      with:
        ref: $branch
        token: \${{ secrets.GITHUB_TOKEN }}

    - name: Sync from upstream
      uses: mathieucarbou/Fork-Sync-With-Upstream-action@fork-sync
      with:
        domain: $domain
        upstream_repository: $upstream
        upstream_branch: $branch
        target_branch: $branch
        git_pull_args: --ff-only

    - name: Log timestamp
      run: date
EOF

  git add .github/workflows/fork-sync.yml
  git commit -m "Add or update fork sync workflow" || true
  git push origin actions

  echo ""
  echo "=========================================================================="
  echo "Fork sync workflow has been pushed to: $fork (branch: actions)"
  echo ""
  echo "Next steps:"
  echo "  1. Go to repo settings: https://$domain/$fork/settings/branches"
  echo "     Set 'actions' as the default branch."
  echo "  2. Trigger the sync manually at least once:"
  echo "     https://$domain/$fork/actions"
  echo "=========================================================================="
}

# ---------------------------
# Main
# ---------------------------
cmd=${1:-}
shift || true

case "$cmd" in
  sync-local)      sync_local "$@" ;;
  setup-fork-sync) setup_fork_sync "$@" ;;
  *)               usage ;;
esac
##
##
