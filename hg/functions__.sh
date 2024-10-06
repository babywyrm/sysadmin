#!/bin/bash

##
##

set -euo pipefail  # Enable strict error handling
IFS=$'\n\t'        # Set Internal Field Separator to handle spaces in filenames

# Usage message
usage() {
  echo "Usage: $0 <dir> [<repo> [<branch>]]"
  exit 1
}

# Resolve directory and set repo/branch defaults
resolve_inputs() {
  local dir repo branch
  dir=$(readlink -f "$1") || usage
  repo=${2:-$(hg --cwd "$dir" paths default || true)}
  branch=${3:-$(get_default_branch "$dir")}
  echo "$dir" "$repo" "$branch"
}

# Get the default branch, fallback to directory name if needed
get_default_branch() {
  local dir=$1
  if [[ -d "$dir" ]]; then
    (cd "$dir" && hg branch)
  else
    basename "$dir"
  fi
}

# Safely run and print commands
run() {
  echo "-> $*"
  "$@"
}

# Update the hgrc file with the repo path
update_hgrc() {
  local dir=$1
  local repo=$2
  echo "-> updating $dir/.hg/hgrc"
  cat > "$dir/.hg/hgrc" <<-EOF
[paths]
default = $repo
EOF
  cat "$dir/.hg/hgrc"
}

# Perform the Mercurial update in an existing repo
update_repo() {
  local dir=$1
  local repo=$2
  local branch=$3
  run hg --cwd "$dir" pull "$repo" -r "$branch"
  run hg --cwd "$dir" update -C "$branch"
}

# Clone from the stable branches if available
clone_from_stable() {
  local dir=$1
  run hg clone -U ~/branches/stable "$dir"
}

# Clone a new repo
clone_new_repo() {
  local repo=$1
  local branch=$2
  local dir=$3
  run hg clone "$repo" -r "$branch" "$dir"
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
  fi

  # Parse input and resolve repo/branch defaults
  read -r dir repo branch < <(resolve_inputs "$@")

  # If directory already exists, update it
  if [[ -d "$dir" ]]; then
    canonical_repo=$(hg paths --cwd "$dir" "$repo" 2>/dev/null || echo "$repo")
    update_hgrc "$dir" "$canonical_repo"
    update_repo "$dir" "$repo" "$branch"

  # If ~/branches/stable exists, clone from there
  elif [[ -d ~/branches/stable ]]; then
    clone_from_stable "$dir"
    canonical_repo=$(hg paths --cwd ~/branches/stable "$repo" 2>/dev/null || echo "$repo")
    update_hgrc "$dir" "$canonical_repo"
    update_repo "$dir" "$repo" "$branch"

  # Otherwise, perform a new clone
  else
    clone_new_repo "$repo" "$branch" "$dir"
  fi
}

main "$@"

##
##

