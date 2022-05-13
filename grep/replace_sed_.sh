#!/usr/bin/env bash

set -o errexit -o pipefail

if [ "$#" -eq 0 ]
then
  echo "usage: rs PATTERN REPLACEMENT [PATH...]" > /dev/stderr
  exit 1
fi

pattern="$1"
replacement="$2"
shift 2

paths=("$@")

rg -l "$pattern" "${paths[@]}" | while IFS=$'\n' read -r file; do
  rg --passthru "$pattern" --replace "$replacement" "$file" | sponge "$file"
done


###################
##
##
