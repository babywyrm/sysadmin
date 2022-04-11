#!/bin/bash

# Install as /usr/local/bin/json-pretty with +xr permissions
#
# Usage: 
#
# * `json-pretty file.json` generate a prettified file-pretty.json file
# * `json-pretty file.json new-file.json` generate a prettified new-file.json file

if [ "$1" == "" ] || [ ! -f "$1" ]; then
    echo -e "\nFile $1 not found\n"
    exit 1
fi

if [ "$2" == "" ]; then
    TARGET="${1%.*}-pretty.json"
else
    TARGET="$2"
fi

if [ "$(which jq)" == "" ]; then
    cat "$1" | python -m json.tool > "$TARGET"
else
    jq . --indent 4 "$1" > "$TARGET"
fi

echo "$TARGET"

exit 0

#####################
##
##
