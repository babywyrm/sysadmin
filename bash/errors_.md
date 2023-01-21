#!/bin/bash

##
##

set -Eeuo pipefail
IFS=$'\n\t'
PROGNAME="$( basename $0 )"

# printf.color
# Arguments:
#   - 1: Color code (from: ansi-escape codes https://en.wikipedia.org/wiki/ANSI_escape_code#Colors)
#   - 2: Message
# Prints message in the color passed as the first argument. (no newline)
function printf.color {
  local color="$1"
  local message="$2"
  local no_color='\033[0m'

  printf "$color%s$no_color" "$message"
}

# printf.green
# Arguments:
#   - 1: Message
# Print message in color green. (no newline)
function printf.green {
  local green='\033[0;32m'
  local message="$1"

  printf.color "$green" "$message"
}

# printf.red
# Arguments:
#   - 1: Message
# Prints message in color red. (no newline)
function printf.red {
  local red='\033[0;31m'
  local message="$1"

  printf.color "$red" "$message"
}

# fail
# Arguments:
#   - 1: Line number (env-variable LINENO) (optional, default: "NAN")
#   - 2: Error message (optional, default: "Unknown Error")
#   - 3: Exit code (optional, default: 1)
# Facilitates failure communication
function fail {
  printf.red "$PROGNAME: ${2:-"Unknown Error"} [Line: #${1:-"NAN"}]" 1>&2
  echo 1>&2

  exit "${3:-1}"
}

# Ensure errors are properly handled
trap 'fail "$LINENO" "Unexpected error. Quitting."' ERR

##
##
