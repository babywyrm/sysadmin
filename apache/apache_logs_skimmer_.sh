#!/usr/bin/env bash
#
# Apache Error Log Scanner - Improved
# Summarizes Apache error_log categories and reports top offenders.
set -euo pipefail

############################################
# CONFIGURATION
############################################

HTDOCS="/usr/local/apache/htdocs/"
MYHOME="/root/BASH/"
CGIBIN="/root/BASH/cgi-bin/"
ENTRIES_PER_CATEGORY=5
LOGFILE=""
TEMP_FILE="$(mktemp /tmp/apachelogscan.XXXXXX)"

# ANSI Colors (optional)
RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
CYAN=$'\033[36m'
RESET=$'\033[0m'

cleanup() {
    rm -f "$TEMP_FILE"
}
trap cleanup EXIT

############################################
# HELPER FUNCTIONS
############################################

usage() {
    echo "Usage: $(basename "$0") [-l count] /path/to/error_log" >&2
    exit 1
}

generate_sedstr() {
    # Masks common Apache paths for cleaner output
    cat <<EOF | tr -d '\n'
s|^| |g;
s|$HTDOCS|[htdocs] |g;
s|$MYHOME|[homedir] |g;
s|$CGIBIN|[cgi-bin] |g
EOF
}

filter_common_errors() {
    # Regex to exclude common noise
    echo "(File does not exist|Invalid error redirect|premature EOF|Premature end of script|script not found)"
}

print_top_occurrences() {
    local file="$1"
    local keyword="$2"
    local label="$3"

    grep -F "$keyword:" "$file" \
        | awk '{print $NF}' \
        | sort | uniq -c | sort -rn | head -n "$ENTRIES_PER_CATEGORY" \
        | sed -E "$(generate_sedstr)" > "$TEMP_FILE"

    if [[ -s "$TEMP_FILE" ]]; then
        echo -e "\n${CYAN}${label}${RESET}"
        cat "$TEMP_FILE"
    fi
}

############################################
# ARGUMENT PARSING
############################################

while [[ $# -gt 0 ]]; do
    case "$1" in
        -l)
            [[ $# -lt 2 ]] && usage
            ENTRIES_PER_CATEGORY="$2"
            shift 2
            ;;
        -*)
            usage
            ;;
        *)
            LOGFILE="$1"
            shift
            ;;
    esac
done

[[ -z "$LOGFILE" || ! -r "$LOGFILE" ]] && usage

############################################
# MAIN REPORT
############################################

echo -e "${YELLOW}Scanning:${RESET} $LOGFILE"
echo "Total entries: $(wc -l < "$LOGFILE")"

START=$(grep -E '\[[0-9]{2}/[A-Za-z]+/[0-9]{4}' "$LOGFILE" | head -n1 | cut -d']' -f1 | tr -d '[')
END=$(grep -E '\[[0-9]{2}/[A-Za-z]+/[0-9]{4}' "$LOGFILE" | tail -n1 | cut -d']' -f1 | tr -d '[')
echo "Date range: $START  →  $END"

############################################
# COMMON ERROR CATEGORIES
############################################

print_top_occurrences "$LOGFILE" "File does not exist" "Missing Files"
print_top_occurrences "$LOGFILE" "Invalid error redirection directive" "Invalid Redirects"
print_top_occurrences "$LOGFILE" "Premature EOF" "Premature EOF"
print_top_occurrences "$LOGFILE" "Script not found or unable to stat" "Script Missing"
print_top_occurrences "$LOGFILE" "Premature end of script headers" "Premature Script Headers"

############################################
# ADDITIONAL ERROR MESSAGES
############################################

grep -Ev "$(filter_common_errors)" "$LOGFILE" \
    | grep "\[error\]" | grep "\[client " \
    | sed 's/\[error\]/`/' | cut -d'`' -f2 | cut -d' ' -f4- \
    | sort | uniq -c | sort -rn | head -n "$ENTRIES_PER_CATEGORY" > "$TEMP_FILE"

if [[ -s "$TEMP_FILE" ]]; then
    echo -e "\n${RED}Additional error messages:${RESET}"
    cat "$TEMP_FILE"
fi

############################################
# NON-ERROR LOG MESSAGES
############################################

echo -e "\n${GREEN}Non-error log messages:${RESET}"
grep -Ev "$(filter_common_errors)" "$LOGFILE" | grep -v "\[error\]" \
    | sort | uniq -c | sort -rn | head -n "$ENTRIES_PER_CATEGORY" \
    | sed 's/^/ /'

exit 0

##
##
