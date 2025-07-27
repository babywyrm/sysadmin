#!/usr/bin/env bash
#
# Apache Error Log Scanner -- Refactored
# Scans an Apache error_log and summarizes key error categories.

set -euo pipefail

### ==== Configuration ====

HTDOCS="/usr/local/apache/htdocs/"
MYHOME="/root/BASH/"
CGIBIN="/root/BASH/cgi-bin/"

ENTRIES_PER_CATEGORY=5
LOGFILE=""
TEMP_FILE="$(mktemp /tmp/apachelogscan.XXXXXX)"

CLEANUP() {
    rm -f "$TEMP_FILE"
}
trap CLEANUP EXIT

### ==== Functions ====

generate_sedstr() {
    echo "s|^| |g;
          s|$HTDOCS|[htdocs] |g;
          s|$MYHOME|[homedir] |g;
          s|$CGIBIN|[cgi-bin] |g" | tr -d '\n'
}

filter_common_errors() {
    echo "(File does not exist|Invalid error redirect|premature EOF|Premature end of script|script not found)"
}

print_top_occurrences() {
    local file="$1"
    local keyword="$2"
    grep -F "$keyword:" "$file" | awk '{print $NF}' \
        | sort | uniq -c | sort -rn | head -n "$ENTRIES_PER_CATEGORY" \
        | sed -E "$(generate_sedstr)" > "$TEMP_FILE"

    if [[ -s "$TEMP_FILE" ]]; then
        echo -e "\n$keyword errors:"
        cat "$TEMP_FILE"
    fi
}

### ==== Argument Parsing ====

usage() {
    echo "Usage: $(basename "$0") [-l count] error_log" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -l)
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

if [[ -z "$LOGFILE" || ! -r "$LOGFILE" ]]; then
    usage
fi

### ==== Main Report ====

echo "Input file '$LOGFILE' has $(wc -l < "$LOGFILE") entries."

START=$(grep -E '\[.*:.*:.*\]' "$LOGFILE" | head -n1 | cut -d']' -f1 | sed 's/\[//')
END=$(grep -E '\[.*:.*:.*\]' "$LOGFILE" | tail -n1 | cut -d']' -f1 | sed 's/\[//')
echo "Entries span from $START to $END"

### ==== Common Error Categories ====

print_top_occurrences "$LOGFILE" "File does not exist"
print_top_occurrences "$LOGFILE" "Invalid error redirection directive"
print_top_occurrences "$LOGFILE" "Premature EOF"
print_top_occurrences "$LOGFILE" "Script not found or unable to stat"
print_top_occurrences "$LOGFILE" "Premature end of script headers"

### ==== Additional [error] messages (filtered) ====

grep -Ev "$(filter_common_errors)" "$LOGFILE" | grep "\[error\]" | grep "\[client " \
    | sed 's/\[error\]/`/' | cut -d'`' -f2 | cut -d' ' -f4- \
    | sort | uniq -c | sort -rn | head -n "$ENTRIES_PER_CATEGORY" > "$TEMP_FILE"

if [[ -s "$TEMP_FILE" ]]; then
    echo -e "\nAdditional error messages in log file:"
    cat "$TEMP_FILE"
fi

### ==== Non-error log messages ====

echo -e "\nNon-error log messages:"
grep -Ev "$(filter_common_errors)" "$LOGFILE" | grep -v "\[error\]" \
    | sort | uniq -c | sort -rn | head -n "$ENTRIES_PER_CATEGORY" \
    | sed 's/^/ /'

exit 0
