#!/usr/bin/env bash
# ffufs-modern.sh
# Usage:
#   ./ffufs-modern.sh -w WORDLIST -u URL [options] -- [extra ffuf args]
#
# Examples:
#   ./ffufs-modern.sh -w /path/wordlist.txt -u https://example.com
#   ./ffufs-modern.sh -w wl.txt -u https://example.com -o ./results -t 50 -j -- -H "User-Agent:MyAgent"
#
set -euo pipefail

# ---------- config / colors ----------
RESET=$'\033[0m'
RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
BLUE=$'\033[1;34m'
MAGENTA=$'\033[1;35m'
WHITE=$'\033[1;37m'

# defaults
OUTDIR="./ffuf_results"
THREADS=40
SAVE_JSON=0
SAVE_CSV=1
SUMMARY=1
EXTS=""
WORDLIST=""
TARGET=""
FFUF_BIN="ffuf"

PROGNAME=$(basename "$0")

usage() {
  cat <<EOF
Usage: $PROGNAME -w WORDLIST -u URL [options] -- [extra ffuf args]

Required:
  -w PATH         Wordlist file (one entry per line)
  -u URL          Target base URL (e.g. https://example.com)

Options:
  -o DIR          Output directory (default: ./ffuf_results)
  -t N            Threads/concurrency for ffuf (default: 40)
  -e exts         Comma-separated extensions (e.g. php,html,txt)
  -j              Save raw ffuf JSON output (also saves CSV if enabled)
  -n              Don't save CSV output (default is to save CSV)
  -s              Disable summary output
  -h              Show this help

Any arguments after -- are passed directly to ffuf.

EOF
  exit 1
}

# ---------- parse args ----------
EXTRA_FFUF_ARGS=()
while getopts ":w:u:o:t:e:jsnh" opt; do
  case $opt in
    w) WORDLIST=$OPTARG ;;
    u) TARGET=$OPTARG ;;
    o) OUTDIR=$OPTARG ;;
    t) THREADS=$OPTARG ;;
    e) EXTS=$OPTARG ;;
    j) SAVE_JSON=1 ;;
    n) SAVE_CSV=0 ;;
    s) SUMMARY=0 ;;
    h) usage ;;
    \?) printf "%s\n" "Invalid option: -$OPTARG" >&2; usage ;;
    :) printf "%s\n" "Option -$OPTARG requires an argument." >&2; usage ;;
  esac
done

shift $((OPTIND - 1))
# remaining args after -- are extra ffuf args
if [ "${#@}" -gt 0 ]; then
  EXTRA_FFUF_ARGS=( "$@" )
fi

# ---------- sanity checks ----------
command -v "$FFUF_BIN" >/dev/null 2>&1 || { echo "$FFUF_BIN not found in PATH; please install ffuf." >&2; exit 2; }
if [ -z "$WORDLIST" ] || [ -z "$TARGET" ]; then
  echo "Missing required parameters." >&2
  usage
fi
if [ ! -f "$WORDLIST" ]; then
  echo "Wordlist not found: $WORDLIST" >&2
  exit 3
fi

# Ensure target has scheme
if ! [[ "$TARGET" =~ ^https?:// ]]; then
  echo "URL must start with http:// or https:// (got: $TARGET)" >&2
  exit 4
fi

# extract host for naming (strip creds if present)
# Use parameter expansion to avoid external dependencies
# remove protocol
_host="${TARGET#*://}"
# remove path and port if present
_host="${_host%%/*}"
# remove possible user:pass@
_host="${_host##*@}"
# safe filename
THISDOMAIN="${_host//[^a-zA-Z0-9._-]/_}"

# create outdir
mkdir -p "$OUTDIR"

# temp workdir for this run
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/ffufrun.XXXXXX")
trap 'rc=$?; rm -rf "$WORKDIR"; exit $rc' EXIT

TIMESTAMP=$(date +'%Y%m%dT%H%M%S')
BASENAME="${THISDOMAIN}-${TIMESTAMP}"
CSV_OUT="${OUTDIR}/${BASENAME}.csv"
JSON_OUT="${OUTDIR}/${BASENAME}.json"
PLAIN_OUT="${OUTDIR}/${BASENAME}.txt"           # pretty colorized human output
PLAIN_OUT_PLAIN="${OUTDIR}/${BASENAME}.plain"   # non-colored plain output

# ---------- build ffuf args ----------
FFUF_CMD=( "$FFUF_BIN" -c -w "$WORDLIST" -u "${TARGET}/FUZZ" -t "$THREADS" )

# add extensions if requested
if [ -n "$EXTS" ]; then
  # ffuf expects -e ext1 -e ext2, so expand
  IFS=',' read -ra EARR <<< "$EXTS"
  for e in "${EARR[@]}"; do
    FFUF_CMD+=( -e "$e" )
  done
fi

# outputs: if requested, save JSON and/or CSV
if [ "$SAVE_JSON" -eq 1 ]; then
  FFUF_CMD+=( -o "$JSON_OUT" -of json )
fi
if [ "$SAVE_CSV" -eq 1 ]; then
  FFUF_CMD+=( -o "$CSV_OUT" -of csv )
fi

# append extra args provided by user (after --)
if [ "${#EXTRA_FFUF_ARGS[@]}" -gt 0 ]; then
  FFUF_CMD+=( "${EXTRA_FFUF_ARGS[@]}" )
fi

# ---------- run ffuf ----------
echo -e "${BLUE}Running ffuf on ${WHITE}$TARGET${RESET}"
echo "Command: ${FFUF_CMD[*]}"
if ! "${FFUF_CMD[@]}" > "$WORKDIR/ffuf_stdout.log" 2>&1; then
  echo -e "${RED}ffuf exited with non-zero status; check ${WORKDIR}/ffuf_stdout.log${RESET}" >&2
fi

# If ffuf didn't produce CSV but produced JSON, try to create CSV from JSON via jq (if available)
if [ "$SAVE_CSV" -eq 1 ] && [ ! -s "$CSV_OUT" ] && [ -s "$JSON_OUT" ]; then
  if command -v jq >/dev/null 2>&1; then
    echo "Converting ffuf JSON to CSV using jq..."
    jq -r '.results[] | [.input, .url, .status, .length, .words] | @csv' "$JSON_OUT" > "$CSV_OUT" || true
  fi
fi

# If we saved CSV, parse it. If not, try to fall back to parsing ffuf stdout (best-effort).
if [ -s "$CSV_OUT" ]; then
  SRC_CSV="$CSV_OUT"
else
  # try to find any CSV-like artifact in workdir
  SRC_CSV=$(grep -l "URL,Referrer,Status,Length" "$WORKDIR"/* 2>/dev/null | head -n1 || true)
  if [ -z "$SRC_CSV" ]; then
    echo -e "${MAGENTA}No CSV output available to parse. Exiting.${RESET}"
    exit 0
  fi
fi

# ---------- parse CSV and produce colored/plain output ----------
# ffuf CSV columns may vary; attempt robust parsing with awk:
# Expected common format: url,status,length,words,input (but ffuf versions differ)
# We'll try to support either "url,status,length,words,input" or "input,url,words,length,status"
awk -v target="$TARGET" -v plain_out="$PLAIN_OUT_PLAIN" -v colored_out="$PLAIN_OUT" -v reset="$RESET" -v g="$GREEN" -v b="$BLUE" -v m="$MAGENTA" -v r="$RED" '
BEGIN {
  FS = ",";
  OFS = ",";
  printed = 0;
  print "Results for " target > plain_out;
  print "Results for " target > colored_out;
}
# skip header lines that contain non-data
/^(#|URL|url|Input|input)/ { next }
{
  # remove surrounding quotes
  for (i=1;i<=NF;i++) {
    gsub(/^"|"$/, "", $i);
    gsub(/\r$/, "", $i);
  }

  # heuristics: find status, length, input, url
  status = ""
  length = ""
  input = ""
  url = ""

  # find first numeric field that looks like a status (3-digit)
  for (i=1;i<=NF;i++) {
    if ($i ~ /^[0-9]{3}$/ && status == "") { status = $i }
  }
  # find a numeric length (heuristic > 0)
  for (i=1;i<=NF;i++) {
    if ($i ~ /^[0-9]+$/ && $i != status && length == "") { length = $i }
  }

  # guess url/input by presence of "http" or path-looking string
  for (i=1;i<=NF;i++) {
    if ($i ~ /^https?:\/\// && url == "") { url = $i }
  }
  # input is anything with "FUZZ" replaced in original; try last field if url found earlier
  if (url != "") {
    # try to extract path from url by removing target if present
    path = url;
    sub("^" target, "", path);
    if (path == "") { path = "/" }
    input = path
  } else {
    # fallback: use first non-numeric field as input
    for (i=1;i<=NF;i++) {
      if ($i !~ /^[0-9]+$/ && $i !~ /^https?:\/\//) { input = $i; break }
    }
  }

  # final fallbacks
  if (status == "") status = "000"
  if (length == "") length = "0"
  if (input == "") input = "(unknown)"

  # build plain and colored lines
  plain_line = target input " [Status: " status ", Size: " length "]"
  if (status ~ /^2/) { colored_line = target input " [Status: " g status reset ", Size: " length "]" }
  else if (status ~ /^3/) { colored_line = target input " [Status: " b status reset ", Size: " length "]" }
  else if (status ~ /^4/) { colored_line = target input " [Status: " m status reset ", Size: " length "]" }
  else if (status ~ /^5/) { colored_line = target input " [Status: " r status reset ", Size: " length "]" }
  else { colored_line = plain_line }

  print plain_line >> plain_out
  print colored_line >> colored_out

  # keep counters
  if (status ~ /^2/) c2++
  else if (status ~ /^3/) c3++
  else if (status ~ /^4/) c4++
  else if (status ~ /^5/) c5++
  total++
}
END {
  # write summary to the end of plain_out
  print "" >> plain_out
  print "Summary:" >> plain_out
  print " Total: " (total+0) >> plain_out
  print " 2xx: " (c2+0) >> plain_out
  print " 3xx: " (c3+0) >> plain_out
  print " 4xx: " (c4+0) >> plain_out
  print " 5xx: " (c5+0) >> plain_out

  # append the same summary to colored_out
  print "" >> colored_out
  print "Summary:" >> colored_out
  print " Total: " (total+0) >> colored_out
  print " 2xx: " (c2+0) >> colored_out
  print " 3xx: " (c3+0) >> colored_out
  print " 4xx: " (c4+0) >> colored_out
  print " 5xx: " (c5+0) >> colored_out
}
' "$SRC_CSV"

# sort the plain (non-colored) output for deterministic ordering (by status then size)
if [ -f "$PLAIN_OUT_PLAIN" ]; then
  # keep header lines then sort the entries (skip first line "Results for ...")
  ( head -n1 "$PLAIN_OUT_PLAIN" && tail -n +2 "$PLAIN_OUT_PLAIN" | sort -t: -k3,3 -k5,5 -n ) > "${PLAIN_OUT_PLAIN}.sorted" || true
  mv "${PLAIN_OUT_PLAIN}.sorted" "$PLAIN_OUT_PLAIN"
fi

# copy plain->colored replacement of color codes to display to terminal
# (the colored file already contains escape sequences; display as-is)
if [ "$SUMMARY" -eq 1 ]; then
  echo -e "${BLUE}RESULTS: ${WHITE}$TARGET${RESET}"
  # show the colored file (if exists)
  if [ -f "$PLAIN_OUT" ]; then
    sed -n '1,200p' "$PLAIN_OUT" || true
  elif [ -f "$PLAIN_OUT_PLAIN" ]; then
    sed -n '1,200p' "$PLAIN_OUT_PLAIN" || true
  fi
fi

# optionally print locations of saved files
echo -e "\nSaved outputs (if produced):"
[ -f "$CSV_OUT" ] && echo " CSV:  $CSV_OUT"
[ -f "$JSON_OUT" ] && echo " JSON: $JSON_OUT"
[ -f "$PLAIN_OUT_PLAIN" ] && echo " TXT:  $PLAIN_OUT_PLAIN"
[ -f "$PLAIN_OUT" ] && echo " COL:  $PLAIN_OUT"

# exit cleanly (trap will remove workdir)
exit 0
