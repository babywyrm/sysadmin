#!/usr/bin/env bash
set -euo pipefail

##
## the OG
## https://github.com/0xKayala/NucleiScanner/blob/main/NucleiScanner.sh
##

# ────────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────────────────────────

# ANSI color codes
RED='\033[0;31m'    # errors
YELLOW='\033[0;33m' # warnings/info
GREEN='\033[0;32m'  # success
RESET='\033[0m'

# Default settings (override via flags)
OUTPUT_DIR="./output"
TEMPLATE_DIR="$HOME/nuclei-templates"
RATE_LIMIT=50
VERBOSE=false
KEEP_TEMP=false

# Tools to ensure are installed (indexed arrays for Bash compatibility)
TOOLS=(subfinder gauplus nuclei httpx uro)
INSTALL_CMDS=(
  "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "go install -v github.com/bp0lr/gauplus@latest"
  "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "pip3 install uro"
)

# File extensions to skip when collecting URLs
EXCLUDE_EXT=(png jpg gif jpeg swf woff svg pdf css webp woff2 eot ttf otf mp4)

# ────────────────────────────────────────────────────────────────────────────────
# LOGGING & CLEANUP
# ────────────────────────────────────────────────────────────────────────────────

LOG_FILE=""

log_info()  { echo -e "[${YELLOW}INFO${RESET}] $1"  | tee -a "$LOG_FILE"; }
log_warn()  { echo -e "[${YELLOW}WARN${RESET}] $1"  | tee -a "$LOG_FILE"; }
log_error() { echo -e "[${RED}ERROR${RESET}] $1" | tee -a "$LOG_FILE"; exit 1; }

cleanup() {
  if ! $KEEP_TEMP; then
    rm -f "$OUTPUT_DIR"/*_{subdomains,raw,validated}.txt 2>/dev/null || true
    log_info "Temporary files removed"
  fi
}
trap cleanup EXIT

# ────────────────────────────────────────────────────────────────────────────────
# PREREQUISITES & REPOSITORY CLONING
# ────────────────────────────────────────────────────────────────────────────────

ensure_tools_installed() {
  for i in "${!TOOLS[@]}"; do
    tool=${TOOLS[i]}
    cmd=${INSTALL_CMDS[i]}
    if ! command -v "$tool" &>/dev/null; then
      log_info "Installing $tool"
      eval "$cmd" || log_error "Failed to install $tool"
      # ensure uro lands in ~/.local/bin on macOS/Linux
      [[ $tool == uro && -d "$HOME/.local/bin" ]] && export PATH="$HOME/.local/bin:$PATH"
    fi
  done
}

clone_if_missing() {
  local repo_url=$1 target_dir=$2
  if [[ ! -d $target_dir ]]; then
    log_info "Cloning $repo_url → $target_dir"
    git clone "$repo_url" "$target_dir" || log_error "Could not clone $repo_url"
  fi
}

ensure_repos_present() {
  clone_if_missing "https://github.com/0xKayala/ParamSpider"   "$HOME/ParamSpider"
  clone_if_missing "https://github.com/projectdiscovery/nuclei-templates.git" "$TEMPLATE_DIR"
}

# ────────────────────────────────────────────────────────────────────────────────
# URL NORMALIZATION & VALIDATION
# ────────────────────────────────────────────────────────────────────────────────

normalize_target() {
  local raw=$1
  if [[ $raw =~ ^https?:// ]]; then
    echo "$raw"
  elif [[ $raw =~ ^[a-zA-Z0-9.-]+$ ]]; then
    echo "http://$raw"
  else
    log_error "Invalid target: $raw"
  fi
}

# ────────────────────────────────────────────────────────────────────────────────
# SUBDOMAIN & URL COLLECTION
# ────────────────────────────────────────────────────────────────────────────────

collect_subdomains() {
  local target=$1 output=$2
  log_info "Collecting subdomains for $target"
  subfinder -d "$target" -silent -all -o "$output"
}

collect_urls() {
  local target=$1 sub_file=$2 raw_file=$3
  log_info "Collecting URLs with ParamSpider for $target"
  python3 "$HOME/ParamSpider/paramspider.py" \
    -d "$target" --exclude "${EXCLUDE_EXT[*]}" --level high --quiet -o "$raw_file.tmp"
  cat "$raw_file.tmp" >> "$raw_file" && rm -f "$raw_file.tmp"

  if [[ -s $sub_file ]]; then
    log_info "Appending URLs from subdomains with gauplus"
    cat "$sub_file" | gauplus -b "${EXCLUDE_EXT[*]}" >> "$raw_file"
  fi
}

dedupe_urls() {
  local input=$1 output=$2
  if [[ ! -s $input ]]; then
    log_error "No URLs found in $input"
  fi
  log_info "Deduplicating URLs"
  sort -u "$input" | uro > "$output"
}

# ────────────────────────────────────────────────────────────────────────────────
# RUN NUCLEI
# ────────────────────────────────────────────────────────────────────────────────

run_nuclei() {
  local url_list=$1
  log_info "Running Nuclei scan (rate=${RATE_LIMIT})"
  httpx -silent \
        -mc 200,204,301,302,401,403,405,500,502,503,504 \
        -l "$url_list" \
    | nuclei -t "$TEMPLATE_DIR" -es info -rl "$RATE_LIMIT" \
             -o "$OUTPUT_DIR/nuclei_results.txt"
}

# ────────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING & MAIN WORKFLOW
# ────────────────────────────────────────────────────────────────────────────────

show_usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -d DOMAIN       Scan a single domain
  -f FILE         Scan domains/URLs from a file
  -o OUTPUT_DIR   Output directory (default: $OUTPUT_DIR)
  -t TEMPLATE_DIR Nuclei templates directory (default: $TEMPLATE_DIR)
  -r RATE_LIMIT   Nuclei rate limit (default: $RATE_LIMIT)
  -v              Enable verbose logging
  -k              Keep temporary files
  -h              Show this help
EOF
  exit 0
}

main() {
  # Parse flags
  while getopts "d:f:o:t:r:vkh" opt; do
    case $opt in
      d) DOMAIN=$OPTARG ;;
      f) FILENAME=$OPTARG ;;
      o) OUTPUT_DIR=$OPTARG ;;
      t) TEMPLATE_DIR=$OPTARG ;;
      r) RATE_LIMIT=$OPTARG ;;
      v) VERBOSE=true ;;
      k) KEEP_TEMP=true ;;
      h) show_usage ;;
      *) show_usage ;;
    esac
  done

  # Prepare environment
  mkdir -p "$OUTPUT_DIR"
  LOG_FILE="$OUTPUT_DIR/nucleiscanner.log"
  : > "$LOG_FILE"

  ensure_tools_installed
  ensure_repos_present

  if [[ -n ${DOMAIN-} ]]; then
    # Single-domain flow
    DOMAIN=$(normalize_target "$DOMAIN")
    base=$(echo "$DOMAIN" | sed 's/[^a-zA-Z0-9]/_/g')
    sub_file="$OUTPUT_DIR/${base}_subdomains.txt"
    raw_file="$OUTPUT_DIR/${base}_raw.txt"
    valid_file="$OUTPUT_DIR/${base}_validated.txt"

    collect_subdomains "$DOMAIN" "$sub_file"
    collect_urls      "$DOMAIN" "$sub_file" "$raw_file"
    dedupe_urls       "$raw_file" "$valid_file"
    run_nuclei        "$valid_file"

  elif [[ -n ${FILENAME-} ]]; then
    # File-of-targets flow
    [[ -f $FILENAME ]] || log_error "File not found: $FILENAME"
    total=$(wc -l < "$FILENAME")
    sub_file="$OUTPUT_DIR/all_subdomains.txt"
    raw_file="$OUTPUT_DIR/all_raw.txt"
    valid_file="$OUTPUT_DIR/all_validated.txt"
    : > "$sub_file" : > "$raw_file"

    count=0
    while IFS= read -r line; do
      ((count++))
      log_info "[$count/$total] Processing $line"
      target=$(normalize_target "$line")
      collect_subdomains "$target" "$sub_file.tmp"
      cat "$sub_file.tmp" >> "$sub_file" && rm -f "$sub_file.tmp"
      collect_urls      "$target" "$sub_file" "$raw_file"
    done < "$FILENAME"

    dedupe_urls "$raw_file" "$valid_file"
    run_nuclei        "$valid_file"

  else
    show_usage
  fi

  log_info "Scan complete. Results in $OUTPUT_DIR/nuclei_results.txt"
}

main "$@"

