#!/usr/bin/env bash
###
# This script ensures that any command that fails will cause the script to exit immediately, (for now).. 
###
## c/o https://github.com/0xKayala/NucleiScanner/blob/main/NucleiScanner.sh
##

set -euo pipefail

# --- CONFIGURATION & CONSTANTS -------------------------------------------------

# ANSI color codes for console output
readonly RED='\033[91m'
readonly GREEN='\033[92m'
readonly YELLOW='\033[93m'
readonly RESET='\033[0m'

# Default settings that can be overridden by command-line flags
OUTPUT_FOLDER="./output"
# Use the standard HOME environment variable, which is more reliable than `eval`.
readonly HOME_DIR="$HOME"
readonly EXCLUDED_EXTENSIONS="png,jpg,gif,jpeg,swf,woff,svg,pdf,css,webp,woff2,eot,ttf,otf,mp4"
VERBOSE=false
KEEP_TEMP=false
RATE_LIMIT=50
# This will be set after the output folder is confirmed.
LOG_FILE=""
# Default template directory, can be overridden with the -t flag.
TEMPLATE_DIR="$HOME/nuclei-templates"


# --- SCRIPT METADATA & HELP ----------------------------------------------------

# Display the initial ASCII art banner.
display_banner() {
    echo -e "${RED}"
cat << "EOF"
                             __     _
           ____  __  _______/ /__  (_)_____________ _____  ____  ___  _____
          / __ \/ / / / ___/ / _ \/ / ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
         / / / / /_/ / /__/ /  __/ (__  ) /__/ /_/ / / / / / / /  __/ /
        /_/ /_/\__,_/\___/_/\___/_/____/\___/\__,_/_/ /_/_/ /_/\___/_/   v2.0.0

                                                Made by Satya Prakash (0xKayala)
EOF
    echo -e "${RESET}"
}

# Display the help menu and exit.
display_help() {
    # Using a heredoc (cat <<EOF) is cleaner for multi-line text.
    cat <<EOF
NucleiScanner: A Powerful Automation Tool for Web Vulnerabilities Scanning

Usage: $0 [options]

Options:
  -h, --help              Display this help menu
  -d, --domain <domain>   Scan a single domain
  -f, --file <filename>   Scan multiple domains/URLs from a file
  -o, --output <folder>   Output folder (default: ./output)
  -t, --templates <path>  Custom Nuclei templates directory (default: $TEMPLATE_DIR)
  -v, --verbose           Enable verbose output (logs to terminal)
  -k, --keep-temp         Keep temporary files after execution
  -r, --rate <limit>      Set rate limit for Nuclei (default: 50)
EOF
    exit 0
}

# --- LOGGING & CLEANUP ---------------------------------------------------------

# Generic logging function.
# @param $1: Log level (e.g., INFO, ERROR)
# @param $2: Message to log
log() {
    local level="$1"
    local message="$2"
    # Log every message to the log file.
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
    # Also print to the console if VERBOSE is true or if it's an ERROR.
    if [[ "$VERBOSE" = true || "$level" = "ERROR" ]]; then
        echo -e "${YELLOW}[$level]${RESET} $message"
    fi
}

# This function is called automatically when the script exits.
cleanup() {
  if [[ "$KEEP_TEMP" = false ]]; then
    log "INFO" "Cleaning up temporary files..."
    # The `2>/dev/null` suppresses errors if the files don't exist.
    rm -f "$OUTPUT_FOLDER"/*_{subdomains,raw,validated}.txt 2>/dev/null
    rm -f "$OUTPUT_FOLDER"/nuclei_*.txt 2>/dev/null
  fi
}
# The trap command ensures the 'cleanup' function runs on script exit.
trap cleanup EXIT

# --- PREREQUISITES -------------------------------------------------------------

# Checks if a tool is installed and installs it if not.
# @param $1: The command name of the tool (e.g., "subfinder")
# @param $2: The command to run for installation
check_prerequisite() {
    local tool="$1"
    local install_command="$2"
    if ! command -v "$tool" &> /dev/null; then
        log "INFO" "Installing $tool..."
        if ! eval "$install_command"; then
            log "ERROR" "Failed to install $tool. Exiting."
            exit 1
        fi
        # Special case for 'uro' which may install to a non-standard PATH.
        if [[ "$tool" = "uro" && -f "$HOME_DIR/.local/bin/uro" ]]; then
            log "INFO" "Adding $HOME_DIR/.local/bin to PATH for uro."
            export PATH="$HOME_DIR/.local/bin:$PATH"
        fi
    fi
}

# Clones a Git repository if the target directory doesn't exist.
# @param $1: The URL of the repository
# @param $2: The target directory to clone into
clone_repo() {
    local repo_url="$1"
    local target_dir="$2"
    if [[ ! -d "$target_dir" ]]; then
        log "INFO" "Cloning $repo_url to $target_dir..."
        # --depth 1 makes the clone faster by only getting the latest commit.
        if ! git clone --depth 1 "$repo_url" "$target_dir"; then
            log "ERROR" "Failed to clone $repo_url. Exiting."
            exit 1
        fi
    fi
}

# --- CORE SCANNING FUNCTIONS ---------------------------------------------------

# Validates and normalizes a target string into a URL.
# @param $1: The input domain or URL
validate_input() {
    local input="$1"
    # If it already has a protocol, it's fine.
    if [[ "$input" =~ ^https?://[a-zA-Z0-9.-]+(/.*)?$ ]]; then
        echo "$input"
    # If it looks like a domain, prepend http://
    elif [[ "$input" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo "http://$input"
    else
        log "ERROR" "Invalid input format: $input"
        return 1
    fi
}

# Uses subfinder to discover subdomains for a given target.
# @param $1: The target domain
# @param $2: The path to the output file
collect_subdomains() {
    local target="$1"
    local output_file="$2"
    # The domain part must be extracted for subfinder.
    local domain_only
    domain_only=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||')

    echo -e "${GREEN}Collecting subdomains for $domain_only...${RESET}"
    subfinder -d "$domain_only" -all -silent -o "$output_file"
}

# Gathers URLs from the main domain (ParamSpider) and subdomains (gauplus).
# @param $1: The target domain
# @param $2: The file containing subdomains
# @param $3: The path to the raw output file
collect_urls() {
    local target="$1"
    local subdomain_file="$2"
    local output_file="$3"
    local domain_only
    domain_only=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||')

    log "INFO" "Starting URL collection for $domain_only..."

    # Use ParamSpider for the root domain. A temp file prevents data loss on error.
    echo -e "${GREEN}Collecting URLs for $domain_only with ParamSpider...${RESET}"
    python3 "$HOME_DIR/ParamSpider/paramspider.py" -d "$domain_only" --exclude "$EXCLUDED_EXTENSIONS" --level high --quiet -o "$output_file.tmp" &&
    cat "$output_file.tmp" >> "$output_file" && rm -f "$output_file.tmp"

    # Use gauplus to get URLs from all discovered subdomains.
    if [[ -s "$subdomain_file" ]]; then
        echo -e "${GREEN}Collecting URLs from subdomains with Gauplus...${RESET}"
        cat "$subdomain_file" | gauplus -b "$EXCLUDED_EXTENSIONS" >> "$output_file"
    fi
}

# Deduplicates and filters URLs using 'uro'.
# @param $1: The raw input file with URLs
# @param $2: The path to the validated output file
deduplicate_urls() {
    local input_file="$1"
    local output_file="$2"
    if [[ ! -s "$input_file" ]]; then
        log "ERROR" "No URLs were collected. Cannot continue."
        exit 1
    fi
    echo -e "${YELLOW}Deduplicating and filtering URLs...${RESET}"
    sort -u "$input_file" | uro > "$output_file"
}

# --- THE NEW, TWO-PART SCANNING FUNCTION ---------------------------------------
# This function now runs two separate scans to get the best results.
# @param $1: The initial, single target domain (for the deep scan)
# @param $2: The file of all discovered URLs (for the broad scan)
run_scans() {
    local initial_target="$1"
    local url_file="$2"

    # --- SCAN 1: Deep Dive on the main domain ---
    echo -e "${GREEN}--- Starting Scan 1: Deep Dive on $initial_target ---${RESET}"
    log "INFO" "Running deep dive scan on the main target..."
    nuclei \
        -target "$initial_target" \
        -t "$TEMPLATE_DIR" \
        -o "$OUTPUT_FOLDER/nuclei_deep_dive_results.txt" \
        -rl "$RATE_LIMIT" \
        -s critical,high,medium,low,info \
        -tags cve,osint,tech,ssl,dns,http,file \
        -v

    # --- SCAN 2: Broad Scan on all discovered URLs ---
    if [[ -s "$url_file" ]]; then
        local url_count
        url_count=$(wc -l < "$url_file")
        echo -e "${GREEN}--- Starting Scan 2: Broad Scan on $url_count Discovered URLs ---${RESET}"
        log "INFO" "Running broad scan on all discovered URLs..."
        # We feed the list of URLs directly to Nuclei, bypassing the problematic httpx.
        nuclei \
            -l "$url_file" \
            -t "$TEMPLATE_DIR" \
            -o "$OUTPUT_FOLDER/nuclei_broad_scan_results.txt" \
            -rl "$RATE_LIMIT" \
            -s critical,high,medium,low \
            -tags cve,tech \
            -as \
            -v
    else
        log "WARN" "No URLs were found in the discovery phase, skipping broad URL scan."
    fi

    # --- Combine Results ---
    log "INFO" "Combining scan results..."
    cat "$OUTPUT_FOLDER"/nuclei_*.txt | sort -u > "$OUTPUT_FOLDER/nuclei_final_results.txt"
}


# --- MAIN WORKFLOW -------------------------------------------------------------

# Main function to orchestrate the script's execution.
main() {
    display_banner

    # --- Argument Parsing ---
    local DOMAIN=""
    local FILENAME=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) display_help ;;
            -d|--domain) DOMAIN="$2"; shift 2 ;;
            -f|--file) FILENAME="$2"; shift 2 ;;
            -o|--output) OUTPUT_FOLDER="$2"; shift 2 ;;
            -t|--templates) TEMPLATE_DIR="$2"; shift 2 ;;
            -v|--verbose) VERBOSE=true; shift ;;
            -k|--keep-temp) KEEP_TEMP=true; shift ;;
            -r|--rate) RATE_LIMIT="$2"; shift 2 ;;
            *) log "ERROR" "Unknown option: $1"; display_help ;;
        esac
    done

    # --- Setup ---
    mkdir -p "$OUTPUT_FOLDER"
    LOG_FILE="$OUTPUT_FOLDER/nucleiscanner.log"
    : > "$LOG_FILE" # Clear log file at the start of a run.

    if [[ -z "$DOMAIN" && -z "$FILENAME" ]]; then
        log "ERROR" "Please provide a domain (-d) or file (-f)."
        display_help
    fi

    # --- Dependency Installation ---
    check_prerequisite "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    check_prerequisite "gauplus" "go install -v github.com/bp0lr/gauplus@latest"
    check_prerequisite "nuclei" "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    check_prerequisite "uro" "pip3 install uro"
    clone_repo "https://github.com/0xKayala/ParamSpider" "$HOME_DIR/ParamSpider"
    clone_repo "https://github.com/projectdiscovery/nuclei-templates.git" "$TEMPLATE_DIR"

    # --- Execution Logic ---
    if [[ -n "$DOMAIN" ]]; then
        # --- Single Domain Workflow ---
        local normalized_target
        normalized_target=$(validate_input "$DOMAIN")
        local base_name
        base_name="${DOMAIN//[^a-zA-Z0-9.-]/_}" # Create a safe filename
        local sub_file="$OUTPUT_FOLDER/${base_name}_subdomains.txt"
        local raw_file="$OUTPUT_FOLDER/${base_name}_raw.txt"
        local validated_file="$OUTPUT_FOLDER/${base_name}_validated.txt"

        collect_subdomains "$normalized_target" "$sub_file"
        collect_urls "$normalized_target" "$sub_file" "$raw_file"
        deduplicate_urls "$raw_file" "$validated_file"
        run_scans "$normalized_target" "$validated_file"

    elif [[ -n "$FILENAME" ]]; then
        # --- Multiple Domain (from file) Workflow ---
        if [[ ! -f "$FILENAME" ]]; then
            log "ERROR" "File $FILENAME not found."
            exit 1
        fi
        local total_lines
        total_lines=$(wc -l < "$FILENAME")
        local count=0
        local all_subdomains_file="$OUTPUT_FOLDER/all_subdomains.txt"
        local all_raw_urls_file="$OUTPUT_FOLDER/all_raw.txt"
        local all_validated_urls_file="$OUTPUT_FOLDER/all_validated.txt"
        : > "$all_subdomains_file" # Clear files before the loop
        : > "$all_raw_urls_file"

        while IFS= read -r line; do
            ((count++))
            echo -e "${YELLOW}[Progress]${RESET} Processing $count/$total_lines: $line"
            local normalized_target
            normalized_target=$(validate_input "$line")
            # Append results to the aggregate files
            collect_subdomains "$normalized_target" "$all_subdomains_file.tmp"
            cat "$all_subdomains_file.tmp" >> "$all_subdomains_file" && rm "$all_subdomains_file.tmp"
            collect_urls "$normalized_target" "$all_subdomains_file" "$all_raw_urls_file"
        done < "$FILENAME"

        deduplicate_urls "$all_raw_urls_file" "$all_validated_urls_file"
        # For file mode, we just run the broad scan on all collected URLs
        echo -e "${GREEN}--- Starting Broad Scan on All Discovered URLs ---${RESET}"
        nuclei -l "$all_validated_urls_file" -o "$OUTPUT_FOLDER/nuclei_final_results.txt" -v
    fi

    log "INFO" "Scanning completed. Results saved in $OUTPUT_FOLDER."
    echo -e "${RED}Nuclei Scanning is completed! Check $OUTPUT_FOLDER/nuclei_final_results.txt for results - Happy Hunting!${RESET}"
}

# This is the entry point of the script. It passes all command-line arguments to the main function.
main "$@"
