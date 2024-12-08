# Red Team Git Enumeration and Exploitation Guide

# These commands can uncover sensitive information, misconfigurations, and potential vulnerabilities.

```bash
# List recent commits in a concise format
git log --oneline

# View detailed commit history with changes (diffs)
git log -p

# List all branches (local and remote)
git branch -a

# List all remote URLs to identify possible access points
git remote -v

# View repository configuration details
git config --list

# Search the entire commit history for sensitive terms like 'password', 'key', or 'secret'
git log -p | grep -i 'password\|key\|secret'

# Search all revisions in the repository for sensitive terms
git rev-list --all | xargs git grep -i 'password\|key\|secret'

# Search specific file types for sensitive terms
git grep -i 'password\|key' -- '*.env' '*.yml' '*.json' '*.config'

# Search for credentials or sensitive terms near "admin"
git log -p | grep -A 5 -B 5 -i 'admin' | grep -i 'password\|key\|secret'

# Search for patterns resembling hardcoded passwords or keys
git log -p | grep -iE 'admin.*(password|passwd|pwd|key).*[=:]'

# View details of a specific commit by its hash
git show <commit-hash>

# View the diff of a file between two commits
git diff <commit-hash-1> <commit-hash-2> -- <file-path>

# Search commit messages for specific keywords (e.g., sensitive changes)
git log --grep='keyword'

# List all commits by a specific author
git log --author='author-name'

# List all files ever committed to the repository
git log --pretty=format: --name-only | sort | uniq

# Show the content of a file from a specific commit
git show <commit-hash>:<file-path>

# Restore a deleted file from a previous commit
git checkout <commit-hash>^ -- <file-path>

# Clone a repository and its full history (bare clone)
git clone --mirror <repository-url>

# Search Git configuration files for potential secrets
cat .git/config | grep -i 'password\|key\|secret'

# Check if sensitive data exists in .gitignore or excluded files
cat .gitignore

# Search for unused branches that might contain sensitive or stale data
git branch -r --merged

# Identify large files in Git history that might contain secrets
git rev-list --objects --all | sort -k 2 | uniq -c | sort -rh | head

# List all tags in the repository
git tag

# View detailed information about a specific tag
git show <tag-name>

# Search for hardcoded IP addresses in the repository
git grep -iE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'

# Search for private keys (e.g., SSH keys)
git grep -i 'PRIVATE KEY'

# Check for hardcoded API keys using common patterns
git grep -iE 'AKIA[0-9A-Z]{16}'

# Extract all email addresses from the repository's history
git log --pretty=format:'%ae' | sort | uniq

# Extract all commit authors
git log --pretty=format:'%an <%ae>' | sort | uniq

# Identify changes to sensitive files over time
git log --stat -- <file-path>

# Identify commits that modified sensitive files
git log --follow -- <file-path>

# Search for sensitive keywords in commit diffs
git log -p | grep -i 'keyword'

# Search for sensitive environment variables (e.g., AWS keys, tokens)
git grep -i 'AWS_SECRET_ACCESS_KEY'
git grep -i 'AWS_ACCESS_KEY_ID'

# List all contributors to the repository
git shortlog -sne

# Analyze Git stash for sensitive or forgotten data
git stash list
git stash show -p stash@{0}

# Recover deleted branches
git reflog

# Recover deleted commits
git fsck --lost-found

# Dump all repository objects into a raw directory for analysis
git cat-file --batch-check --batch-all-objects > git_objects.txt

# Find large blobs in the repository (potential for sensitive data)
git rev-list --objects --all | git cat-file --batch-check | grep blob | sort -k 3 -n -r | head -n 10

# Detect submodules that might contain additional sensitive data
cat .gitmodules

# Enumerate all URLs in submodules
git config --file .gitmodules --get-regexp url
```
##
##


# https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/git


Learn & practice AWS Hacking:HackTricks Training AWS Red Team Expert (ARTE)
Learn & practice GCP Hacking: HackTricks Training GCP Red Team Expert (GRTE)

To dump a .git folder from a URL use https://github.com/arthaud/git-dumper

Use https://www.gitkraken.com/ to inspect the content

If a .git directory is found in a web application you can download all the content using wget -r http://web.com/.git. Then, you can see the changes made by using git diff.

The tools: Git-Money, DVCS-Pillage and GitTools can be used to retrieve the content of a git directory.

The tool https://github.com/cve-search/git-vuln-finder can be used to search for CVEs and security vulnerability messages inside commits messages.

The tool https://github.com/michenriksen/gitrob search for sensitive data in the repositories of an organisations and its employees.

Repo security scanner is a command line-based tool that was written with a single goal: to help you discover GitHub secrets that developers accidentally made by pushing sensitive data. And like the others, it will help you find passwords, private keys, usernames, tokens and more.

TruffleHog searches through GitHub repositories and digs through the commit history and branches, looking for accidentally committed secrets

Here you can find an study about github dorks: https://securitytrails.com/blog/github-dorks

Learn & practice AWS Hacking:HackTricks Training AWS Red Team Expert (ARTE)
Learn & practice GCP Hacking: HackTricks Training GCP Red Team Expert (GRTE)

Previous
NodeJS Express


