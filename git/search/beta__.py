#!/usr/bin/env python3
import requests
import argparse
import time
import os,sys,re,csv
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# Fetch commit details (e.g. files, additions, deletions)
# ─────────────────────────────────────────────────────────────────────────────
def fetch_commit_metadata(repo, sha, headers):
    url = f"https://api.github.com/repos/{repo}/commits/{sha}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"[!] Could not fetch commit {sha}: {response.status_code}")
        return None

# ─────────────────────────────────────────────────────────────────────────────
# Retrieve all commits from a specific author, optionally verbose
# ─────────────────────────────────────────────────────────────────────────────
def collect_commits_by_author(repo, author, token, verbose=False, since=None, until=None):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json"
    }

    base_url = f"https://api.github.com/repos/{repo}/commits"
    params = {
        "author": author,
        "per_page": 100,
        "page": 1
    }

    # Convert standard date input to ISO 8601
    if since:
        try:
            since_dt = datetime.strptime(since, "%Y-%m-%d")
            params["since"] = since_dt.isoformat() + "Z"
        except ValueError:
            print("[!] Invalid --since format. Use YYYY-MM-DD.")
            sys.exit(1)

    if until:
        try:
            until_dt = datetime.strptime(until, "%Y-%m-%d")
            params["until"] = until_dt.isoformat() + "Z"
        except ValueError:
            print("[!] Invalid --until format. Use YYYY-MM-DD.")
            sys.exit(1)

    print(f"\n[+] Querying commits for author '{author}' in '{repo}'")
    if since or until:
        print(f"    ⤷ Date range: {since or 'beginning'} to {until or 'now'}\n")

    results = []

    while True:
        response = requests.get(base_url, headers=headers, params=params)
        if response.status_code != 200:
            print(f"[!] API error: {response.status_code} {response.text}")
            sys.exit(1)

        commits = response.json()
        if not commits:
            break

        print(f"--- Fetched page {params['page']} with {len(commits)} commits ---")

        for entry in commits:
            sha_full = entry.get("sha", "")
            sha_short = sha_full[:7]
            commit_date = entry.get("commit", {}).get("author", {}).get("date", "unknown")
            commit_msg = entry.get("commit", {}).get("message", "").split("\n")[0]
            html_url = entry.get("html_url", "")

            data = {
                "date": commit_date,
                "sha": sha_short,
                "message": commit_msg,
                "url": html_url
            }

            if verbose:
                details = fetch_commit_metadata(repo, sha_full, headers)
                if details:
                    files = details.get("files", [])
                    data["files_changed"] = len(files)
                    data["additions"] = sum(f.get("additions", 0) for f in files)
                    data["deletions"] = sum(f.get("deletions", 0) for f in files)
                    data["filenames"] = [f.get("filename") for f in files]

                    print(f"[{commit_date}] {sha_short}: {commit_msg}")
                    print(f"  ⤷ URL: {html_url}")
                    print(f"  ⤷ Files changed: {data['files_changed']}, +{data['additions']}, -{data['deletions']}")
                    for fname in data["filenames"]:
                        print(f"    - {fname}")
                    print()

            else:
                print(f"[{commit_date}] {sha_short}: {commit_msg}")
                print(f"  ⤷ {html_url}\n")

            results.append(data)

        params["page"] += 1
        time.sleep(0.5)  # be kind to GitHub API

    print(f"\n[✓] Total commits retrieved: {len(results)}")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# Output commit data to CSV
# ─────────────────────────────────────────────────────────────────────────────
def export_to_csv(commits, filename):
    with open(filename, "w", newline="") as f:
        fieldnames = ["date", "sha", "message", "url", "files_changed", "additions", "deletions"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for c in commits:
            writer.writerow({
                "date": c["date"],
                "sha": c["sha"],
                "message": c["message"],
                "url": c["url"],
                "files_changed": c.get("files_changed", ""),
                "additions": c.get("additions", ""),
                "deletions": c.get("deletions", "")
            })
    print(f"[✓] CSV file saved to: {filename}")

# ─────────────────────────────────────────────────────────────────────────────
# Output commit data to Markdown
# ─────────────────────────────────────────────────────────────────────────────
def export_to_markdown(commits, filename):
    with open(filename, "w") as f:
        f.write("| Date | SHA | Message | Files Changed | + | - | Link |\n")
        f.write("|------|-----|---------|----------------|---|---|------|\n")
        for c in commits:
            f.write(f"| {c['date']} | `{c['sha']}` | {c['message']} | {c.get('files_changed','')} | {c.get('additions','')} | {c.get('deletions','')} | [link]({c['url']}) |\n")
    print(f"[✓] Markdown file saved to: {filename}")

# ─────────────────────────────────────────────────────────────────────────────
# Main logic and argument handling
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🔍 GitHub commit inspector by author")
    parser.add_argument("--repo", required=True, help="GitHub repository (e.g. org/repo)")
    parser.add_argument("--author", required=True, help="GitHub username (commit author)")
    parser.add_argument("--token", required=True, help="GitHub personal access token (PAT)")
    parser.add_argument("--csv", help="Optional: write results to CSV file")
    parser.add_argument("--md", help="Optional: write results to Markdown file")
    parser.add_argument("--verbose", action="store_true", help="Show detailed file change info")
    parser.add_argument("--since", help="Optional start date (YYYY-MM-DD)")
    parser.add_argument("--until", help="Optional end date (YYYY-MM-DD)")
    args = parser.parse_args()

    commits = collect_commits_by_author(
        repo=args.repo,
        author=args.author,
        token=args.token,
        verbose=args.verbose,
        since=args.since,
        until=args.until
    )

    if args.csv:
        export_to_csv(commits, args.csv)
    if args.md:
        export_to_markdown(commits, args.md)
