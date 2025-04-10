#!/usr/bin/env python3
"""
GitHub Commit Filtering Script - Beta Edition
------------------------------

This script fetches commits from a specified GitHub repository for a given author.
It can output the data to CSV and/or Markdown files, and you can also request
detailed commit information including file changes and diff patches.

The script supports a configurable delay between processing each commit's details,
which can help you avoid hitting API rate limits.

Usage Examples:
 1. Fetch recent commits by a user:
    ./github_commits.py --repo org/repo --author username --token YOUR_TOKEN

 2. Fetch commits within a specific date range and output to CSV:
    ./github_commits.py --repo org/repo --author username --token YOUR_TOKEN --since 2023-01-01 --until 2023-08-31 --csv commits.csv

 3. Fetch commits with verbose details and include diff patches:
    ./github_commits.py --repo org/repo --author username --token YOUR_TOKEN --verbose --dig

 4. Fetch commits and introduce a 1-second delay between processing each commit:
    ./github_commits.py --repo org/repo --author username --token YOUR_TOKEN --delay 1

For full help, run:
    ./github_commits.py --help
"""

from __future__ import annotations
import requests
import argparse
import time
import sys
import csv
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class GitHubClient:
    """
    A client to interact with the GitHub API to fetch commit data.
    """
    BASE_URL: str = "https://api.github.com"

    def __init__(self, repo: str, author: str, token: str, delay: float = 0.0) -> None:
        """
        Initialize the GitHub client.

        Args:
            repo: Repository name in "org/repo" format.
            author: GitHub username of the commit author.
            token: GitHub Personal Access Token (PAT) with repo access.
            delay: Delay (in seconds) to wait between processing each commit.
        """
        self.repo = repo
        self.author = author
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json"
        })

    def fetch_commit_details(self, sha: str) -> Optional[Dict[str, Any]]:
        """
        Fetch detailed information for a given commit SHA.

        Args:
            sha: The commit SHA.

        Returns:
            A dictionary with commit details or None on failure.
        """
        url = f"{self.BASE_URL}/repos/{self.repo}/commits/{sha}"
        response = self.session.get(url)
        if response.ok:
            return response.json()
        else:
            logger.error(f"Failed to fetch details for {sha}: {response.status_code}")
            return None

    def fetch_commits(
        self,
        since: Optional[str] = None,
        until: Optional[str] = None,
        verbose: bool = False,
        dig: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Fetch commits matching the provided filters.
        
        Args:
            since: Start date in YYYY-MM-DD (optional).
            until: End date in YYYY-MM-DD (optional).
            verbose: If True, fetch and display detailed commit information.
            dig: If True (with verbose), display diff patch details per file.

        Returns:
            A list of commit summaries.
        """
        commits: List[Dict[str, Any]] = []
        params = {
            "author": self.author,
            "per_page": 100,
            "page": 1
        }
        if since:
            try:
                dt = datetime.strptime(since, "%Y-%m-%d")
                params["since"] = dt.isoformat() + "Z"
            except ValueError:
                logger.error("Invalid '--since' date format. Use YYYY-MM-DD.")
                sys.exit(1)
        if until:
            try:
                dt = datetime.strptime(until, "%Y-%m-%d")
                params["until"] = dt.isoformat() + "Z"
            except ValueError:
                logger.error("Invalid '--until' date format. Use YYYY-MM-DD.")
                sys.exit(1)

        logger.info(f"Fetching commits by '{self.author}' from repo '{self.repo}'")
        if since or until:
            logger.info(f"Time range: {since or 'beginning'} to {until or 'now'}")

        base_url = f"{self.BASE_URL}/repos/{self.repo}/commits"
        while True:
            response = self.session.get(base_url, params=params)
            if not response.ok:
                logger.error(f"Failed: {response.status_code} {response.text}")
                sys.exit(1)
            page_commits = response.json()
            if not page_commits:
                break

            logger.info(f"--- Page {params['page']} ({len(page_commits)} commits) ---")
            for commit in page_commits:
                sha = commit.get("sha", "")
                short_sha = sha[:7]
                date = commit.get("commit", {}).get("author", {}).get("date", "unknown")
                message = commit.get("commit", {}).get("message", "").split("\n")[0]
                html_url = commit.get("html_url", "")

                summary = {
                    "date": date,
                    "sha": short_sha,
                    "message": message,
                    "url": html_url
                }
                if verbose:
                    details = self.fetch_commit_details(sha)
                    if details:
                        files = details.get("files", [])
                        summary.update({
                            "files_changed": len(files),
                            "additions": sum(f.get("additions", 0) for f in files),
                            "deletions": sum(f.get("deletions", 0) for f in files),
                            "filenames": [f.get("filename") for f in files]
                        })
                        logger.info(f"[{date}] {short_sha}: {message}")
                        logger.info(f"  URL: {html_url}")
                        logger.info(f"  Files changed: {summary['files_changed']}, +{summary['additions']}, -{summary['deletions']}")
                        for f in files:
                            logger.info(f"    - {f.get('filename')}")
                        if dig:
                            logger.info("  [Diff Details]")
                            for f in files:
                                patch = f.get("patch")
                                if patch:
                                    logger.info(f"---- {f.get('filename')} ----")
                                    logger.info(patch)
                                    logger.info("--------------------")
                    else:
                        logger.info(f"[{date}] {short_sha}: {message}")
                        logger.info(f"  URL: {html_url}")
                else:
                    logger.info(f"[{date}] {short_sha}: {message}")
                    logger.info(f"  {html_url}")

                commits.append(summary)
                # Delay between processing each individual commit (user-configurable).
                if self.delay > 0:
                    time.sleep(self.delay)
            params["page"] += 1
            # Short delay after each page to avoid rate limiting.
            time.sleep(0.5)
        logger.info(f"Total commits retrieved: {len(commits)}")
        return commits


def output_csv(commits: List[Dict[str, Any]], filename: str) -> None:
    """
    Output commits data to a CSV file.

    Args:
        commits: A list of commit summaries.
        filename: The filename for the CSV output.
    """
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
    logger.info(f"CSV written to {filename}")


def output_markdown(commits: List[Dict[str, Any]], filename: str) -> None:
    """
    Output commits data to a Markdown file.

    Args:
        commits: A list of commit summaries.
        filename: The filename for the Markdown output.
    """
    with open(filename, "w") as f:
        f.write("| Date | SHA | Message | Files Changed | + | - | Link |\n")
        f.write("|------|-----|---------|----------------|---|---|------|\n")
        for c in commits:
            f.write(
                f"| {c['date']} | `{c['sha']}` | {c['message']} | {c.get('files_changed', '')} | "
                f"{c.get('additions', '')} | {c.get('deletions', '')} | [link]({c['url']}) |\n"
            )
    logger.info(f"Markdown written to {filename}")


def parse_arguments() -> argparse.Namespace:
    """
    Parse and return the command-line arguments.

    The epilog provides usage examples to guide you.
    """
    parser = argparse.ArgumentParser(
        description="Fetch and print GitHub commits by author.",
        epilog="""Examples:
  1. Basic usage:
     ./github_commits.py --repo org/repo --author username --token YOUR_TOKEN

  2. With CSV output and date range:
     ./github_commits.py --repo org/repo --author username --token YOUR_TOKEN --since 2023-01-01 --until 2023-08-31 --csv commits.csv

  3. Verbose details with diff patches:
     ./github_commits.py --repo org/repo --author username --token YOUR_TOKEN --verbose --dig

  4. With a delay between commit requests:
     ./github_commits.py --repo org/repo --author username --token YOUR_TOKEN --delay 1
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo", required=True, help="GitHub repo (e.g. org/repo)")
    parser.add_argument("--author", required=True, help="GitHub username (for author field)")
    parser.add_argument("--token", required=True, help="GitHub PAT with repo access")
    parser.add_argument("--csv", help="Optional: output CSV file")
    parser.add_argument("--md", help="Optional: output Markdown file")
    parser.add_argument("--verbose", action="store_true", help="Include full commit details (files changed, stats)")
    parser.add_argument("--dig", action="store_true", help="Show commit diff details (patches) for each file changed")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay (in seconds) between processing each commit's details (default: 0)")
    parser.add_argument("--since", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--until", help="End date (YYYY-MM-DD)")
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    client = GitHubClient(args.repo, args.author, args.token, delay=args.delay)
    commits = client.fetch_commits(since=args.since, until=args.until, verbose=args.verbose, dig=args.dig)
    if args.csv:
        output_csv(commits, args.csv)
    if args.md:
        output_markdown(commits, args.md)


if __name__ == "__main__":
    main()

