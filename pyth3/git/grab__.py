#!/usr/bin/env python3
import argparse
import os,sys,re
import requests
from typing import Optional, Dict, Any, List

##
##

class GithubBot:
    def __init__(self, token: Optional[str] = None):
        self.base_url = "https://api.github.com/"
        self.session = requests.Session()
        if token:
            # Use a personal access token to help with rate limits and private data.
            self.session.headers.update({"Authorization": f"token {token}"})
    
    def get_user_details(self, username: str) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}users/{username}"
        response = self.session.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[Error] Unable to get user details (HTTP {response.status_code}): {response.text}")
            return None

    def get_repo_details(self, owner: str, repo: str) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}repos/{owner}/{repo}"
        response = self.session.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[Error] Unable to get repo details (HTTP {response.status_code}): {response.text}")
            return None

    def list_user_repos(self, username: str) -> Optional[List[Dict[str, Any]]]:
        """
        Retrieve all repositories for a given user using pagination.
        GitHub paginates responses so that only a subset of results is returned at a time.
        """
        repos = []
        url = f"{self.base_url}users/{username}/repos"
        params = {'per_page': 100, 'page': 1}  # Request up to 100 repos per page.
        
        while True:
            response = self.session.get(url, params=params)
            if response.status_code != 200:
                print(f"[Error] Unable to list repositories (HTTP {response.status_code}): {response.text}")
                return None
            page_repos = response.json()
            if not page_repos:  # No more repos on this page.
                break
            repos.extend(page_repos)
            # If fewer repos than requested are returned, it's the last page.
            if len(page_repos) < params['per_page']:
                break
            params['page'] += 1  # Move to the next page.
        return repos

    def list_repo_issues(self, owner: str, repo: str) -> Optional[List[Dict[str, Any]]]:
        """
        Retrieve open issues for a given repository.
        This example doesn't handle pagination. If you expect many issues,
        consider implementing a similar pagination loop.
        """
        url = f"{self.base_url}repos/{owner}/{repo}/issues"
        response = self.session.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[Error] Unable to list issues (HTTP {response.status_code}): {response.text}")
            return None

def print_user_details(data: Dict[str, Any]) -> None:
    print(f"Username:      {data.get('login')}")
    print(f"Name:          {data.get('name')}")
    print(f"Bio:           {data.get('bio')}")
    print(f"Location:      {data.get('location')}")
    print(f"Public Repos:  {data.get('public_repos')}")
    print(f"Followers:     {data.get('followers')}")
    print(f"Following:     {data.get('following')}")

def print_repo_details(data: Dict[str, Any]) -> None:
    print(f"Repository:    {data.get('full_name')}")
    print(f"Description:   {data.get('description')}")
    print(f"URL:           {data.get('html_url')}")
    print(f"Stars:         {data.get('stargazers_count')}")
    print(f"Forks:         {data.get('forks_count')}")
    print(f"Language:      {data.get('language')}")
    print(f"Open Issues:   {data.get('open_issues_count')}")

def print_repo_list(repos: List[Dict[str, Any]]) -> None:
    if not repos:
        print("No repositories found.")
        return
    for repo in repos:
        desc = repo.get('description') or 'No description'
        print(f"- {repo.get('full_name')}: {desc} (Stars: {repo.get('stargazers_count')})")

def print_issue_list(issues: List[Dict[str, Any]]) -> None:
    if not issues:
        print("No issues found.")
        return
    for issue in issues:
        print(f"- #{issue.get('number')}: {issue.get('title')} (State: {issue.get('state')})")

def main():
    parser = argparse.ArgumentParser(
        description="GitHub CLI Tool: Get details about users, repositories, and issues."
    )
    # Optional token for authenticated requests (or set the GITHUB_TOKEN environment variable)
    parser.add_argument(
        "--token",
        help="GitHub Personal Access Token (or set GITHUB_TOKEN env variable)",
        default=os.environ.get("GITHUB_TOKEN")
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Sub-commands")

    # Subcommand: user
    user_parser = subparsers.add_parser("user", help="Get details about a GitHub user")
    user_parser.add_argument("username", help="GitHub username")

    # Subcommand: repo
    repo_parser = subparsers.add_parser("repo", help="Get details about a GitHub repository")
    repo_parser.add_argument("owner", help="Owner of the repository")
    repo_parser.add_argument("repo", help="Repository name")

    # Subcommand: repos
    repos_parser = subparsers.add_parser("repos", help="List repositories of a GitHub user")
    repos_parser.add_argument("username", help="GitHub username")

    # Subcommand: issues
    issues_parser = subparsers.add_parser("issues", help="List open issues in a GitHub repository")
    issues_parser.add_argument("owner", help="Owner of the repository")
    issues_parser.add_argument("repo", help="Repository name")

    args = parser.parse_args()
    bot = GithubBot(token=args.token)

    if args.command == "user":
        data = bot.get_user_details(args.username)
        if data:
            print_user_details(data)
    elif args.command == "repo":
        data = bot.get_repo_details(args.owner, args.repo)
        if data:
            print_repo_details(data)
    elif args.command == "repos":
        repos = bot.list_user_repos(args.username)
        if repos is not None:
            print_repo_list(repos)
    elif args.command == "issues":
        issues = bot.list_repo_issues(args.owner, args.repo)
        if issues is not None:
            print_issue_list(issues)

if __name__ == "__main__":
    main()
###
