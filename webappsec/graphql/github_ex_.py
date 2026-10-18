#!/usr/bin/env python3
"""
Enhanced GitHub GraphQL API Client
o/g
https://gist.github.com/kwk/c89b6a3e5eb40487fed78f226e982fcc
"""

import argparse
import datetime
import os
import time
import json
from string import Template
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import requests
from pprint import pprint
import logging
from http.client import HTTPConnection


# Custom Exceptions
class GitHubAPIError(Exception):
    """Base exception for GitHub API errors"""
    pass


class AuthenticationError(GitHubAPIError):
    """Authentication failed"""
    pass


class RateLimitError(GitHubAPIError):
    """Rate limit exceeded"""
    def __init__(self, message: str, reset_at: Optional[int] = None):
        super().__init__(message)
        self.reset_at = reset_at


class NotFoundError(GitHubAPIError):
    """Resource not found"""
    pass


@dataclass
class RateLimit:
    """Rate limit information"""
    limit: int
    remaining: int
    reset_at: int
    used: int
    
    @property
    def reset_datetime(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(self.reset_at)


@dataclass
class IssueComment:
    """Enhanced IssueComment with more fields and utility methods"""
    id: str
    body: str
    url: str
    author: str
    issue_id: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    html_url: Optional[str] = None
    issue_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class Issue:
    """Represents a GitHub issue"""
    id: str
    number: int
    title: str
    body: str
    state: str
    url: str
    html_url: str
    author: str
    created_at: str
    updated_at: str
    closed: bool
    labels: List[str]


@dataclass
class PullRequest:
    """Represents a GitHub pull request"""
    id: str
    number: int
    title: str
    body: str
    state: str
    url: str
    html_url: str
    author: str
    created_at: str
    updated_at: str
    merged: bool
    draft: bool
    mergeable: Optional[str]


class GitHubGraphQL:
    """
    Enhanced GitHub GraphQL API client with better error handling,
    rate limiting, and additional functionality.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        verbose: bool = False,
        retry_attempts: int = 3,
        retry_delay: float = 1.0
    ) -> None:
        """
        Initialize the GitHub GraphQL client.
        
        :param token: GitHub access token (if None, tries GITHUB_TOKEN env var)
        :param verbose: Enable debug logging
        :param retry_attempts: Number of retry attempts for failed requests
        :param retry_delay: Delay between retries in seconds
        """
        self.__token = token or os.getenv('GITHUB_TOKEN')
        if not self.__token:
            raise AuthenticationError("No GitHub token provided")
            
        self.__verbose = verbose
        self.__retry_attempts = retry_attempts
        self.__retry_delay = retry_delay
        self.__session = requests.Session()
        self.__rate_limit: Optional[RateLimit] = None
        
        # Setup logging
        self.__setup_logging()

    def __setup_logging(self) -> None:
        """Configure logging based on verbose setting"""
        if self.__verbose:
            HTTPConnection.debuglevel = 1
            logging.basicConfig(level=logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True
        else:
            logging.basicConfig(level=logging.INFO)

    def __check_rate_limit(self) -> None:
        """Check if we're approaching rate limits"""
        if self.__rate_limit and self.__rate_limit.remaining < 100:
            logging.warning(
                f"Rate limit low: {self.__rate_limit.remaining} requests remaining"
            )
            if self.__rate_limit.remaining < 10:
                sleep_time = self.__rate_limit.reset_at - time.time()
                if sleep_time > 0:
                    logging.warning(f"Sleeping {sleep_time:.1f}s due to rate limit")
                    time.sleep(sleep_time)

    def __update_rate_limit(self, headers: Dict[str, str]) -> None:
        """Update rate limit info from response headers"""
        if 'X-RateLimit-Limit' in headers:
            self.__rate_limit = RateLimit(
                limit=int(headers['X-RateLimit-Limit']),
                remaining=int(headers['X-RateLimit-Remaining']),
                reset_at=int(headers['X-RateLimit-Reset']),
                used=int(headers['X-RateLimit-Used'])
            )

    def __run_query(self, query: str, variables: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute GraphQL query with enhanced error handling and retries.
        
        :param query: GraphQL query string
        :param variables: Query variables
        :return: Response data
        """
        if variables is None:
            variables = {}
            
        headers = {
            'Authorization': f'Bearer {self.__token}',
            'X-Github-Next-Global-ID': '1',
            'Accept': 'application/vnd.github.v4+json'
        }
        
        payload = {
            'query': query,
            'variables': variables
        }
        
        last_exception = None
        
        for attempt in range(self.__retry_attempts):
            try:
                self.__check_rate_limit()
                
                response = self.__session.post(
                    'https://api.github.com/graphql',
                    json=payload,
                    headers=headers,
                    timeout=30
                )
                
                self.__update_rate_limit(response.headers)
                
                if response.status_code == 401:
                    raise AuthenticationError("Invalid or expired token")
                elif response.status_code == 403:
                    if 'rate limit' in response.text.lower():
                        raise RateLimitError(
                            "Rate limit exceeded",
                            self.__rate_limit.reset_at if self.__rate_limit else None
                        )
                    raise GitHubAPIError(f"Forbidden: {response.text}")
                elif response.status_code != 200:
                    raise GitHubAPIError(
                        f"Query failed with status {response.status_code}: {response.text}"
                    )
                
                result = response.json()
                
                if 'errors' in result:
                    error_messages = [error['message'] for error in result['errors']]
                    raise GitHubAPIError(f"GraphQL errors: {'; '.join(error_messages)}")
                
                return result
                
            except requests.exceptions.RequestException as e:
                last_exception = GitHubAPIError(f"Request failed: {str(e)}")
                if attempt < self.__retry_attempts - 1:
                    time.sleep(self.__retry_delay * (2 ** attempt))  # Exponential backoff
                    continue
                    
        raise last_exception or GitHubAPIError("Unknown error occurred")

    @property
    def rate_limit(self) -> Optional[RateLimit]:
        """Get current rate limit information"""
        return self.__rate_limit

    def get_pr_id(self, owner: str, repo: str, pr_num: int) -> str:
        """Get pull request global ID"""
        query = """
        query($owner: String!, $reponame: String!, $pr_id: Int!) {
            repository(owner: $owner, name: $reponame) {
                pullRequest(number: $pr_id) {
                    id
                }
            }
        }
        """
        variables = {
            'owner': owner,
            'reponame': repo,
            'pr_id': pr_num
        }
        
        result = self.__run_query(query, variables)
        pr_data = result['data']['repository']['pullRequest']
        
        if not pr_data:
            raise NotFoundError(f"Pull request #{pr_num} not found in {owner}/{repo}")
            
        return pr_data['id']

    def get_issue_id(self, owner: str, repo: str, issue_num: int) -> str:
        """Get issue global ID"""
        query = """
        query($owner: String!, $reponame: String!, $issue_id: Int!) {
            repository(owner: $owner, name: $reponame) {
                issue(number: $issue_id) {
                    id
                }
            }
        }
        """
        variables = {
            'owner': owner,
            'reponame': repo,
            'issue_id': issue_num
        }
        
        result = self.__run_query(query, variables)
        issue_data = result['data']['repository']['issue']
        
        if not issue_data:
            raise NotFoundError(f"Issue #{issue_num} not found in {owner}/{repo}")
            
        return issue_data['id']

    def get_issue(self, owner: str, repo: str, issue_num: int) -> Issue:
        """Get detailed issue information"""
        query = """
        query($owner: String!, $reponame: String!, $issue_id: Int!) {
            repository(owner: $owner, name: $reponame) {
                issue(number: $issue_id) {
                    id
                    number
                    title
                    body
                    state
                    url
                    resourcePath
                    author {
                        login
                    }
                    createdAt
                    updatedAt
                    closed
                    labels(first: 20) {
                        nodes {
                            name
                        }
                    }
                }
            }
        }
        """
        variables = {
            'owner': owner,
            'reponame': repo,
            'issue_id': issue_num
        }
        
        result = self.__run_query(query, variables)
        issue_data = result['data']['repository']['issue']
        
        if not issue_data:
            raise NotFoundError(f"Issue #{issue_num} not found in {owner}/{repo}")
        
        return Issue(
            id=issue_data['id'],
            number=issue_data['number'],
            title=issue_data['title'],
            body=issue_data['body'] or '',
            state=issue_data['state'],
            url=issue_data['url'],
            html_url=f"https://github.com{issue_data['resourcePath']}",
            author=issue_data['author']['login'] if issue_data['author'] else 'unknown',
            created_at=issue_data['createdAt'],
            updated_at=issue_data['updatedAt'],
            closed=issue_data['closed'],
            labels=[label['name'] for label in issue_data['labels']['nodes']]
        )

    def get_pull_request(self, owner: str, repo: str, pr_num: int) -> PullRequest:
        """Get detailed pull request information"""
        query = """
        query($owner: String!, $reponame: String!, $pr_id: Int!) {
            repository(owner: $owner, name: $reponame) {
                pullRequest(number: $pr_id) {
                    id
                    number
                    title
                    body
                    state
                    url
                    resourcePath
                    author {
                        login
                    }
                    createdAt
                    updatedAt
                    merged
                    isDraft
                    mergeable
                }
            }
        }
        """
        variables = {
            'owner': owner,
            'reponame': repo,
            'pr_id': pr_num
        }
        
        result = self.__run_query(query, variables)
        pr_data = result['data']['repository']['pullRequest']
        
        if not pr_data:
            raise NotFoundError(f"Pull request #{pr_num} not found in {owner}/{repo}")
        
        return PullRequest(
            id=pr_data['id'],
            number=pr_data['number'],
            title=pr_data['title'],
            body=pr_data['body'] or '',
            state=pr_data['state'],
            url=pr_data['url'],
            html_url=f"https://github.com{pr_data['resourcePath']}",
            author=pr_data['author']['login'] if pr_data['author'] else 'unknown',
            created_at=pr_data['createdAt'],
            updated_at=pr_data['updatedAt'],
            merged=pr_data['merged'],
            draft=pr_data['isDraft'],
            mergeable=pr_data['mergeable']
        )

    def add_issue_comment(self, issue_node_id: str, comment_body: str) -> IssueComment:
        """Add comment to issue or pull request"""
        query = """
        mutation($issue_node_id: String!, $comment_body: String!) {
            addComment(input: {
                subjectId: $issue_node_id,
                body: $comment_body
            }) {
                commentEdge {
                    node {
                        id
                        body
                        url
                        resourcePath
                        author {
                            login
                        }
                        createdAt
                        updatedAt
                        issue {
                            id
                            url
                        }
                    }
                }
            }
        }
        """
        variables = {
            'issue_node_id': issue_node_id,
            'comment_body': comment_body
        }
        
        result = self.__run_query(query, variables)
        comment_data = result['data']['addComment']['commentEdge']['node']
        
        return IssueComment(
            id=comment_data['id'],
            body=comment_data['body'],
            url=comment_data['url'],
            author=comment_data['author']['login'] if comment_data['author'] else 'unknown',
            issue_id=comment_data['issue']['id'],
            created_at=comment_data['createdAt'],
            updated_at=comment_data['updatedAt'],
            html_url=f"https://github.com{comment_data['resourcePath']}",
            issue_url=comment_data['issue']['url']
        )

    def update_comment(self, comment_id: str, new_body: str) -> IssueComment:
        """Update an existing comment"""
        query = """
        mutation($comment_id: String!, $new_body: String!) {
            updateIssueComment(input: {
                id: $comment_id,
                body: $new_body
            }) {
                issueComment {
                    id
                    body
                    url
                    resourcePath
                    author {
                        login
                    }
                    createdAt
                    updatedAt
                    issue {
                        id
                        url
                    }
                }
            }
        }
        """
        variables = {
            'comment_id': comment_id,
            'new_body': new_body
        }
        
        result = self.__run_query(query, variables)
        comment_data = result['data']['updateIssueComment']['issueComment']
        
        return IssueComment(
            id=comment_data['id'],
            body=comment_data['body'],
            url=comment_data['url'],
            author=comment_data['author']['login'] if comment_data['author'] else 'unknown',
            issue_id=comment_data['issue']['id'],
            created_at=comment_data['createdAt'],
            updated_at=comment_data['updatedAt'],
            html_url=f"https://github.com{comment_data['resourcePath']}",
            issue_url=comment_data['issue']['url']
        )

    def delete_comment(self, comment_id: str) -> bool:
        """Delete a comment"""
        query = """
        mutation($comment_id: String!) {
            deleteIssueComment(input: {
                id: $comment_id
            }) {
                clientMutationId
            }
        }
        """
        variables = {'comment_id': comment_id}
        
        try:
            self.__run_query(query, variables)
            return True
        except GitHubAPIError:
            return False

    def get_comment(self, comment_id: str) -> IssueComment:
        """Get comment details by ID"""
        query = """
        query($comment_id: String!) {
            node(id: $comment_id) {
                ... on IssueComment {
                    id
                    body
                    url
                    resourcePath
                    author {
                        login
                    }
                    createdAt
                    updatedAt
                    issue {
                        id
                        url
                    }
                }
            }
        }
        """
        variables = {'comment_id': comment_id}
        
        result = self.__run_query(query, variables)
        comment_data = result['data']['node']
        
        if not comment_data:
            raise NotFoundError(f"Comment {comment_id} not found")
        
        return IssueComment(
            id=comment_data['id'],
            body=comment_data['body'],
            url=comment_data['url'],
            author=comment_data['author']['login'] if comment_data['author'] else 'unknown',
            issue_id=comment_data['issue']['id'],
            created_at=comment_data['createdAt'],
            updated_at=comment_data['updatedAt'],
            html_url=f"https://github.com{comment_data['resourcePath']}",
            issue_url=comment_data['issue']['url']
        )

    def get_issue_comments(
        self,
        owner: str,
        repo: str,
        issue_num: int,
        first: int = 20
    ) -> List[IssueComment]:
        """Get all comments for an issue"""
        query = """
        query($owner: String!, $reponame: String!, $issue_id: Int!, $first: Int!) {
            repository(owner: $owner, name: $reponame) {
                issue(number: $issue_id) {
                    id
                    url
                    comments(first: $first) {
                        nodes {
                            id
                            body
                            url
                            resourcePath
                            author {
                                login
                            }
                            createdAt
                            updatedAt
                        }
                    }
                }
            }
        }
        """
        variables = {
            'owner': owner,
            'reponame': repo,
            'issue_id': issue_num,
            'first': first
        }
        
        result = self.__run_query(query, variables)
        issue_data = result['data']['repository']['issue']
        
        if not issue_data:
            raise NotFoundError(f"Issue #{issue_num} not found in {owner}/{repo}")
        
        comments = []
        for comment_data in issue_data['comments']['nodes']:
            comments.append(IssueComment(
                id=comment_data['id'],
                body=comment_data['body'],
                url=comment_data['url'],
                author=comment_data['author']['login'] if comment_data['author'] else 'unknown',
                issue_id=issue_data['id'],
                created_at=comment_data['createdAt'],
                updated_at=comment_data['updatedAt'],
                html_url=f"https://github.com{comment_data['resourcePath']}",
                issue_url=issue_data['url']
            ))
        
        return comments

    def close(self) -> None:
        """Close the session"""
        self.__session.close()


def main():
    """Example usage and CLI interface"""
    parser = argparse.ArgumentParser(description='GitHub GraphQL API Client')
    parser.add_argument('--token', help='GitHub token (or set GITHUB_TOKEN env var)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--owner', required=True, help='Repository owner')
    parser.add_argument('--repo', required=True, help='Repository name')
    parser.add_argument('--issue', type=int, help='Issue number')
    parser.add_argument('--pr', type=int, help='Pull request number')
    parser.add_argument('--comment', help='Add comment with this text')
    
    args = parser.parse_args()
    
    try:
        client = GitHubGraphQL(token=args.token, verbose=args.verbose)
        
        if args.issue:
            issue = client.get_issue(args.owner, args.repo, args.issue)
            print(f"Issue: {issue.title}")
            print(f"State: {issue.state}")
            print(f"Author: {issue.author}")
            print(f"URL: {issue.html_url}")
            
            if args.comment:
                comment = client.add_issue_comment(issue.id, args.comment)
                print(f"Added comment: {comment.url}")
        
        elif args.pr:
            pr = client.get_pull_request(args.owner, args.repo, args.pr)
            print(f"PR: {pr.title}")
            print(f"State: {pr.state}")
            print(f"Author: {pr.author}")
            print(f"Merged: {pr.merged}")
            print(f"URL: {pr.html_url}")
            
            if args.comment:
                comment = client.add_issue_comment(pr.id, args.comment)
                print(f"Added comment: {comment.url}")
        
        # Show rate limit info
        if client.rate_limit:
            print(f"\nRate limit: {client.rate_limit.remaining}/{client.rate_limit.limit}")
        
    except (GitHubAPIError, AuthenticationError, NotFoundError) as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
##
##
