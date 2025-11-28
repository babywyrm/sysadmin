#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jira_tool.py — Modern JIRA CLI Utility (..beta..)
-------------------------------------------------

Features:
- Securely connect to a JIRA server using environment variables or interactive login.
- Fetch and print issue details.
- Update assignee and fields.
- Handle errors gracefully with structured logging.

Requirements:
    pip install jira

Environment Variables:
    JIRA_SERVER, JIRA_USER, JIRA_PASSWORD

Usage Examples:
    python jira_tool.py show PROJ-123
    python jira_tool.py assign PROJ-123 johndoe
    python jira_tool.py update PROJ-123 --summary "Updated summary"
"""

import argparse
import logging
import os
import sys
import getpass
from jira import JIRA
from jira.exceptions import JIRAError

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(levelname)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger("jira_tool")

# ---------------------------------------------------------------------------
# JIRA Connection
# ---------------------------------------------------------------------------
def connect_jira(server: str, user: str, password: str) -> JIRA:
    """Connect to JIRA using server URL and credentials."""
    try:
        log.info(f"Connecting to JIRA server: {server}")
        options = {"server": server}
        jira = JIRA(options=options, basic_auth=(user, password))
        return jira
    except Exception as e:
        log.error(f"JIRA connection failed: {e}")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Display issue information
# ---------------------------------------------------------------------------
def print_issue(issue, server: str):
    """Pretty-print JIRA issue details."""
    fields = issue.fields
    print("=" * 80)
    print(f"Issue:       {issue.key}")
    print(f"Summary:     {fields.summary}")
    print(f"Description: {fields.description or '(No description)'}")
    print(f"Reporter:    {fields.reporter.displayName}")
    print(f"Assignee:    {fields.assignee.displayName if fields.assignee else 'Unassigned'}")
    print(f"Status:      {fields.status.name}")
    print(f"Link:        {server}/browse/{issue.key}")
    print("=" * 80)

# ---------------------------------------------------------------------------
# Assign issue to a user
# ---------------------------------------------------------------------------
def assign_issue(jira: JIRA, issue_key: str, assignee: str):
    """Assign a JIRA issue to a user."""
    try:
        issue = jira.issue(issue_key)
        log.info(f"Assigning {issue_key} to {assignee} ...")
        issue.update(fields={"assignee": {"name": assignee}})
        log.info("Assignment successful.")
    except JIRAError as e:
        log.error(f"Failed to assign {issue_key}: {e}")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Update issue summary or description
# ---------------------------------------------------------------------------
def update_issue(jira: JIRA, issue_key: str, summary=None, description=None):
    """Update summary and/or description fields of a JIRA issue."""
    try:
        issue = jira.issue(issue_key)
        fields_to_update = {}
        if summary:
            fields_to_update["summary"] = summary
        if description:
            fields_to_update["description"] = description

        if not fields_to_update:
            log.warning("No fields provided to update.")
            return

        issue.update(fields=fields_to_update)
        log.info(f"Updated issue {issue_key}.")
    except JIRAError as e:
        log.error(f"Failed to update {issue_key}: {e}")
        sys.exit(1)

# ---------------------------------------------------------------------------
# CLI Argument Parsing
# ---------------------------------------------------------------------------
def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Modern JIRA command-line tool.")
    parser.add_argument("command", choices=["show", "assign", "update"], help="Action to perform.")
    parser.add_argument("issue", help="JIRA issue key (e.g. PROJ-123).")
    parser.add_argument("value", nargs="?", help="Value for the operation (e.g. assignee username).")
    parser.add_argument("--summary", help="Update issue summary.")
    parser.add_argument("--description", help="Update issue description.")
    return parser.parse_args()

# ---------------------------------------------------------------------------
# Main execution logic
# ---------------------------------------------------------------------------
def main():
    args = parse_arguments()

    # Gather credentials securely
    server = os.getenv("JIRA_SERVER") or input("JIRA server URL (e.g. https://jira.domain.com): ")
    user = os.getenv("JIRA_USER") or input("Username: ")
    password = os.getenv("JIRA_PASSWORD") or getpass.getpass("Password: ")

    jira = connect_jira(server, user, password)

    if args.command == "show":
        try:
            issue = jira.issue(args.issue)
            print_issue(issue, server)
        except JIRAError as e:
            log.error(f"Could not fetch issue {args.issue}: {e}")
            sys.exit(1)

    elif args.command == "assign":
        if not args.value:
            sys.exit("Missing assignee username.")
        assign_issue(jira, args.issue, args.value)

    elif args.command == "update":
        update_issue(jira, args.issue, args.summary, args.description)

if __name__ == "__main__":
    main()
