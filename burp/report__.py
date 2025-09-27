#!/usr/bin/env python3
"""
Burp Suite XML → JIRA Ticket Generator ..beta..

- Parses Burp XML reports
- Groups identical vulnerabilities by type + URL
- Creates contextual JIRA tickets with impact/remediation
- Supports creating an Epic with summary breakdowns
"""

import os
import re
import sys
import json
import base64
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter

from jira import JIRA
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


# === Configurable mappings ===
DUE_DATE_RULES = {
    "Critical": 30,
    "High": 30,
    "Medium": 60,
    "Low": 90,
    "Info": None,
}

PRIORITY_MAP = {
    "Critical": "Highest",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Lowest",
}

SEVERITY_ID_MAP = {
    "Critical": "10001",
    "High": "10002",
    "Medium": "10003",
    "Low": "10004",
    "Info": "10005",
}


# === Helpers ===
def parse_burp_report(xml_path, console):
    """Parse Burp XML into structured vulnerability objects"""
    findings = []
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for issue in root.findall(".//issue"):
        f = {}
        f["name"] = issue.findtext("name", "Unknown")
        f["severity"] = issue.findtext("severity", "Info").capitalize()
        f["confidence"] = issue.findtext("confidence", "Firm")
        f["host"] = issue.findtext("host", "")
        f["path"] = issue.findtext("path", "")
        f["url"] = f"{f['host']}{f['path']}"

        f["description"] = issue.findtext("issueDetail", "")
        f["remediation"] = issue.findtext("remediationDetail", "")
        f["issue_type"] = issue.findtext("type", "")

        # request/response decoding
        req = issue.find(".//requestresponse/request")
        if req is not None and req.text:
            if req.attrib.get("base64") == "true":
                try:
                    f["http_request"] = base64.b64decode(req.text).decode(errors="ignore")
                except Exception:
                    f["http_request"] = "[error decoding request]"
            else:
                f["http_request"] = req.text
        else:
            f["http_request"] = ""

        resp = issue.find(".//requestresponse/response")
        if resp is not None and resp.text:
            if resp.attrib.get("base64") == "true":
                try:
                    f["http_response"] = base64.b64decode(resp.text).decode(errors="ignore")
                except Exception:
                    f["http_response"] = "[error decoding response]"
            else:
                f["http_response"] = resp.text
        else:
            f["http_response"] = ""

        findings.append(f)

    console.print(f"[green]Parsed {len(findings)} issues from XML[/green]")
    return findings


def group_findings(findings, console):
    """Group duplicate vulns by name+URL"""
    groups = defaultdict(list)
    for f in findings:
        key = f"{f['name']}|||{f['url']}"
        groups[key].append(f)

    unique, dupes = [], 0
    for key, vulns in groups.items():
        if len(vulns) > 1:
            dupes += len(vulns)
            console.print(f"[yellow]Grouped {len(vulns)} × {vulns[0]['name']} at {vulns[0]['url']}[/yellow]")
        unique.append(merge_group(vulns))

    console.print(f"[green]Reduced {len(findings)} → {len(unique)} unique tickets ({dupes} grouped)[/green]")
    return unique


def merge_group(vulns):
    """Merge multiple identical findings into one"""
    if not vulns:
        return None
    merged = vulns[0].copy()
    merged["instance_count"] = len(vulns)
    if len(vulns) > 1:
        merged["description"] = max((v.get("description", "") for v in vulns), key=len, default="")
        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        merged["severity"] = max(vulns, key=lambda v: severity_rank.get(v["severity"], 0))["severity"]
    return merged


def classify_category(name):
    """Roughly classify vuln type"""
    n = name.lower()
    if any(t in n for t in ["xss", "script", "injection", "sql"]):
        return "injection"
    if any(t in n for t in ["auth", "csrf", "session"]):
        return "auth"
    if any(t in n for t in ["disclosure", "info", "directory", "path"]):
        return "disclosure"
    if any(t in n for t in ["header", "cookie", "config"]):
        return "configuration"
    return "general"


def build_issue_summary(name, url, count=1):
    """Generate a short JIRA summary"""
    endpoint = url.split("/", 3)[-1] if "/" in url else url
    summary = f"{name} in /{endpoint}"
    if count > 1:
        summary += f" ({count} instances)"
    return summary[:100]


def sanitize_text(text, maxlen=1200):
    clean = re.sub(r"<[^>]+>", "", text or "")
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean[:maxlen] + ("..." if len(clean) > maxlen else "")


def build_ticket(vuln):
    """Construct a ticket object from a vuln dict"""
    category = classify_category(vuln["name"])
    summary = build_issue_summary(vuln["name"], vuln["url"], vuln.get("instance_count", 1))

    return {
        "summary": summary,
        "description": sanitize_text(vuln.get("description", "")),
        "severity": vuln.get("severity", "Info"),
        "category": category,
        "url": vuln.get("url"),
        "remediation": sanitize_text(vuln.get("remediation", "")),
        "count": vuln.get("instance_count", 1),
        "http_request": vuln.get("http_request", ""),
        "http_response": vuln.get("http_response", ""),
    }


def ticket_to_jira_body(ticket):
    """Render ticket fields into JIRA wiki markup"""
    body = f"""h1. {ticket['summary']}

*Severity:* {ticket['severity']}
*Category:* {ticket['category'].title()}
*Instances:* {ticket['count']}

h2. Description
{ticket['description'] or 'No description'}

h2. Affected Endpoint
{ticket['url']}

h2. Suggested Remediation
{ticket['remediation'] or 'Review required'}
"""
    if ticket["http_request"]:
        body += f"\nh2. Sample Request\n{{code}}\n{ticket['http_request'][:800]}\n{{code}}\n"
    if ticket["http_response"]:
        body += f"\nh2. Sample Response\n{{code}}\n{ticket['http_response'][:800]}\n{{code}}\n"
    return body


def epic_summary(tickets):
    """Generate the Epic description with stats"""
    total = len(tickets)
    instances = sum(t["count"] for t in tickets)
    sev_counts = Counter(t["severity"] for t in tickets)
    cat_counts = Counter(t["category"] for t in tickets)
    top_types = Counter(t["summary"].split(" in ")[0] for t in tickets)

    body = f"""h1. Burp Suite Scan Summary

*Unique Vulns:* {total}
*Total Instances:* {instances}

h2. Severity Breakdown
"""
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        body += f"* {sev}: {sev_counts.get(sev, 0)}\n"
    body += "\nh2. Category Breakdown\n"
    for cat, c in cat_counts.most_common():
        body += f"* {cat.title()}: {c}\n"
    body += "\nh2. Top 5 Findings\n"
    for v, c in top_types.most_common(5):
        body += f"# {v} ({c} instances)\n"
    return body


# === JIRA integration ===
def push_ticket_to_jira(ticket, jira, project, epic_key=None):
    issue_dict = {
        "project": {"key": project},
        "summary": ticket["summary"],
        "description": ticket_to_jira_body(ticket),
        "issuetype": {"name": "Bug"},  # configurable
        "priority": {"name": PRIORITY_MAP.get(ticket["severity"], "Medium")},
        "labels": ["burp-scan", f"severity-{ticket['severity'].lower()}"],
    }
    if epic_key:
        issue_dict["customfield_10000"] = epic_key  # generic Epic link field
    return jira.create_issue(fields=issue_dict)


def push_epic_to_jira(jira, project, name, tickets):
    issue_dict = {
        "project": {"key": project},
        "summary": name,
        "description": epic_summary(tickets),
        "issuetype": {"name": "Epic"},
    }
    return jira.create_issue(fields=issue_dict)


# === Main ===
def main():
    p = argparse.ArgumentParser(description="Burp XML → JIRA ticket automation")
    p.add_argument("xml", help="Path to Burp XML")
    p.add_argument("--project", default="TEST", help="JIRA project key")
    p.add_argument("--max", type=int, help="Max tickets")
    p.add_argument("--epic", help="Create Epic with this name")
    p.add_argument("--push", action="store_true", help="Push to JIRA")
    args = p.parse_args()

    console = Console()
    console.print(Panel("Burp XML to JIRA", style="bold magenta"))

    findings = parse_burp_report(args.xml, console)
    grouped = group_findings(findings, console)
    tickets = [build_ticket(f) for f in grouped]
    if args.max:
        tickets = tickets[: args.max]

    if args.push:
        jira = JIRA(
            server=os.environ.get("JIRA_SERVER"),
            basic_auth=(os.environ.get("JIRA_USER"), os.environ.get("JIRA_TOKEN")),
        )
        epic_key = None
        if args.epic:
            epic = push_epic_to_jira(jira, args.project, args.epic, tickets)
            epic_key = epic.key
            console.print(f"[green]Created Epic {epic.key}[/green]")
        for t in tickets:
            issue = push_ticket_to_jira(t, jira, args.project, epic_key)
            console.print(f"[green]Created ticket {issue.key}[/green]")

    with open("tickets.json", "w") as f:
        json.dump(tickets, f, indent=2)


if __name__ == "__main__":
    main()

##
##
