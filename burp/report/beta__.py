#!/usr/bin/env python3
"""
Burp Suite Report to JIRA Ticket Generator (..beta..)
- Parses Burp XML reports
- Groups identical vulnerabilities per endpoint
- Generates contextual JIRA tickets dynamically
- Supports creating a master Epic with child tickets
- Saves outputs as JSON + per-ticket text files
"""
import os
import sys
import json
import argparse
import re
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import xml.etree.ElementTree as ET

from jira import JIRA
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# =====================================================================
# === Configurable mappings (safe placeholders) =======================
# =====================================================================

DUE_DATE_RULES = {
    "Critical": 30,
    "High": 30,
    "Medium": 60,
    "Low": 90,
    "Info": None,
}

# Placeholder IDs – replace with real values in your JIRA
SEVERITY_FIELD_MAP = {
    "Critical": "customfield_severity_critical",
    "High": "customfield_severity_high",
    "Medium": "customfield_severity_medium",
    "Low": "customfield_severity_low",
    "Info": "customfield_severity_info",
}

PRIORITY_MAP = {
    "Critical": "Highest",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Lowest",
}

# Use this for Epic linking (replace with your JIRA custom field ID)
EPIC_LINK_FIELD = "customfield_epic_link"
EPIC_NAME_FIELD = "customfield_epic_name"

# =====================================================================
# === Analysis helpers =================================================
# =====================================================================

def analyze_vulnerability_types(vulnerabilities, console):
    """Summarize vulnerability distribution by type and severity."""
    vuln_stats = Counter()
    severity_stats = defaultdict(Counter)

    for vuln in vulnerabilities:
        name = vuln["name"]
        sev = vuln["severity"]
        vuln_stats[name] += 1
        severity_stats[name][sev] += 1

    console.print(f"\n[bold cyan]Found {len(vuln_stats)} unique vulnerability types[/bold cyan]")

    table = Table(title="Vulnerability Type Analysis")
    table.add_column("Vulnerability Type", style="cyan", max_width=50)
    table.add_column("Count", style="yellow", justify="right")
    table.add_column("Severities", style="red")

    for vuln_name, count in vuln_stats.most_common():
        severities = ", ".join(f"{sev}({c})" for sev, c in severity_stats[vuln_name].most_common())
        table.add_row(
            vuln_name[:47] + ("..." if len(vuln_name) > 50 else ""),
            str(count),
            severities
        )
    console.print(table)
    return list(vuln_stats.keys())


def classify_vulnerability_category(vuln_name):
    """Map a vulnerability name into a broader security category."""
    text = vuln_name.lower()
    if any(t in text for t in ['injection', 'sqli', 'sql', 'xss', 'script']):
        return 'injection'
    if any(t in text for t in ['auth', 'session', 'csrf', 'clickjacking']):
        return 'auth'
    if any(t in text for t in ['disclosure', 'info', 'error', 'path']):
        return 'disclosure'
    if any(t in text for t in ['header', 'config', 'cookie', 'tls']):
        return 'configuration'
    if any(t in text for t in ['validation', 'input', 'reflected']):
        return 'validation'
    if any(t in text for t in ['crypto', 'ssl', 'encryption']):
        return 'crypto'
    return 'general'


def build_dynamic_impact(vuln_name, category, severity):
    """Generate human-readable business impact text."""
    base_impacts = {
        'injection': "Risk of data breach, unauthorized access, or data manipulation",
        'auth': "Risk of account compromise, privilege escalation, or session hijacking",
        'disclosure': "Sensitive information leakage that could aid attackers",
        'configuration': "Weak configurations may broaden attack surface",
        'validation': "Improper input handling may enable injection or logic bypass",
        'crypto': "Weak cryptography may lead to data exposure or MITM attacks",
        'general': "Security weakness requiring remediation"
    }
    impact = base_impacts.get(category, base_impacts['general'])
    if severity in ["Critical", "High"]:
        impact += " – requires immediate attention."
    elif severity == "Medium":
        impact += " – should be remediated soon."
    elif severity == "Low":
        impact += " – lower urgency but still relevant."
    return impact


def build_remediation_steps(category):
    """Return a generic set of remediation recommendations by category."""
    steps = {
        'injection': [
            "Use parameterized queries",
            "Validate and sanitize input",
            "Apply least-privilege principles"
        ],
        'auth': [
            "Implement proper session management",
            "Add MFA where possible",
            "Enforce strict authorization checks"
        ],
        'disclosure': [
            "Remove sensitive debug info",
            "Harden error handling",
            "Restrict file/directory access"
        ],
        'configuration': [
            "Apply recommended security headers",
            "Harden TLS/SSL configuration",
            "Regularly audit system configs"
        ],
        'validation': [
            "Enforce whitelist-based input validation",
            "Escape/encode user-controlled output",
            "Audit parameter handling logic"
        ],
        'crypto': [
            "Update to strong cryptographic standards",
            "Validate certificates properly",
            "Apply TLS 1.2+ only"
        ],
        'general': [
            "Review and remediate based on context",
            "Test fixes before deployment"
        ]
    }
    return steps.get(category, steps['general'])


# =====================================================================
# === Burp XML Parsing =================================================
# =====================================================================

def parse_burp_xml(xml_path, console):
    """Parse Burp XML file and extract vulnerability data."""
    vulns = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for issue in root.findall(".//issue"):
            vuln = {}
            vuln["name"] = issue.findtext("name", "Unknown")
            vuln["severity"] = issue.findtext("severity", "Info")
            vuln["confidence"] = issue.findtext("confidence", "Firm")
            vuln["host"] = issue.findtext("host", "")
            vuln["path"] = issue.findtext("path", "")
            vuln["url"] = f"{vuln['host']}{vuln['path']}"
            vuln["description"] = issue.findtext("issueDetail", "")
            vuln["remediation"] = issue.findtext("remediationDetail", "")
            vuln["issue_type"] = issue.findtext("type", "")
            vulns.append(vuln)
        console.print(f"[green]Parsed {len(vulns)} vulnerabilities from XML[/green]")
    except Exception as e:
        console.print(f"[red]Error parsing XML: {e}[/red]")
    return vulns


def group_by_url(vulnerabilities, console):
    """Group vulnerabilities by (name, url)."""
    groups = defaultdict(list)
    for v in vulnerabilities:
        groups[f"{v['name']}|||{v['url']}"].append(v)

    result = []
    dupes = 0
    for key, vulns in groups.items():
        consolidated = vulns[0].copy()
        consolidated["instance_count"] = len(vulns)
        result.append(consolidated)
        if len(vulns) > 1:
            dupes += len(vulns)
            console.print(f"[yellow]Grouped {len(vulns)}: {vulns[0]['name']} at {vulns[0]['url']}[/yellow]")

    console.print(f"[green]Grouped {dupes} duplicates into {len(result)} tickets[/green]")
    return result


# =====================================================================
# === Ticket Generation ===============================================
# =====================================================================

def smart_summary(name, url, count):
    """Generate a clean JIRA summary."""
    endpoint = url.split("/", 3)[-1] if "/" in url else url
    if count > 1:
        return f"{name} in {endpoint} ({count} instances)"
    return f"{name} in {endpoint}"


def build_ticket(vuln):
    """Assemble a ticket object from a vuln dict."""
    category = classify_vulnerability_category(vuln["name"])
    return {
        "summary": smart_summary(vuln["name"], vuln["url"], vuln.get("instance_count", 1)),
        "description": vuln.get("description", "No details"),
        "priority": PRIORITY_MAP.get(vuln["severity"], "Medium"),
        "impact": build_dynamic_impact(vuln["name"], category, vuln["severity"]),
        "remediation_steps": build_remediation_steps(category),
        "url": vuln["url"],
        "severity": vuln["severity"],
        "category": category,
        "instance_count": vuln.get("instance_count", 1)
    }


def format_ticket_for_jira(ticket):
    """Build JIRA body (Wiki Markup)."""
    body = f"""h1. {ticket['summary']}

*Severity:* {ticket['severity']}
*Category:* {ticket['category']}
*Priority:* {ticket['priority']}

h2. Description
{ticket['description']}

h2. Impact
{ticket['impact']}

h2. Remediation Steps
"""
    for i, step in enumerate(ticket["remediation_steps"], 1):
        body += f"{i}. {step}\n"

    if ticket["instance_count"] > 1:
        body += f"\nThis issue appeared {ticket['instance_count']} times.\n"

    body += "\n----\n_Generated by burp2jira.py_"
    return body


# =====================================================================
# === JIRA API Helpers =================================================
# =====================================================================

def create_issue(jira, project, ticket, epic_key=None, console=None):
    """Create a JIRA issue for a ticket."""
    fields = {
        "project": {"key": project},
        "summary": ticket["summary"],
        "description": format_ticket_for_jira(ticket),
        "issuetype": {"name": "Task"},
        "priority": {"name": ticket["priority"]},
        "labels": ["burp-scan", f"category-{ticket['category']}", f"severity-{ticket['severity']}"],
    }
    if epic_key:
        fields[EPIC_LINK_FIELD] = epic_key

    issue = jira.create_issue(fields=fields)
    if console:
        console.print(f"[green]Created issue {issue.key}[/green]")
    return issue.key


def create_epic(jira, project, tickets, epic_name=None, console=None):
    """Create a master Epic summarizing all tickets."""
    total_vulns = len(tickets)
    total_instances = sum(t["instance_count"] for t in tickets)
    name = epic_name or f"Burp Report {datetime.now().date()}"

    description = f"""h1. Burp Scan Summary

*Unique Vulnerabilities:* {total_vulns}
*Total Instances:* {total_instances}

This Epic contains all Burp findings imported into JIRA.
"""

    fields = {
        "project": {"key": project},
        "summary": name,
        "description": description,
        "issuetype": {"name": "Epic"},
        EPIC_NAME_FIELD: name,
    }
    epic = jira.create_issue(fields=fields)
    if console:
        console.print(f"[bold green]Created Epic {epic.key}[/bold green]")
    return epic.key


# =====================================================================
# === Main =============================================================
# =====================================================================

def main():
    parser = argparse.ArgumentParser(description="Burp XML to JIRA")
    parser.add_argument("xml_file", help="Path to Burp XML file")
    parser.add_argument("--project", default="DEMOSEC")
    parser.add_argument("--max-tickets", type=int, default=25)
    parser.add_argument("--push-to-jira", action="store_true")
    parser.add_argument("--create-master", action="store_true")
    parser.add_argument("--epic-name", help="Custom Epic name")
    args = parser.parse_args()

    console = Console()
    console.print(Panel(f"Processing: {args.xml_file}\nDynamic vulnerability analysis",
                        title="Burp → JIRA"))

    vulns = parse_burp_xml(args.xml_file, console)
    grouped = group_by_url(vulns, console)

    tickets = [build_ticket(v) for v in grouped[:args.max_tickets]]

    jira = None
    epic_key = None
    if args.push_to_jira:
        jira = JIRA(
            server=os.getenv("JIRA_SERVER", "https://your-jira.example.com"),
            basic_auth=(os.getenv("JIRA_USER", "user"), os.getenv("JIRA_PASS", "pass"))
        )
        if args.create_master:
            epic_key = create_epic(jira, args.project, tickets, epic_name=args.epic_name, console=console)

    for t in tickets:
        if args.push_to_jira and jira:
            create_issue(jira, args.project, t, epic_key=epic_key, console=console)

    # Save summary
    out_file = f"burp_jira_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_file, "w") as f:
        json.dump(tickets, f, indent=2)
    console.print(f"[blue]Summary saved to {out_file}[/blue]")


if __name__ == "__main__":
    main()
##
##
