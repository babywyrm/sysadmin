#!/usr/bin/env python3
"""
Burp Suite Report to JIRA Ticket Generator with URL-based Grouping ~~ beta ~~

This module parses Burp Suite XML reports and generates consolidated JIRA tickets
for security vulnerabilities, grouping identical vulnerabilities found on the same
exact URL/endpoint to reduce ticket noise.

Dependencies:
    - anthropic: Claude API client
    - rich: Terminal formatting and display
    - xml.etree.ElementTree: XML parsing (stdlib)
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Any, DefaultDict
import xml.etree.ElementTree as ET

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Type aliases for better code readability
VulnerabilityDict = Dict[str, Any]
TicketDict = Dict[str, Any]
GroupedVulnerabilities = DefaultDict[str, List[VulnerabilityDict]]


def get_anthropic_api_key() -> str:
    """
    Retrieve the Anthropic API key from environment variables.
    
    Checks both CLAUDE_API_KEY and ANTHROPIC_API_KEY environment variables.
    
    Returns:
        str: The API key
        
    Raises:
        SystemExit: If no API key is found in environment variables
    """
    api_key = os.getenv('CLAUDE_API_KEY') or os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        print("Error: CLAUDE_API_KEY or ANTHROPIC_API_KEY environment variable not set.")
        sys.exit(1)
    return api_key


def parse_burp_xml_report(xml_file_path: Path, console: Console) -> List[VulnerabilityDict]:
    """
    Parse a Burp Suite XML report and extract vulnerability data.
    
    Args:
        xml_file_path: Path to the Burp Suite XML export file
        console: Rich console for output formatting
        
    Returns:
        List of vulnerability dictionaries containing parsed data
        
    Note:
        Each vulnerability dict contains: name, severity, confidence, host, 
        path, url, description, remediation, and issue_type
    """
    vulnerabilities: List[VulnerabilityDict] = []
    
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        
        # Iterate through all <issue> elements in the XML
        for issue_element in root.findall('.//issue'):
            vulnerability = _extract_vulnerability_data(issue_element)
            vulnerabilities.append(vulnerability)
        
        console.print(f"[green]Successfully parsed {len(vulnerabilities)} vulnerabilities from XML[/green]")
        
    except ET.ParseError as e:
        console.print(f"[red]XML parsing error: {e}[/red]")
    except FileNotFoundError:
        console.print(f"[red]XML file not found: {xml_file_path}[/red]")
    except Exception as e:
        console.print(f"[red]Unexpected error parsing XML: {e}[/red]")
    
    return vulnerabilities


def _extract_vulnerability_data(issue_element: ET.Element) -> VulnerabilityDict:
    """
    Extract vulnerability data from a single XML <issue> element.
    
    Args:
        issue_element: XML element containing issue data
        
    Returns:
        Dictionary containing structured vulnerability data
    """
    # Helper function to safely extract text from XML elements
    def safe_extract_text(parent: ET.Element, tag_name: str, default: str = '') -> str:
        element = parent.find(tag_name)
        return element.text if element is not None and element.text else default
    
    # Extract core vulnerability information
    name = safe_extract_text(issue_element, 'name', 'Unknown Vulnerability')
    severity = safe_extract_text(issue_element, 'severity', 'Info')
    confidence = safe_extract_text(issue_element, 'confidence', 'Firm')
    host = safe_extract_text(issue_element, 'host')
    path = safe_extract_text(issue_element, 'path')
    
    # Construct full URL for grouping purposes
    full_url = f"{host}{path}"
    
    # Extract detailed descriptions
    description = safe_extract_text(issue_element, 'issueDetail')
    remediation = safe_extract_text(issue_element, 'remediationDetail')
    issue_type = safe_extract_text(issue_element, 'type')
    
    return {
        'name': name,
        'severity': severity,
        'confidence': confidence,
        'host': host,
        'path': path,
        'url': full_url,
        'description': description,
        'remediation': remediation,
        'issue_type': issue_type
    }


def group_vulnerabilities_by_url_and_type(
    vulnerabilities: List[VulnerabilityDict], 
    console: Console
) -> List[VulnerabilityDict]:
    """
    Group vulnerabilities by exact URL and vulnerability name match.
    
    This function consolidates identical vulnerabilities found on the same
    endpoint to reduce ticket duplication.
    
    Args:
        vulnerabilities: List of individual vulnerability dictionaries
        console: Rich console for progress output
        
    Returns:
        List of consolidated vulnerability dictionaries with instance counts
    """
    # Group vulnerabilities using vulnerability name + exact URL as key
    vulnerability_groups: GroupedVulnerabilities = defaultdict(list)
    
    for vulnerability in vulnerabilities:
        # Create unique grouping key: vulnerability_name|||exact_url
        grouping_key = f"{vulnerability['name']}|||{vulnerability['url']}"
        vulnerability_groups[grouping_key].append(vulnerability)
    
    # Process groups and create consolidated vulnerabilities
    consolidated_vulnerabilities: List[VulnerabilityDict] = []
    grouped_instance_count = 0
    total_original_instances = len(vulnerabilities)
    
    for group_key, vulnerability_list in vulnerability_groups.items():
        # Track how many instances were grouped
        if len(vulnerability_list) > 1:
            grouped_instance_count += len(vulnerability_list)
            console.print(
                f"[yellow]Consolidated {len(vulnerability_list)} identical instances: "
                f"{vulnerability_list[0]['name']} at {vulnerability_list[0]['url']}[/yellow]"
            )
        
        # Create consolidated vulnerability from the group
        consolidated = _create_consolidated_vulnerability(vulnerability_list)
        consolidated_vulnerabilities.append(consolidated)
    
    # Display grouping statistics
    unique_tickets = len(consolidated_vulnerabilities)
    console.print(
        f"[green]Consolidated {grouped_instance_count} duplicate instances[/green]"
    )
    console.print(
        f"[green]Result: {total_original_instances} instances -> {unique_tickets} unique tickets[/green]"
    )
    
    return consolidated_vulnerabilities


def _create_consolidated_vulnerability(vulnerability_list: List[VulnerabilityDict]) -> VulnerabilityDict:
    """
    Create a single consolidated vulnerability from multiple identical instances.
    
    Args:
        vulnerability_list: List of identical vulnerabilities on the same URL
        
    Returns:
        Consolidated vulnerability dictionary with metadata about instances
    """
    if not vulnerability_list:
        raise ValueError("Cannot consolidate empty vulnerability list")
    
    # Start with the first vulnerability as the base
    consolidated = vulnerability_list[0].copy()
    consolidated['instance_count'] = len(vulnerability_list)
    
    # If we have multiple instances, enhance the consolidation
    if len(vulnerability_list) > 1:
        consolidated = _enhance_consolidated_vulnerability(vulnerability_list, consolidated)
    
    return consolidated


def _enhance_consolidated_vulnerability(
    vulnerability_list: List[VulnerabilityDict], 
    base_vulnerability: VulnerabilityDict
) -> VulnerabilityDict:
    """
    Enhance consolidated vulnerability with best data from all instances.
    
    Args:
        vulnerability_list: All vulnerability instances
        base_vulnerability: Base vulnerability to enhance
        
    Returns:
        Enhanced consolidated vulnerability
    """
    # Collect unique descriptions (in case of variations)
    unique_descriptions = []
    for vuln in vulnerability_list:
        description = vuln.get('description', '').strip()
        if description and description not in unique_descriptions:
            unique_descriptions.append(description)
    
    # Use the most detailed description
    if unique_descriptions:
        base_vulnerability['description'] = max(unique_descriptions, key=len)
    
    # Use the highest severity level found across all instances
    severity_hierarchy = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
    highest_severity_vuln = max(
        vulnerability_list, 
        key=lambda vuln: severity_hierarchy.get(vuln.get('severity', 'Info'), 0)
    )
    base_vulnerability['severity'] = highest_severity_vuln['severity']
    base_vulnerability['confidence'] = highest_severity_vuln['confidence']
    
    return base_vulnerability


def create_jira_ticket_prompt(consolidated_vulnerability: VulnerabilityDict) -> str:
    """
    Generate a prompt for Claude API to create a JIRA ticket.
    
    Args:
        consolidated_vulnerability: Vulnerability data including instance count
        
    Returns:
        Formatted prompt string for Claude API
    """
    vuln = consolidated_vulnerability
    instance_count = vuln.get('instance_count', 1)
    
    # Add context about multiple instances if applicable
    instance_context = ""
    if instance_count > 1:
        instance_context = (
            f"This vulnerability was detected {instance_count} times on the same endpoint, "
            f"indicating multiple instances or strong confirmation of the issue."
        )
    
    prompt_template = f"""Create a comprehensive JIRA ticket for this security vulnerability:

Vulnerability Name: {vuln['name']}
Severity Level: {vuln['severity']}
Detection Confidence: {vuln.get('confidence', 'Firm')}
Affected URL: {vuln['url']}
Instance Count: {instance_count} {'occurrence' if instance_count == 1 else 'occurrences'}

{instance_context}

Vulnerability Description: {vuln['description'][:1500]}
Recommended Remediation: {vuln['remediation'][:800]}

Generate a structured JSON response with these specific fields:
{{
  "summary": "Clear, actionable ticket title suitable for JIRA",
  "priority": "Critical|High|Medium|Low", 
  "description": "Detailed JIRA description with proper markdown formatting",
  "impact": "Comprehensive business and security impact assessment",
  "remediation_steps": ["Specific step 1", "Specific step 2", "Specific step 3"],
  "affected_endpoint": "The exact URL or endpoint affected",
  "technical_details": "Technical explanation suitable for developers",
  "labels": ["security", "vulnerability", "additional-relevant-tags"]
}}

Focus on providing actionable, specific remediation steps for this particular endpoint and vulnerability type."""
    
    return prompt_template


def generate_jira_ticket_via_claude(
    client: anthropic.Anthropic, 
    consolidated_vulnerability: VulnerabilityDict, 
    console: Console
) -> Optional[TicketDict]:
    """
    Generate a JIRA ticket using Claude API for the given vulnerability.
    
    Args:
        client: Configured Anthropic client
        consolidated_vulnerability: Vulnerability data to process
        console: Rich console for error reporting
        
    Returns:
        Generated ticket dictionary or None if generation failed
    """
    try:
        # Create the prompt for Claude
        prompt = create_jira_ticket_prompt(consolidated_vulnerability)
        
        # Make API call to Claude
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        # Extract and parse the response
        response_text = response.content[0].text
        ticket_data = _extract_json_from_response(response_text)
        
        if ticket_data:
            # Add metadata to the ticket
            ticket_data = _add_metadata_to_ticket(ticket_data, consolidated_vulnerability)
            return ticket_data
        else:
            console.print("[yellow]Could not parse JSON response from Claude API[/yellow]")
            
    except anthropic.APIError as e:
        console.print(f"[red]Claude API error: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Unexpected error generating ticket: {e}[/red]")
    
    return None


def _extract_json_from_response(response_text: str) -> Optional[Dict[str, Any]]:
    """
    Extract JSON object from Claude's text response.
    
    Args:
        response_text: Raw text response from Claude
        
    Returns:
        Parsed JSON dictionary or None if parsing failed
    """
    try:
        # Find JSON boundaries in the response
        json_start = response_text.find('{')
        json_end = response_text.rfind('}') + 1
        
        if json_start >= 0 and json_end > json_start:
            json_string = response_text[json_start:json_end]
            return json.loads(json_string)
    except json.JSONDecodeError:
        pass
    
    return None


def _add_metadata_to_ticket(ticket_data: TicketDict, vulnerability: VulnerabilityDict) -> TicketDict:
    """
    Add metadata from the original vulnerability to the generated ticket.
    
    Args:
        ticket_data: Generated ticket data from Claude
        vulnerability: Original vulnerability data
        
    Returns:
        Enhanced ticket data with metadata
    """
    ticket_data['vulnerability_name'] = vulnerability['name']
    ticket_data['instance_count'] = vulnerability.get('instance_count', 1)
    ticket_data['url'] = vulnerability['url']
    ticket_data['original_severity'] = vulnerability['severity']
    
    return ticket_data


def format_jira_ticket_content(ticket: TicketDict) -> str:
    """
    Format a ticket dictionary as JIRA-ready markup text.
    
    Args:
        ticket: Generated ticket data
        
    Returns:
        Formatted JIRA ticket content with proper markup
    """
    if not ticket:
        return "No ticket data available"
    
    instance_count = ticket.get('instance_count', 1)
    instance_suffix = f" ({instance_count} instances)" if instance_count > 1 else ""
    
    # Build the JIRA-formatted ticket content
    jira_content_sections = [
        f"h1. {ticket.get('summary', 'Security Issue')}{instance_suffix}",
        "",
        f"*Priority:* {ticket.get('priority', 'Medium')}",
        f"*Vulnerability Type:* {ticket.get('vulnerability_name', 'Unknown')}",
        f"*Original Severity:* {ticket.get('original_severity', 'Unknown')}",
        "",
        "h2. Description",
        ticket.get('description', 'No description available'),
        "",
        "h2. Affected Endpoint", 
        ticket.get('affected_endpoint', ticket.get('url', 'Unknown URL')),
        "",
        "h2. Business Impact",
        ticket.get('impact', 'Impact assessment pending'),
        "",
        "h2. Technical Details",
        ticket.get('technical_details', 'Technical analysis required'),
        "",
        "h2. Remediation Steps"
    ]
    
    # Add numbered remediation steps
    remediation_steps = ticket.get('remediation_steps', ['No remediation steps provided'])
    for step_number, step_description in enumerate(remediation_steps, 1):
        jira_content_sections.append(f"{step_number}. {step_description}")
    
    # Add instance detection notes if applicable
    if instance_count > 1:
        jira_content_sections.extend([
            "",
            "h2. Detection Notes",
            f"This vulnerability was detected {instance_count} times on the same endpoint, "
            f"confirming the presence and consistency of the security issue."
        ])
    
    # Add labels and footer
    labels = ', '.join(ticket.get('labels', ['security']))
    jira_content_sections.extend([
        "",
        "h2. Labels", 
        labels,
        "",
        "----",
        "_Generated from Burp Suite Report via Claude AI_"
    ])
    
    return '\n'.join(jira_content_sections)


def display_vulnerability_grouping_summary(consolidated_vulnerabilities: List[VulnerabilityDict], console: Console) -> None:
    """
    Display a formatted table showing the vulnerability grouping results.
    
    Args:
        consolidated_vulnerabilities: List of consolidated vulnerabilities
        console: Rich console for table display
    """
    table = Table(title="Vulnerability Consolidation Summary")
    table.add_column("Vulnerability Type", style="cyan", max_width=40)
    table.add_column("Affected URL", style="magenta", max_width=50) 
    table.add_column("Instances", style="yellow", justify="right")
    table.add_column("Severity", style="red")
    
    # Sort by instance count (grouped items appear first)
    sorted_vulnerabilities = sorted(
        consolidated_vulnerabilities, 
        key=lambda vuln: vuln.get('instance_count', 1), 
        reverse=True
    )
    
    for vulnerability in sorted_vulnerabilities:
        url = vulnerability.get('url', 'Unknown URL')
        # Truncate long URLs for table display
        display_url = f"{url[:47]}..." if len(url) > 50 else url
        
        vulnerability_name = vulnerability['name']
        display_name = f"{vulnerability_name[:37]}..." if len(vulnerability_name) > 40 else vulnerability_name
        
        table.add_row(
            display_name,
            display_url,
            str(vulnerability.get('instance_count', 1)),
            vulnerability.get('severity', 'Unknown')
        )
    
    console.print("\n")
    console.print(table)
    console.print("\n")


def save_jira_tickets_to_files(
    tickets: List[TicketDict], 
    output_base_path: Optional[str], 
    console: Console
) -> None:
    """
    Save generated JIRA tickets to individual text files and a JSON summary.
    
    Args:
        tickets: List of generated ticket dictionaries
        output_base_path: Base path for output files (auto-generated if None)
        console: Rich console for progress output
    """
    # Determine output path
    if output_base_path:
        base_path = output_base_path
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_path = f"grouped_jira_tickets_{timestamp}"
    
    # Create output directory for individual ticket files
    ticket_directory = Path(f"{base_path}_files")
    ticket_directory.mkdir(exist_ok=True)
    
    # Save each ticket as an individual file
    for ticket_index, ticket in enumerate(tickets, 1):
        if ticket:
            filename = _generate_ticket_filename(ticket, ticket_index)
            ticket_file_path = ticket_directory / filename
            
            # Format and save ticket content
            jira_content = format_jira_ticket_content(ticket)
            ticket_file_path.write_text(jira_content, encoding='utf-8')
            
            # Display progress with instance information
            instance_count = ticket.get('instance_count', 1)
            instance_note = f" (consolidates {instance_count} instances)" if instance_count > 1 else ""
            console.print(f"[green]Saved: {ticket_file_path.name}{instance_note}[/green]")
    
    # Save JSON summary of all tickets
    summary_file_path = Path(f"{base_path}.json")
    summary_file_path.write_text(json.dumps(tickets, indent=2), encoding='utf-8')
    
    # Display completion summary
    total_instances = sum(ticket.get('instance_count', 1) for ticket in tickets if ticket)
    console.print(
        f"[bold green]Saved {len(tickets)} tickets covering {total_instances} "
        f"vulnerability instances to {ticket_directory}[/bold green]"
    )
    console.print(f"[bold green]JSON summary saved to {summary_file_path}[/bold green]")


def _generate_ticket_filename(ticket: TicketDict, ticket_index: int) -> str:
    """
    Generate a safe filename for a JIRA ticket file.
    
    Args:
        ticket: Ticket data dictionary
        ticket_index: Sequential ticket number
        
    Returns:
        Safe filename string
    """
    vulnerability_name = ticket.get('vulnerability_name', 'vulnerability')
    # Create filesystem-safe name by keeping only alphanumeric and safe characters
    safe_name = "".join(
        char for char in vulnerability_name 
        if char.isalnum() or char in (' ', '-', '_')
    )[:25]  # Limit length
    
    instance_count = ticket.get('instance_count', 1)
    instance_suffix = f"_{instance_count}x" if instance_count > 1 else ""
    
    return f"ticket_{ticket_index:03d}_{safe_name}{instance_suffix}.txt"


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure the command-line argument parser.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description="Generate JIRA tickets from Burp Suite reports with URL-based vulnerability grouping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python burp_to_jira.py report.xml
  python burp_to_jira.py report.xml --max-tickets 50 --show-grouping
  python burp_to_jira.py report.xml --output my_tickets --verbose
        """
    )
    
    parser.add_argument(
        'xml_file', 
        help='Path to the Burp Suite XML export file'
    )
    parser.add_argument(
        '--output', '-o', 
        help='Base name for output files (auto-generated if not specified)'
    )
    parser.add_argument(
        '--max-tickets', 
        type=int, 
        default=25, 
        help='Maximum number of tickets to generate (default: 25)'
    )
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true', 
        help='Enable verbose output with additional details'
    )
    parser.add_argument(
        '--show-grouping', 
        action='store_true', 
        help='Display vulnerability grouping summary table'
    )
    
    return parser


def main() -> None:
    """
    Main execution function for the Burp to JIRA ticket generator.
    
    Orchestrates the entire process: argument parsing, vulnerability extraction,
    grouping, ticket generation, and file output.
    """
    # Parse command line arguments
    argument_parser = create_argument_parser()
    args = argument_parser.parse_args()
    
    # Initialize Rich console for formatted output
    console = Console()
    
    # Validate input file existence
    xml_file_path = Path(args.xml_file)
    if not xml_file_path.exists():
        console.print(f"[red]Error: XML file not found at {xml_file_path}[/red]")
        sys.exit(1)
    
    # Initialize Claude API client
    try:
        api_key = get_anthropic_api_key()
        anthropic_client = anthropic.Anthropic(api_key=api_key)
    except SystemExit:
        return  # get_anthropic_api_key already printed error and called sys.exit
    
    # Display processing banner
    console.print(
        Panel(
            f"Processing: {xml_file_path.name}\n"
            f"Grouping identical vulnerabilities on same URLs for efficient ticketing", 
            title="Burp Suite to JIRA Ticket Generator"
        )
    )
    
    # Parse vulnerabilities from XML report
    raw_vulnerabilities = parse_burp_xml_report(xml_file_path, console)
    
    if not raw_vulnerabilities:
        console.print("[yellow]No vulnerabilities found in the XML report[/yellow]")
        return
    
    # Group vulnerabilities by exact URL and vulnerability type
    consolidated_vulnerabilities = group_vulnerabilities_by_url_and_type(raw_vulnerabilities, console)
    
    # Display grouping summary if requested
    if args.show_grouping:
        display_vulnerability_grouping_summary(consolidated_vulnerabilities, console)
    
    # Limit processing to specified maximum
    max_tickets_to_process = min(len(consolidated_vulnerabilities), args.max_tickets)
    console.print(f"Generating JIRA tickets for {max_tickets_to_process} unique vulnerabilities...")
    
    # Generate JIRA tickets using Claude API
    generated_tickets: List[Optional[TicketDict]] = []
    
    for ticket_index, vulnerability_group in enumerate(consolidated_vulnerabilities[:max_tickets_to_process], 1):
        instance_count = vulnerability_group.get('instance_count', 1)
        instance_indicator = f" ({instance_count}x)" if instance_count > 1 else ""
        
        console.print(
            f"[{ticket_index}/{max_tickets_to_process}] Processing: "
            f"{vulnerability_group['name'][:35]}...{instance_indicator}"
        )
        
        # Generate ticket via Claude API
        generated_ticket = generate_jira_ticket_via_claude(anthropic_client, vulnerability_group, console)
        generated_tickets.append(generated_ticket)
        
        # Display verbose information if requested
        if args.verbose and generated_ticket:
            console.print(f"  Priority: {generated_ticket.get('priority', 'N/A')}")
            console.print(f"  URL: {generated_ticket.get('url', 'N/A')[:60]}...")
        
        # Rate limiting to avoid API throttling
        time.sleep(1)
    
    # Filter out None values and save results
    valid_tickets = [ticket for ticket in generated_tickets if ticket is not None]
    save_jira_tickets_to_files(valid_tickets, args.output, console)
    
    # Display final summary
    total_vulnerability_instances = sum(
        ticket.get('instance_count', 1) for ticket in valid_tickets
    )
    console.print(
        f"\n[bold green]Successfully created {len(valid_tickets)} JIRA tickets "
        f"covering {total_vulnerability_instances} vulnerability instances[/bold green]"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)
