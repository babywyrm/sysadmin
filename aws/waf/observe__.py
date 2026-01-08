#!/usr/bin/env python3
"""
WAF Observer - Unified Read-Only WAF Observability Tool

Purpose: Audit, monitor, and report on AWS WAF configurations
Access: Read-only (safe for production environments)
Version: 2.0.0
Author: DevOps Team
Last Updated: 2026-01-07

Dependencies:
    - boto3
    - python 3.8+

Usage:
    ./waf-observer.py coverage --profile PROFILE --region REGION
    ./waf-observer.py audit --profile PROFILE --region REGION
    ./waf-observer.py metrics --webacl NAME --profile PROFILE --region REGION
    ./waf-observer.py dump --profile PROFILE --region REGION

Exit Codes:
    0 - Success
    1 - General error
    2 - Missing dependencies
    3 - Invalid arguments
    4 - AWS API error
"""

import argparse
import sys
import os
from typing import List, Dict, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("ERROR: boto3 is required. Install with: pip install boto3", file=sys.stderr)
    sys.exit(2)

# Constants
VERSION = "2.0.0"
MIN_PYTHON_VERSION = (3, 8)

# Rule Priority Classifications
HIGH_PRIORITY_RULES = [
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesLinuxRuleSet",
]

MEDIUM_PRIORITY_RULES = [
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesAmazonIpReputationList",
]

OPTIONAL_RULES = [
    "AWSManagedRulesAnonymousIpList",
]

# ANSI Colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color


class WAFObserver:
    """Main class for WAF observability operations."""
    
    def __init__(self, profile: str, region: str):
        """
        Initialize WAF Observer.
        
        Args:
            profile: AWS profile name
            region: AWS region
        """
        self.profile = profile
        self.region = region
        self.session = None
        self.wafv2_client = None
        self.cloudwatch_client = None
        
    def _initialize_session(self):
        """Initialize boto3 session and clients."""
        try:
            self.session = boto3.Session(
                profile_name=self.profile,
                region_name=self.region
            )
            self.wafv2_client = self.session.client('wafv2')
            self.cloudwatch_client = self.session.client('cloudwatch')
            
            # Validate credentials
            sts = self.session.client('sts')
            sts.get_caller_identity()
            self._success("AWS authentication successful")
            
        except NoCredentialsError:
            self._error_exit(
                f"No AWS credentials found for profile '{self.profile}'",
                exit_code=4
            )
        except ClientError as e:
            self._error_exit(
                f"Failed to authenticate with AWS: {e}",
                exit_code=4
            )
    
    def _print_separator(self, char: str = "━", length: int = 110):
        """Print a horizontal separator line."""
        print(char * length)
    
    def _print_header(self, title: str):
        """Print a formatted section header."""
        print()
        self._print_separator()
        print(f"{Colors.BOLD}{title}{Colors.NC}")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
        print(f"Region: {self.region} | Profile: {self.profile} | Date: {timestamp}")
        self._print_separator()
        print()
    
    def _info(self, message: str):
        """Log an info message."""
        print(f"{Colors.CYAN}INFO:{Colors.NC} {message}")
    
    def _success(self, message: str):
        """Log a success message."""
        print(f"{Colors.GREEN}✓{Colors.NC} {message}")
    
    def _warn(self, message: str):
        """Log a warning message."""
        print(f"{Colors.YELLOW}WARNING:{Colors.NC} {message}", file=sys.stderr)
    
    def _error_exit(self, message: str, exit_code: int = 1):
        """Log an error message and exit."""
        print(f"{Colors.RED}ERROR:{Colors.NC} {message}", file=sys.stderr)
        sys.exit(exit_code)
    
    def _fetch_webacls(self) -> List[Dict]:
        """
        Fetch all WebACLs in the region.
        
        Returns:
            List of WebACL dictionaries
        """
        try:
            response = self.wafv2_client.list_web_acls(Scope='REGIONAL')
            webacls = response.get('WebACLs', [])
            
            if not webacls:
                self._warn(f"No WebACLs found in region {self.region}")
            
            return webacls
            
        except ClientError as e:
            self._error_exit(f"Failed to fetch WebACLs: {e}", exit_code=4)
    
    def _fetch_webacl_rules(self, webacl_id: str, webacl_name: str) -> List[str]:
        """
        Fetch rules for a specific WebACL.
        
        Args:
            webacl_id: WebACL ID
            webacl_name: WebACL Name
            
        Returns:
            List of rule names
        """
        try:
            response = self.wafv2_client.get_web_acl(
                Scope='REGIONAL',
                Id=webacl_id,
                Name=webacl_name
            )
            rules = response.get('WebACL', {}).get('Rules', [])
            return [rule['Name'] for rule in rules]
            
        except ClientError as e:
            self._warn(f"Failed to fetch rules for WebACL {webacl_name}: {e}")
            return []
    
    def _check_rules(self, rules: List[str]) -> Dict[str, bool]:
        """
        Check which recommended rules are present.
        
        Args:
            rules: List of rule names
            
        Returns:
            Dictionary with rule presence status
        """
        return {
            'common': 'AWSManagedRulesCommonRuleSet' in rules,
            'linux': 'AWSManagedRulesLinuxRuleSet' in rules,
            'badinput': 'AWSManagedRulesKnownBadInputsRuleSet' in rules,
            'sqli': 'AWSManagedRulesSQLiRuleSet' in rules,
            'iprep': 'AWSManagedRulesAmazonIpReputationList' in rules,
            'anon': 'AWSManagedRulesAnonymousIpList' in rules,
        }
    
    def coverage(self, output_format: str = 'text'):
        """
        Display coverage matrix of AWS managed rules across all WebACLs.
        
        Args:
            output_format: Output format ('text' or 'csv')
        """
        self._print_header("WAF Rule Coverage Matrix")
        self._info("Fetching WebACLs...")
        
        webacls = self._fetch_webacls()
        if not webacls:
            return
        
        self._success(f"Found {len(webacls)} WebACLs. Building coverage matrix...")
        print()
        
        if output_format == 'csv':
            self._coverage_csv(webacls)
        else:
            self._coverage_text(webacls)
    
    def _coverage_csv(self, webacls: List[Dict]):
        """Generate CSV coverage report."""
        print("WebACL Name,Common Rule Set,Linux Rule Set,Bad Inputs Rule Set,SQLi Rule Set,IP Reputation List")
        
        for webacl in webacls:
            name = webacl['Name']
            rules = self._fetch_webacl_rules(webacl['Id'], name)
            status = self._check_rules(rules)
            
            print(f"{name},"
                  f"{'Yes' if status['common'] else 'No'},"
                  f"{'Yes' if status['linux'] else 'No'},"
                  f"{'Yes' if status['badinput'] else 'No'},"
                  f"{'Yes' if status['sqli'] else 'No'},"
                  f"{'Yes' if status['iprep'] else 'No'}")
    
    def _coverage_text(self, webacls: List[Dict]):
        """Generate text coverage report."""
        # Print header
        print(f"{'WebACL Name':<40} | {'Common':<8} | {'Linux':<8} | {'BadInput':<8} | {'SQLi':<8} | {'IpRep':<8}")
        print(f"{'-'*40}-+-{'-'*8}-+-{'-'*8}-+-{'-'*8}-+-{'-'*8}-+-{'-'*8}")
        
        for webacl in webacls:
            name = webacl['Name']
            rules = self._fetch_webacl_rules(webacl['Id'], name)
            status = self._check_rules(rules)
            
            print(f"{name:<40} | "
                  f"{'✅' if status['common'] else '❌':<8} | "
                  f"{'✅' if status['linux'] else '❌':<8} | "
                  f"{'✅' if status['badinput'] else '❌':<8} | "
                  f"{'✅' if status['sqli'] else '❌':<8} | "
                  f"{'✅' if status['iprep'] else '❌':<8}")
        
        print()
        self._print_separator("─")
        print()
        print(f"{Colors.BOLD}Legend:{Colors.NC}")
        print("  Common   = AWSManagedRulesCommonRuleSet (OWASP Top-10)")
        print("  Linux    = AWSManagedRulesLinuxRuleSet (RCE protection)")
        print("  BadInput = AWSManagedRulesKnownBadInputsRuleSet")
        print("  SQLi     = AWSManagedRulesSQLiRuleSet")
        print("  IpRep    = AWSManagedRulesAmazonIpReputationList")
        print()
        print("  ✅ = Enabled    ❌ = Missing")
        print()
    
    def audit(self):
        """Audit all WebACLs for security compliance."""
        self._print_header("WAF Security Audit - Missing High-Priority Rules")
        self._info("Fetching WebACLs...")
        
        webacls = self._fetch_webacls()
        if not webacls:
            return
        
        self._success(f"Found {len(webacls)} WebACLs. Starting audit...")
        print()
        
        stats = {'total': 0, 'at_risk': 0, 'partial': 0, 'protected': 0}
        
        for idx, webacl in enumerate(webacls, 1):
            stats['total'] += 1
            name = webacl['Name']
            rules = self._fetch_webacl_rules(webacl['Id'], name)
            status = self._check_rules(rules)
            
            # Count missing rules by priority
            missing_high = sum(1 for r in ['common', 'linux'] if not status[r])
            missing_medium = sum(1 for r in ['badinput', 'sqli', 'iprep'] if not status[r])
            
            # Determine risk level
            if missing_high > 0:
                stats['at_risk'] += 1
                print(f"{Colors.RED}⚠  [{idx}/{len(webacls)}] {name} - AT RISK{Colors.NC}")
                print(f"   └─ Missing {missing_high} high-priority + {missing_medium} medium-priority rules:")
                
                if not status['common']:
                    print(f"      {Colors.RED}✗ HIGH{Colors.NC}   AWSManagedRulesCommonRuleSet (OWASP Top-10)")
                if not status['linux']:
                    print(f"      {Colors.RED}✗ HIGH{Colors.NC}   AWSManagedRulesLinuxRuleSet (RCE protection)")
                if not status['badinput']:
                    print(f"      {Colors.YELLOW}✗ MEDIUM{Colors.NC} AWSManagedRulesKnownBadInputsRuleSet")
                if not status['sqli']:
                    print(f"      {Colors.YELLOW}✗ MEDIUM{Colors.NC} AWSManagedRulesSQLiRuleSet")
                if not status['iprep']:
                    print(f"      {Colors.YELLOW}✗ MEDIUM{Colors.NC} AWSManagedRulesAmazonIpReputationList")
                if not status['anon']:
                    print(f"      {Colors.BLUE}ℹ OPTIONAL{Colors.NC} AWSManagedRulesAnonymousIpList (may impact legitimate users)")
                print()
                
            elif missing_medium > 0:
                stats['partial'] += 1
                print(f"{Colors.YELLOW}⚡ [{idx}/{len(webacls)}] {name} - PARTIAL PROTECTION{Colors.NC}")
                print(f"   └─ Has high-priority rules, missing {missing_medium} medium-priority:")
                
                if not status['badinput']:
                    print(f"      {Colors.YELLOW}✗{Colors.NC} AWSManagedRulesKnownBadInputsRuleSet")
                if not status['sqli']:
                    print(f"      {Colors.YELLOW}✗{Colors.NC} AWSManagedRulesSQLiRuleSet")
                if not status['iprep']:
                    print(f"      {Colors.YELLOW}✗{Colors.NC} AWSManagedRulesAmazonIpReputationList")
                if not status['anon']:
                    print(f"      {Colors.BLUE}ℹ OPTIONAL{Colors.NC} AWSManagedRulesAnonymousIpList")
                print()
                
            else:
                stats['protected'] += 1
                print(f"{Colors.GREEN}✓  [{idx}/{len(webacls)}] {name} - FULLY PROTECTED{Colors.NC}")
                if not status['anon']:
                    print(f"      {Colors.BLUE}ℹ{Colors.NC}  Optional: AWSManagedRulesAnonymousIpList not enabled")
        
        # Print summary
        print()
        self._print_separator()
        
        total = stats['total']
        protected_pct = (stats['protected'] * 100 // total) if total > 0 else 0
        partial_pct = (stats['partial'] * 100 // total) if total > 0 else 0
        at_risk_pct = (stats['at_risk'] * 100 // total) if total > 0 else 0
        
        print(f"{Colors.BOLD}Summary:{Colors.NC}")
        print(f"  Total WebACLs:           {total}")
        print(f"  {Colors.GREEN}Fully Protected:{Colors.NC}         {stats['protected']} ({protected_pct}%)")
        print(f"  {Colors.YELLOW}Partial Protection:{Colors.NC}      {stats['partial']} ({partial_pct}%)")
        print(f"  {Colors.RED}At Risk:{Colors.NC}                 {stats['at_risk']} ({at_risk_pct}%) - Missing HIGH-priority rules")
        print()
        print(f"{Colors.BOLD}Recommended Rule Priority:{Colors.NC}")
        print(f"  {Colors.RED}HIGH{Colors.NC}     AWSManagedRulesCommonRuleSet, AWSManagedRulesLinuxRuleSet")
        print(f"  {Colors.YELLOW}MEDIUM{Colors.NC}   AWSManagedRulesKnownBadInputsRuleSet, SQLiRuleSet, IpReputationList")
        print(f"  {Colors.BLUE}OPTIONAL{Colors.NC} AWSManagedRulesAnonymousIpList (may block legitimate users)")
        print()
        print(f"{Colors.BOLD}Next Steps:{Colors.NC}")
        print("  1. Enable HIGH-priority rules in COUNT mode first (observe for 7 days)")
        print("  2. Promote to BLOCK mode if no false positives detected")
        print("  3. Enable MEDIUM-priority rules incrementally")
        print("  4. Evaluate OPTIONAL rules based on business requirements")
        self._print_separator()
        print()
    
    def dump(self):
        """Dump complete rule configurations for all WebACLs."""
        self._print_header("WAF Rules Dump - All Configurations")
        self._info("Fetching WebACLs...")
        
        webacls = self._fetch_webacls()
        if not webacls:
            return
        
        self._success(f"Found {len(webacls)} WebACLs. Dumping configurations...")
        print()
        
        for idx, webacl in enumerate(webacls, 1):
            name = webacl['Name']
            webacl_id = webacl['Id']
            
            self._print_separator("─", 50)
            print(f"{Colors.BOLD}WebACL [{idx}/{len(webacls)}]: {name}{Colors.NC}")
            print(f"ID: {webacl_id}")
            self._print_separator("─", 50)
            
            rules = self._fetch_webacl_rules(webacl_id, name)
            
            if not rules:
                print(f"  {Colors.YELLOW}(No rules configured){Colors.NC}")
            else:
                for rule_idx, rule in enumerate(rules, 1):
                    if rule.startswith('AWSManaged'):
                        print(f"  [{rule_idx}] {Colors.GREEN}AWS MANAGED:{Colors.NC} {rule}")
                    else:
                        print(f"  [{rule_idx}] {Colors.CYAN}CUSTOM:{Colors.NC} {rule}")
            
            print()
        
        self._print_separator()
    
    def list_webacls(self):
        """List all WebACLs with basic information."""
        self._print_header("Available WebACLs")
        self._info("Fetching WebACLs...")
        
        webacls = self._fetch_webacls()
        if not webacls:
            return
        
        self._success(f"Found {len(webacls)} WebACLs")
        print()
        
        for webacl in webacls:
            print(f"  • {webacl['Name']}")
            print(f"    ID: {webacl['Id']}")
            print(f"    ARN: {webacl['ARN']}")
            print()
        
        self._print_separator()
    
    def metrics(self, webacl_name: str, days: int = 7):
        """
        Display CloudWatch metrics for a specific WebACL.
        
        Args:
            webacl_name: Name of the WebACL
            days: Number of days to retrieve metrics for
        """
        self._print_header(f"WAF Metrics - {webacl_name}")
        self._info(f"Fetching CloudWatch metrics for last {days} days...")
        print()
        
        # Find the WebACL
        webacls = self._fetch_webacls()
        webacl = next((w for w in webacls if w['Name'] == webacl_name), None)
        
        if not webacl:
            self._error_exit(f"WebACL '{webacl_name}' not found in region {self.region}")
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        
        metrics = [
            ('AllowedRequests', 'Allowed Requests'),
            ('BlockedRequests', 'Blocked Requests'),
            ('CountedRequests', 'Counted Requests'),
        ]
        
        try:
            for metric_name, display_name in metrics:
                response = self.cloudwatch_client.get_metric_statistics(
                    Namespace='AWS/WAFV2',
                    MetricName=metric_name,
                    Dimensions=[
                        {'Name': 'Region', 'Value': self.region},
                        {'Name': 'Rule', 'Value': 'ALL'},
                        {'Name': 'WebACL', 'Value': webacl_name},
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # 1 day
                    Statistics=['Sum']
                )
                
                datapoints = response.get('Datapoints', [])
                total = sum(dp['Sum'] for dp in datapoints)
                
                print(f"{Colors.BOLD}{display_name}:{Colors.NC} {total:,.0f}")
            
            print()
            self._print_separator()
            
        except ClientError as e:
            self._error_exit(f"Failed to fetch CloudWatch metrics: {e}", exit_code=4)
    
    def available(self):
        """List all available AWS managed rule groups with recommendations."""
        self._print_header("Available AWS Managed Rule Groups")
        self._info("Fetching available AWS managed rule groups...")
        print()
        
        try:
            response = self.wafv2_client.list_available_managed_rule_groups(
                Scope='REGIONAL'
            )
            
            rule_groups = [
                rg for rg in response.get('ManagedRuleGroups', [])
                if rg.get('VendorName') == 'AWS'
            ]
            
            # Create lookup dictionary
            rules_dict = {rg['Name']: rg['Description'] for rg in rule_groups}
            
            # Display HIGH priority rules
            self._print_separator("=", 67)
            print(f"{Colors.RED}{Colors.BOLD}🔴 HIGH PRIORITY - Recommended for All WebACLs{Colors.NC}")
            self._print_separator("=", 67)
            
            for rule in HIGH_PRIORITY_RULES:
                if rule in rules_dict:
                    print()
                    print(f"{Colors.RED}• {rule}{Colors.NC}")
                    print(f"  └─ {rules_dict[rule]}")
            
            # Display MEDIUM priority rules
            print()
            self._print_separator("=", 67)
            print(f"{Colors.YELLOW}{Colors.BOLD}🟡 MEDIUM PRIORITY - Defense-in-Depth{Colors.NC}")
            self._print_separator("=", 67)
            
            for rule in MEDIUM_PRIORITY_RULES:
                if rule in rules_dict:
                    print()
                    print(f"{Colors.YELLOW}• {rule}{Colors.NC}")
                    print(f"  └─ {rules_dict[rule]}")
            
            # Display OPTIONAL rules
            print()
            self._print_separator("=", 67)
            print(f"{Colors.BLUE}{Colors.BOLD}🔵 OPTIONAL - Evaluate Based on Business Requirements{Colors.NC}")
            self._print_separator("=", 67)
            
            for rule in OPTIONAL_RULES:
                if rule in rules_dict:
                    print()
                    print(f"{Colors.BLUE}• {rule}{Colors.NC}")
                    print(f"  └─ {rules_dict[rule]}")
                    print("  ⚠️  May block legitimate users behind VPNs/TOR")
            
            # Display OTHER available rules
            print()
            self._print_separator("=", 67)
            print(f"{Colors.BOLD}ℹ️  OTHER AVAILABLE RULES (Not Currently Recommended){Colors.NC}")
            self._print_separator("=", 67)
            print()
            print("The following AWS managed rules are available but not in our")
            print("standard recommendation (specialized use cases only):")
            print()
            
            all_recommended = set(HIGH_PRIORITY_RULES + MEDIUM_PRIORITY_RULES + OPTIONAL_RULES)
            
            for name, desc in rules_dict.items():
                if name not in all_recommended:
                    print(f"• {name}")
                    print(f"  └─ {desc}")
                    print()
            
            self._print_separator()
            print()
            print(f"{Colors.BOLD}Note:{Colors.NC} Rule availability may vary by region. Showing results for: {self.region}")
            print()
            
        except ClientError as e:
            self._error_exit(f"Failed to fetch managed rule groups: {e}", exit_code=4)


def check_python_version():
    """Check if Python version meets minimum requirements."""
    if sys.version_info < MIN_PYTHON_VERSION:
        print(
            f"ERROR: Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher is required. "
            f"Current version: {sys.version}",
            file=sys.stderr
        )
        sys.exit(2)


def main():
    """Main entry point."""
    check_python_version()
    
    parser = argparse.ArgumentParser(
        description='WAF Observer - Read-Only WAF Observability Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s coverage --profile my-readonly-profile --region us-east-1
  %(prog)s coverage --profile my-profile --format csv > coverage.csv
  %(prog)s audit --profile my-readonly-profile --region us-west-2
  %(prog)s metrics --webacl my-webacl --profile my-profile
  %(prog)s available --profile my-profile --region eu-west-1

Exit Codes:
  0 - Success
  1 - General error
  2 - Missing dependencies
  3 - Invalid arguments
  4 - AWS API error
        """
    )
    
    parser.add_argument(
        'mode',
        choices=['coverage', 'audit', 'dump', 'list', 'metrics', 'available'],
        help='Operation mode'
    )
    parser.add_argument(
        '--profile',
        default=os.environ.get('AWS_PROFILE', 'default'),
        help='AWS profile (default: default or $AWS_PROFILE)'
    )
    parser.add_argument(
        '--region',
        default=os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'),
        help='AWS region (default: us-east-1 or $AWS_DEFAULT_REGION)'
    )
    parser.add_argument(
        '--webacl',
        help='WebACL name (required for metrics mode)'
    )
    parser.add_argument(
        '--format',
        choices=['text', 'csv'],
        default='text',
        help='Output format for coverage mode (default: text)'
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {VERSION}'
    )
    
    args = parser.parse_args()
    
    # Validate metrics mode requires --webacl
    if args.mode == 'metrics' and not args.webacl:
        parser.error("--webacl is required for metrics mode")
    
    # Initialize observer
    observer = WAFObserver(args.profile, args.region)
    observer._initialize_session()
    
    # Execute requested mode
    try:
        if args.mode == 'coverage':
            observer.coverage(args.format)
        elif args.mode == 'audit':
            observer.audit()
        elif args.mode == 'dump':
            observer.dump()
        elif args.mode == 'list':
            observer.list_webacls()
        elif args.mode == 'metrics':
            observer.metrics(args.webacl)
        elif args.mode == 'available':
            observer.available()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}ERROR:{Colors.NC} Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
