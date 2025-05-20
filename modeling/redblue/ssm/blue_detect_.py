#!/usr/bin/env python3
"""
AWS SSM Security Scanner Module
-------------------------------
A comprehensive tool for detecting potential SSM agent hijacking and abuse.

# Basic scan in default region with default profile
python ssm_security_scanner.py

# Scan specific region with specific profile
python ssm_security_scanner.py --region us-east-1 --profile security

# Scan with SSM agent integrity verification on all instances
python ssm_security_scanner.py --verify-agents

# Scan specific instances for SSM agent integrity
python ssm_security_scanner.py --verify-agents --instance-ids i-1234567890abcdef0 i-0987654321fedcba0

# Scan with detailed debugging output
python ssm_security_scanner.py --debug

# Scan last 30 days of activity
python ssm_security_scanner.py --days 30

"""

import boto3
import json
import re
import datetime
import os
import hashlib
import pandas as pd
import logging
import argparse
from collections import defaultdict
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ssm_security')

class SSMSecurityScanner:
    """Comprehensive SSM security scanning tool"""
    
    def __init__(self, region=None, profile=None, days_to_analyze=7):
        """
        Initialize the SSM Security Scanner
        
        Args:
            region: AWS region to scan
            profile: AWS profile to use
            days_to_analyze: Number of days of history to analyze
        """
        self.region = region
        self.days_to_analyze = days_to_analyze
        
        # Initialize session
        if profile:
            self.session = boto3.Session(profile_name=profile, region_name=region)
        else:
            self.session = boto3.Session(region_name=region)
            
        # Initialize AWS clients
        self.ssm = self.session.client('ssm')
        self.cloudtrail = self.session.client('cloudtrail')
        self.logs = self.session.client('logs')
        self.ec2 = self.session.client('ec2')
        self.iam = self.session.client('iam')
        
        # Calculate time range for analysis
        self.end_time = datetime.datetime.utcnow()
        self.start_time = self.end_time - datetime.timedelta(days=days_to_analyze)
        
        # Known good hashes for SSM agent binaries
        # These should be populated with the actual hashes for your environment
        self.known_good_agent_hashes = [
            # Example hashes - replace with actual values from your environment
            "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0",
            "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d"
        ]
    
    def scan_all(self):
        """Run all available security scans"""
        logger.info("Starting comprehensive SSM security scan")
        
        results = {
            "cloudtrail_anomalies": self.analyze_cloudtrail_activity(),
            "suspicious_documents": self.scan_ssm_documents(),
            "iam_overprivileged": self.check_iam_permissions(),
            "network_anomalies": self.analyze_ssm_network_traffic(),
            "parameter_store_abuse": self.check_parameter_store(),
            "maintenance_windows": self.check_maintenance_windows(),
            "ssm_associations": self.check_suspicious_associations()
        }
        
        return results
    
    def analyze_cloudtrail_activity(self):
        """Analyze CloudTrail for suspicious SSM activity"""
        logger.info("Analyzing CloudTrail for suspicious SSM activity")
        
        # Track patterns
        user_activity = defaultdict(lambda: defaultdict(int))
        document_usage = defaultdict(lambda: defaultdict(int))
        ip_activity = defaultdict(lambda: defaultdict(int))
        suspicious_activity = []
        
        # Look up events
        paginator = self.cloudtrail.get_paginator('lookup_events')
        try:
            for page in paginator.paginate(
                LookupAttributes=[{'AttributeKey': 'EventSource', 'AttributeValue': 'ssm.amazonaws.com'}],
                StartTime=self.start_time,
                EndTime=self.end_time
            ):
                for event in page['Events']:
                    event_name = event['EventName']
                    username = event.get('Username', 'Unknown')
                    
                    # Get cloud trail event details
                    cloud_trail_event = json.loads(event['CloudTrailEvent'])
                    source_ip = cloud_trail_event['sourceIPAddress']
                    
                    user_activity[username][event_name] += 1
                    ip_activity[source_ip][event_name] += 1
                    
                    # Check for document usage
                    if event_name == 'SendCommand':
                        request_parameters = cloud_trail_event.get('requestParameters', {})
                        document_name = request_parameters.get('documentName', 'Unknown')
                        document_usage[document_name][username] += 1
                        
                        # Check command content for suspicious patterns
                        if document_name == 'AWS-RunShellScript':
                            commands = request_parameters.get('parameters', {}).get('commands', [])
                            for command in commands:
                                if isinstance(command, str):
                                    # Check for suspicious patterns
                                    if (re.search(r'(curl|wget).*\s*\|\s*(bash|sh)', command) or
                                        re.search(r'base64\s+(-d|--decode)', command) or
                                        'nc -e' in command or 'netcat -e' in command):
                                        
                                        suspicious_activity.append({
                                            'type': 'suspicious_command',
                                            'username': username,
                                            'sourceIp': source_ip,
                                            'documentName': document_name,
                                            'command': command,
                                            'timestamp': cloud_trail_event.get('eventTime')
                                        })
            
            # Detect anomalies
            for user, actions in user_activity.items():
                if 'SendCommand' in actions and actions['SendCommand'] > 20:
                    suspicious_activity.append({
                        'type': 'high_command_volume',
                        'username': user,
                        'commandCount': actions['SendCommand']
                    })
                
                if 'CreateDocument' in actions and actions['CreateDocument'] > 3:
                    suspicious_activity.append({
                        'type': 'multiple_document_creation',
                        'username': user,
                        'documentCount': actions['CreateDocument']
                    })
                    
                if 'DeleteDocument' in actions and actions['DeleteDocument'] > 3:
                    suspicious_activity.append({
                        'type': 'multiple_document_deletion',
                        'username': user,
                        'deletionCount': actions['DeleteDocument']
                    })
            
            # Check for unusual document usage
            known_docs = {}
            response = self.ssm.list_documents(
                Filters=[{'Key': 'Owner', 'Values': ['Amazon', 'Self']}]
            )
            for doc in response['DocumentIdentifiers']:
                known_docs[doc['Name']] = doc['Owner']
                
            for doc_name, users in document_usage.items():
                if doc_name not in known_docs and sum(users.values()) > 5:
                    suspicious_activity.append({
                        'type': 'non_standard_document_usage',
                        'documentName': doc_name,
                        'usageCount': sum(users.values()),
                        'users': list(users.keys())
                    })
                    
            return suspicious_activity
                
        except Exception as e:
            logger.error(f"Error analyzing CloudTrail: {str(e)}")
            return []
            
    def scan_ssm_documents(self):
        """Scan SSM documents for security issues"""
        logger.info("Scanning SSM documents for security issues")
        suspicious_documents = []
        
        try:
            # Get all documents owned by the account
            paginator = self.ssm.get_paginator('list_documents')
            for page in paginator.paginate(
                Filters=[{'Key': 'Owner', 'Values': ['Self']}]
            ):
                documents = page.get('DocumentIdentifiers', [])
                
                for doc in documents:
                    doc_name = doc['Name']
                    logger.debug(f"Scanning document: {doc_name}")
                    
                    # Get document content
                    try:
                        doc_response = self.ssm.get_document(
                            Name=doc_name,
                            DocumentVersion='$LATEST'
                        )
                        
                        content = doc_response['Content']
                        issues = self._scan_document_content(content, doc_name)
                        
                        if issues:
                            suspicious_documents.append({
                                'documentName': doc_name,
                                'documentType': doc.get('DocumentType', 'Unknown'),
                                'issues': issues
                            })
                    except Exception as e:
                        logger.warning(f"Error getting document {doc_name}: {str(e)}")
                        
            return suspicious_documents
                
        except Exception as e:
            logger.error(f"Error scanning SSM documents: {str(e)}")
            return []
            
    def _scan_document_content(self, document_content, doc_name):
        """Scan an individual SSM document for security issues"""
        issues = []
        
        try:
            content = json.loads(document_content)
            
            # Check for shell script execution
            if "mainSteps" in content:
                for step in content["mainSteps"]:
                    if step.get("action") == "aws:runShellScript":
                        inputs = step.get("inputs", {})
                        commands = inputs.get("runCommand", [])
                        
                        for cmd in commands:
                            # Check for suspicious command patterns
                            if isinstance(cmd, str):
                                if re.search(r'(curl|wget)\s+.*\s*\|\s*(bash|sh)', cmd):
                                    issues.append(f"Suspicious pipe to shell: {cmd}")
                                
                                if re.search(r'base64\s+--decode', cmd) or 'base64 -d' in cmd:
                                    issues.append(f"Base64 decoding detected: {cmd}")
                                
                                if re.search(r'(nc|netcat|ncat).+\s+-e\s+', cmd):
                                    issues.append(f"Possible reverse shell: {cmd}")
                                
                                if 'eval' in cmd and ('$(' in cmd or '`' in cmd):
                                    issues.append(f"Suspicious eval construct: {cmd}")
                    
                    # Check for AWS API calls that could be used for privilege escalation
                    if step.get("action") == "aws:executeAwsApi":
                        inputs = step.get("inputs", {})
                        service = inputs.get("Service", "")
                        api = inputs.get("Api", "")
                        
                        if service.lower() == "iam":
                            issues.append(f"Document contains IAM API calls: {api}")
                        
                        if service.lower() == "sts" and api.lower() == "assumerolewithwebidentity":
                            issues.append("Document contains STS AssumeRoleWithWebIdentity call")
            
            # Check for suspicious parameter patterns
            if "parameters" in content:
                for param_name, param_details in content["parameters"].items():
                    if param_details.get("type") == "String" and param_name.lower() in ["command", "script", "payload"]:
                        issues.append(f"Potentially dangerous parameter name: {param_name}")
                        
            return issues
                        
        except Exception as e:
            logger.warning(f"Error parsing document content for {doc_name}: {str(e)}")
            return [f"Error parsing document: {str(e)}"]
    
    def check_iam_permissions(self):
        """Check for overly permissive IAM permissions related to SSM"""
        logger.info("Checking for overly permissive IAM permissions")
        risky_policies = []
        
        try:
            # Get all roles
            paginator = self.iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_name = role['RoleName']
                    
                    # Check if role has EC2 as trusted entity (common for SSM-managed instances)
                    assume_role_policy = json.loads(role['AssumeRolePolicyDocument'])
                    is_ec2_role = False
                    
                    for statement in assume_role_policy.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            principal = statement.get('Principal', {})
                            if principal.get('Service') == 'ec2.amazonaws.com':
                                is_ec2_role = True
                                break
                    
                    if not is_ec2_role:
                        continue
                        
                    # Get attached policies
                    attached_policies = self.iam.list_attached_role_policies(RoleName=role_name)
                    
                    # Check each policy
                    for policy in attached_policies['AttachedPolicies']:
                        policy_arn = policy['PolicyArn']
                        
                        # Skip AWS managed policies for now (could be included in more comprehensive scan)
                        if 'arn:aws:iam::aws:policy/' in policy_arn:
                            continue
                            
                        policy_version = self.iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                        policy_document = self.iam.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=policy_version
                        )['PolicyVersion']['Document']
                        
                        # Check for overly permissive SSM permissions
                        for statement in policy_document.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                actions = statement.get('Action', [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                    
                                for action in actions:
                                    if action == 'ssm:*' or action == '*':
                                        risky_policies.append({
                                            'roleName': role_name,
                                            'policyName': policy['PolicyName'],
                                            'policyArn': policy_arn,
                                            'issue': f"Overly permissive SSM permissions: {action}"
                                        })
                                        
            # Also check inline policies
            paginator = self.iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_name = role['RoleName']
                    
                    # Get inline policies
                    inline_policies = self.iam.list_role_policies(RoleName=role_name)
                    
                    for policy_name in inline_policies['PolicyNames']:
                        policy_document = self.iam.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name
                        )['PolicyDocument']
                        
                        # Check for overly permissive SSM permissions
                        for statement in policy_document.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                actions = statement.get('Action', [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                    
                                for action in actions:
                                    if action == 'ssm:*' or action == '*':
                                        risky_policies.append({
                                            'roleName': role_name,
                                            'policyName': policy_name,
                                            'policyType': 'inline',
                                            'issue': f"Overly permissive SSM permissions: {action}"
                                        })
                                        
            return risky_policies
                                        
        except Exception as e:
            logger.error(f"Error checking IAM permissions: {str(e)}")
            return []
            
    def analyze_ssm_network_traffic(self):
        """Analyze VPC Flow Logs for suspicious SSM traffic patterns"""
        logger.info("Analyzing VPC Flow Logs for suspicious SSM traffic patterns")
        
        try:
            # Get all VPC Flow Log groups
            response = self.logs.describe_log_groups(
                logGroupNamePrefix='/aws/vpc/flowlogs'
            )
            
            log_groups = [group['logGroupName'] for group in response.get('logGroups', [])]
            if not log_groups:
                logger.warning("No VPC Flow Log groups found")
                return []
            
            # Get SSM endpoints
            ssm_endpoints = []
            
            # Get standard service endpoints
            response = self.ec2.describe_vpc_endpoints(
                Filters=[{'Name': 'service-name', 'Values': ['com.amazonaws.*.ssm']}]
            )
            for endpoint in response.get('VpcEndpoints', []):
                for dns in endpoint.get('DnsEntries', []):
                    ssm_endpoints.append(dns.get('DnsName'))
            
            # Add standard AWS SSM endpoints for regions
            aws_regions = self.session.get_available_regions('ssm')
            for aws_region in aws_regions:
                ssm_endpoints.append(f"ssm.{aws_region}.amazonaws.com")
            
            # Prepare query
            ssm_endpoint_query = " or ".join([f"dstAddr LIKE '{endpoint}'" for endpoint in ssm_endpoints])
            query = f"""
            filter (dstPort = 443 and ({ssm_endpoint_query})) or 
                   (srcPort = 443 and ({ssm_endpoint_query.replace('dstAddr', 'srcAddr')}))
            | stats 
                sum(bytes) as bytes,
                count() as flowCount
                by srcAddr, dstAddr, srcPort, dstPort, protocol, action, accountId, instance_id
            | sort bytes desc
            """
            
            # Execute query
            results = []
            for log_group in log_groups:
                try:
                    query_response = self.logs.start_query(
                        logGroupName=log_group,
                        startTime=int(self.start_time.timestamp()),
                        endTime=int(self.end_time.timestamp()),
                        queryString=query
                    )
                    
                    query_id = query_response['queryId']
                    
                    # Wait for query to complete
                    response = None
                    while response is None or response['status'] == 'Running':
                        response = self.logs.get_query_results(queryId=query_id)
                        if response['status'] == 'Running':
                            import time
                            time.sleep(1)
                    
                    # Process results
                    for result in response.get('results', []):
                        result_dict = {}
                        for field in result:
                            result_dict[field['field']] = field['value']
                        results.append(result_dict)
                except Exception as e:
                    logger.warning(f"Error querying {log_group}: {str(e)}")
            
            if not results:
                logger.info("No SSM traffic found in the analyzed period")
                return []
            
            # Convert to DataFrame for analysis
            df = pd.DataFrame(results)
            
            # Anomaly detection - identify instances with unusually high SSM traffic
            if 'instance_id' in df.columns and 'bytes' in df.columns:
                df['bytes'] = df['bytes'].astype(float)
                instance_traffic = df.groupby('instance_id')['bytes'].sum()
                mean_traffic = instance_traffic.mean()
                std_traffic = instance_traffic.std()
                
                anomalous_instances = instance_traffic[instance_traffic > mean_traffic + 2*std_traffic]
                
                anomalies = []
                if not anomalous_instances.empty:
                    for instance, traffic in anomalous_instances.items():
                        anomalies.append({
                            'instance_id': instance,
                            'traffic_bytes': float(traffic),
                            'avg_traffic': float(mean_traffic),
                            'threshold': float(mean_traffic + 2*std_traffic)
                        })
                
                # Optional: Generate visualization
                if len(instance_traffic) > 0:
                    plt.figure(figsize=(12, 6))
                    instance_traffic.plot(kind='bar')
                    plt.title('SSM Traffic by Instance')
                    plt.ylabel('Bytes')
                    plt.xlabel('Instance ID')
                    plt.axhline(y=mean_traffic + 2*std_traffic, color='r', linestyle='--')
                    plt.tight_layout()
                    plt.savefig('ssm_traffic_by_instance.png')
                    logger.info("Saved traffic analysis chart to ssm_traffic_by_instance.png")
                
                return anomalies
            
            return []
            
        except Exception as e:
            logger.error(f"Error analyzing SSM network traffic: {str(e)}")
            return []
    
    def check_parameter_store(self):
        """Check for suspicious SSM Parameter Store usage"""
        logger.info("Checking for suspicious Parameter Store usage")
        suspicious_parameters = []
        
        try:
            # Get parameters
            paginator = self.ssm.get_paginator('describe_parameters')
            for page in paginator.paginate():
                for param in page['Parameters']:
                    param_name = param['Name']
                    
                    # Check for suspicious patterns
                    if 'script' in param_name.lower() or 'exec' in param_name.lower() or 'command' in param_name.lower():
                        try:
                            # Get parameter value for SecureString parameters
                            if param['Type'] == 'SecureString':
                                param_value = self.ssm.get_parameter(
                                    Name=param_name,
                                    WithDecryption=True
                                )['Parameter']['Value']
                                
                                # Check if it looks like base64 encoded data
                                if re.match(r'^[A-Za-z0-9+/=]+$', param_value) and len(param_value) > 100:
                                    suspicious_parameters.append({
                                        'name': param_name,
                                        'type': param['Type'],
                                        'issue': 'Possible base64-encoded payload in SecureString parameter'
                                    })
                                # Check if it contains script-like content
                                elif any(keyword in param_value for keyword in ['#!/bin', 'function ', 'eval ', ';']):
                                    suspicious_parameters.append({
                                        'name': param_name,
                                        'type': param['Type'],
                                        'issue': 'Parameter contains script-like content'
                                    })
                            else:
                                suspicious_parameters.append({
                                    'name': param_name,
                                    'type': param['Type'],
                                    'issue': 'Parameter name suggests executable content but is not encrypted'
                                })
                        except Exception as e:
                            logger.warning(f"Error inspecting parameter {param_name}: {str(e)}")
                            
            return suspicious_parameters
                            
        except Exception as e:
            logger.error(f"Error checking Parameter Store: {str(e)}")
            return []
    
    def check_maintenance_windows(self):
        """Check for suspicious SSM maintenance windows"""
        logger.info("Checking for suspicious maintenance windows")
        suspicious_windows = []
        
        try:
            # Get all maintenance windows
            paginator = self.ssm.get_paginator('describe_maintenance_windows')
            for page in paginator.paginate():
                for window in page['WindowIdentities']:
                    window_id = window['WindowId']
                    
                    # Get tasks for this window
                    try:
                        tasks = self.ssm.describe_maintenance_window_tasks(
                            WindowId=window_id
                        )
                        
                        for task in tasks.get('Tasks', []):
                            task_id = task['WindowTaskId']
                            task_type = task['TaskType']
                            
                            # Check Run Command tasks
                            if task_type == 'RUN_COMMAND':
                                targets = self.ssm.describe_maintenance_window_targets(
                                    WindowId=window_id
                                )
                                
                                # Check if targets all instances or has wide scope
                                has_wide_target = False
                                for target in targets.get('Targets', []):
                                    target_key = target.get('Key', '')
                                    target_values = target.get('Values', [])
                                    
                                    if not target_values or '*' in target_values:
                                        has_wide_target = True
                                
                                # Get task details
                                task_invocation = task.get('TaskInvocationParameters', {})
                                run_command_params = task_invocation.get('RunCommand', {})
                                document_name = run_command_params.get('DocumentName', '')
                                
                                if document_name == 'AWS-RunShellScript' and has_wide_target:
                                    suspicious_windows.append({
                                        'windowId': window_id,
                                        'taskId': task_id,
                                        'documentName': document_name,
                                        'issue': 'Maintenance window runs shell script on wide target scope'
                                    })
                                    
                                # Check parameters for suspicious commands
                                parameters = run_command_params.get('Parameters', {})
                                commands = parameters.get('commands', [])
                                
                                for cmd in commands:
                                    if re.search(r'(curl|wget)\s+.*\s*\|\s*(bash|sh)', cmd):
                                        suspicious_windows.append({
                                            'windowId': window_id,
                                            'taskId': task_id,
                                            'documentName': document_name,
                                            'issue': f'Suspicious pipe to shell: {cmd}'
                                        })
                                    
                                    if re.search(r'base64\s+(-d|--decode)', cmd):
                                        suspicious_windows.append({
                                            'windowId': window_id,
                                            'taskId': task_id,
                                            'documentName': document_name,
                                            'issue': f'Base64 decoding: {cmd}'
                                        })
                                        
                    except Exception as e:
                        logger.warning(f"Error checking tasks for window {window_id}: {str(e)}")
                        
            return suspicious_windows
                        
        except Exception as e:
            logger.error(f"Error checking maintenance windows: {str(e)}")
            return []
    
    def check_suspicious_associations(self):
        """Check for suspicious SSM associations"""
        logger.info("Checking for suspicious SSM associations")
        suspicious_associations = []
        
        try:
            # Get all associations
            paginator = self.ssm.get_paginator('list_associations')
            for page in paginator.paginate():
                for assoc in page['Associations']:
                    assoc_id = assoc['AssociationId']
                    doc_name = assoc.get('Name')
                    
                    # Check for suspicious documents
                    if doc_name == 'AWS-RunShellScript':
                        try:
                            # Get association details
                            details = self.ssm.describe_association(
                                AssociationId=assoc_id
                            )
                            
                            # Check targets
                            targets = details.get('AssociationDescription', {}).get('Targets', [])
                            has_wide_target = False
                            
                            for target in targets:
                                target_key = target.get('Key', '')
                                target_values = target.get('Values', [])
                                
                                if not target_values or '*' in target_values:
                                    has_wide_target = True
                            
                            # Check parameters
                            parameters = details.get('AssociationDescription', {}).get('Parameters', {})
                            commands = parameters.get('commands', [])
                            
                            if has_wide_target:
                                suspicious_associations.append({
                                    'associationId': assoc_id,
                                    'documentName': doc_name,
                                    'issue': 'Association runs shell script on wide target scope'
                                })
                            
                            for cmd in commands:
                                if re.search(r'(curl|wget)\s+.*\s*\|\s*(bash|sh)', cmd):
                                    suspicious_associations.append({
                                        'associationId': assoc_id,
                                        'documentName': doc_name,
                                        'issue': f'Suspicious pipe to shell: {cmd}'
                                    })
                                
                                if re.search(r'base64\s+(-d|--decode)', cmd):
                                    suspicious_associations.append({
                                        'associationId': assoc_id,
                                        'documentName': doc_name,
                                        'issue': f'Base64 decoding: {cmd}'
                                    })
                                    
                            # Check schedules
                            schedule = details.get('AssociationDescription', {}).get('ScheduleExpression')
                            
                            if schedule and 'cron(' in schedule.lower():
                                # Check for unusual timing (e.g., night execution)
                                cron_match = re.search(r'cron\(([^)]+)\)', schedule)
                                if cron_match:
                                    cron_parts = cron_match.group(1).split()
                                    if len(cron_parts) >= 2:
                                        hour = cron_parts[1]
                                        # Check for night hours (0-5)
                                        if hour in ['0', '1', '2', '3', '4', '5'] or hour.startswith('0-'):
                                            suspicious_associations.append({
                                                'associationId': assoc_id,
                                                'documentName': doc_name,
                                                'schedule': schedule,
                                                'issue': 'Association scheduled for night hours'
                                            })
                                            
                        except Exception as e:
                            logger.warning(f"Error checking association {assoc_id}: {str(e)}")
                            
            return suspicious_associations
                            
        except Exception as e:
            logger.error(f"Error checking associations: {str(e)}")
            return []

    def verify_ssm_agent_integrity(self, instance_ids=None):
        """
        Create and run SSM command to verify agent integrity on instances
        
        Args:
            instance_ids: List of EC2 instance IDs to check, or None for all
            
        Returns:
            Results of agent integrity check
        """
        logger.info(f"Verifying SSM agent integrity on {'all' if instance_ids is None else len(instance_ids)} instances")
        
        # Create the integrity check command
        integrity_check_script = f"""
        #!/bin/bash
        AGENT_PATH=$(which amazon-ssm-agent)
        if [ -z "$AGENT_PATH" ]; then
          AGENT_PATH="/usr/bin/amazon-ssm-agent"
        fi

        if [ ! -f "$AGENT_PATH" ]; then
          echo "ERROR: SSM Agent binary not found"
          exit 1
        fi

        # Calculate hash
        AGENT_HASH=$(sha256sum "$AGENT_PATH" | awk '{{print $1}}')
        KNOWN_GOOD_HASHES=({' '.join(self.known_good_agent_hashes)})
        HASH_VALID=0

        for hash in "${{KNOWN_GOOD_HASHES[@]}}"; do
          if [ "$AGENT_HASH" == "$hash" ]; then
            HASH_VALID=1
            break
          fi
        done

        echo "Agent binary hash: $AGENT_HASH"
        if [ $HASH_VALID -eq 0 ]; then
          echo "WARNING: SSM Agent binary hash doesn't match known good hashes"
          echo "Possible tampering detected!"
        else
          echo "SSM Agent binary hash verification passed"
        fi

        # Check configuration file integrity
        CONFIG_FILE="/etc/amazon/ssm/amazon-ssm-agent.json"
        if [ -f "$CONFIG_FILE" ]; then
          # Check for suspicious endpoints
          grep -E "endpoint.*\.(amazonaws\.com|amazon\.com)" "$CONFIG_FILE" > /dev/null
          if [ $? -ne 0 ]; then
            echo "WARNING: Suspicious endpoint configuration in SSM Agent config"
            grep "endpoint" "$CONFIG_FILE"
          fi
        else
          echo "ERROR: SSM Agent config file not found"
        fi

        # Check for unauthorized SSM plugins
        PLUGIN_DIR="/etc/amazon/ssm/plugins"
        if [ -d "$PLUGIN_DIR" ]; then
          echo "SSM plugin files found:"
          find "$PLUGIN_DIR" -type f -exec sha256sum {{}} \;
        fi

        # Check for suspicious processes accessing SSM
        echo "Processes accessing SSM agent files:"
        lsof | grep -i ssm | grep -v "^COMMAND" || echo "No processes found accessing SSM files"
        """
        
        # Build targets
        if instance_ids is None:
            targets = [{'Key': 'InstanceIds', 'Values': ['*']}]
        else:
            targets = [{'Key': 'InstanceIds', 'Values': instance_ids}]
        
        # Run the command
        try:
            response = self.ssm.send_command(
                DocumentName='AWS-RunShellScript',
                Parameters={'commands': [integrity_check_script]},
                Targets=targets,
                MaxConcurrency='10',
                MaxErrors='100%'
            )
            
            command_id = response['Command']['CommandId']
            logger.info(f"Initiated SSM agent integrity check with command ID: {command_id}")
            
            # Wait for command to complete
            waiter = True
            results = []
            
            while waiter:
                command_invocations = self.ssm.list_command_invocations(
                    CommandId=command_id,
                    Details=True
                )
                
                all_complete = True
                for invocation in command_invocations['CommandInvocations']:
                    if invocation['Status'] in ['Pending', 'InProgress']:
                        all_complete = False
                        break
                
                if all_complete:
                    for invocation in command_invocations['CommandInvocations']:
                        instance_id = invocation['InstanceId']
                        status = invocation['Status']
                        
                        if status == 'Success':
                            output = invocation['CommandPlugins'][0]['Output']
                            
                            # Parse output for issues
                            issues = []
                            if "WARNING" in output or "ERROR" in output:
                                for line in output.splitlines():
                                    if line.startswith("WARNING") or line.startswith("ERROR"):
                                        issues.append(line)
                            
                            agent_hash = None
                            hash_match = re.search(r'Agent binary hash: ([a-f0-9]+)', output)
                            if hash_match:
                                agent_hash = hash_match.group(1)
                            
                            results.append({
                                'instanceId': instance_id,
                                'status': status,
                                'agentHash': agent_hash,
                                'issues': issues,
                                'output': output
                            })
                        else:
                            results.append({
                                'instanceId': instance_id,
                                'status': status,
                                'error': invocation.get('StatusDetails', 'Unknown error')
                            })
                    
                    waiter = False
                else:
                    import time
                    time.sleep(2)
            
            return results
            
        except Exception as e:
            logger.error(f"Error verifying SSM agent integrity: {str(e)}")
            return []
    
    def generate_report(self, results):
        """Generate a comprehensive security report"""
        logger.info("Generating security report")
        
        report = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'scan_period': {
                'start': self.start_time.isoformat(),
                'end': self.end_time.isoformat()
            },
            'findings_summary': {
                'total_findings': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0
            },
            'findings': [],
            'raw_results': results
        }
        
        # Process CloudTrail anomalies
        for anomaly in results.get('cloudtrail_anomalies', []):
            severity = 'medium'
            if anomaly.get('type') == 'suspicious_command':
                severity = 'high'
            
            report['findings'].append({
                'title': f"Suspicious SSM Activity: {anomaly.get('type', 'unknown')}",
                'severity': severity,
                'details': anomaly,
                'recommendation': "Investigate user activity and validate whether commands are authorized"
            })
            report['findings_summary']['total_findings'] += 1
            report['findings_summary'][f"{severity}_severity"] += 1
        
        # Process suspicious documents
        for doc in results.get('suspicious_documents', []):
            report['findings'].append({
                'title': f"Suspicious SSM Document: {doc.get('documentName', 'unknown')}",
                'severity': 'high',
                'details': doc,
                'recommendation': "Review document content and delete if unauthorized"
            })
            report['findings_summary']['total_findings'] += 1
            report['findings_summary']['high_severity'] += 1
        
        # Process overprivileged IAM
        for policy in results.get('iam_overprivileged', []):
            report['findings'].append({
                'title': f"Overly Permissive IAM Policy: {policy.get('policyName', 'unknown')}",
                'severity': 'medium',
                'details': policy,
                'recommendation': "Restrict SSM permissions to least privilege"
            })
            report['findings_summary']['total_findings'] += 1
            report['findings_summary']['medium_severity'] += 1
        
        # Process network anomalies
        for anomaly in results.get('network_anomalies', []):
            report['findings'].append({
                'title': f"Unusual SSM Traffic: {anomaly.get('instance_id', 'unknown')}",
                'severity': 'low',
                'details': anomaly,
                'recommendation': "Investigate instance for unauthorized SSM activity"
            })
            report['findings_summary']['total_findings'] += 1
            report['findings_summary']['low_severity'] += 1
        
        # Process parameter store abuse
        for param in results.get('parameter_store_abuse', []):
            report['findings'].append({
                'title': f"Suspicious Parameter: {param.get('name', 'unknown')}",
                'severity': 'medium',
                'details': param,
                'recommendation': "Review parameter content and delete if unauthorized"
            })
            report['findings_summary']['total_findings'] += 1
            report['findings_summary']['medium_severity'] += 1
        
        # Process maintenance windows
        for window in results.get('maintenance_windows', []):
            report['findings'].append({
                'title': f"Suspicious Maintenance Window: {window.get('windowId', 'unknown')}",
                'severity': 'medium',
                'details': window,
                'recommendation': "Review maintenance window configuration and tasks"
            })
            report['findings_summary']['total_findings'] += 1
            report['findings_summary']['medium_severity'] += 1
        
        # Process associations
        for assoc in results.get('ssm_associations', []):
            report['findings'].append({
                'title': f"Suspicious Association: {assoc.get('associationId', 'unknown')}",
                'severity': 'medium',
                'details': assoc,
                'recommendation': "Review association configuration and parameters"
            })
            report['findings_summary']['total_findings'] += 1
            report['findings_summary']['medium_severity'] += 1
        
        return report

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='AWS SSM Security Scanner')
    parser.add_argument('--region', help='AWS region to scan')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--days', type=int, default=7, help='Number of days of history to analyze')
    parser.add_argument('--output', default='ssm_security_report.json', help='Output file for report')
    parser.add_argument('--verify-agents', action='store_true', help='Verify SSM agent integrity on instances')
    parser.add_argument('--instance-ids', nargs='+', help='Specific instance IDs to check agent integrity')
    parser.add_argument('--quiet', action='store_true', help='Suppress output except for errors')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Configure logging
    if args.quiet:
        logger.setLevel(logging.ERROR)
    elif args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Initialize scanner
    scanner = SSMSecurityScanner(
        region=args.region,
        profile=args.profile,
        days_to_analyze=args.days
    )
    
    # Run scans
    results = scanner.scan_all()
    
    # Verify agent integrity if requested
    if args.verify_agents:
        agent_results = scanner.verify_ssm_agent_integrity(args.instance_ids)
        results['agent_integrity'] = agent_results
    
    # Generate report
    report = scanner.generate_report(results)
    
    # Output report
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    if not args.quiet:
        print("\nSSM Security Scan Complete")
        print("-------------------------")
        print(f"Total findings: {report['findings_summary']['total_findings']}")
        print(f"High severity: {report['findings_summary']['high_severity']}")
        print(f"Medium severity: {report['findings_summary']['medium_severity']}")
        print(f"Low severity: {report['findings_summary']['low_severity']}")
        print(f"\nDetailed report saved to: {args.output}")

if __name__ == "__main__":
    main()
