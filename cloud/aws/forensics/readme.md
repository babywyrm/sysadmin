# AWS Incident Response Workflow - EC2 & S3 ..beta..

## Quick Reference

**EC2**: Isolate → Snapshot → Forensics → Remediate  
**S3**: Enable logging → Preserve state → Analyze access → Contain

---

## EC2 Incident Response

### 1. Initial Triage (0-15 min)

**Assess Severity**
```bash
# Check instance metadata
aws ec2 describe-instances --instance-ids i-xxxxx \
  --query 'Reservations[0].Instances[0].[State.Name,SecurityGroups,IamInstanceProfile]'

# Review CloudTrail for suspicious API calls
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=ResourceName,AttributeValue=i-xxxxx \
  --max-results 50
```

**Document**
- Timestamp of detection
- Alert source (GuardDuty, CloudWatch, etc.)
- Instance ID, VPC, subnet
- Owner/team contact

### 2. Isolation (15-30 min)

**Option A: Network isolation (non-destructive)**
```bash
# Create forensic security group (deny all)
aws ec2 create-security-group \
  --group-name forensic-isolation-sg \
  --description "Incident response isolation" \
  --vpc-id vpc-xxxxx

# Remove all rules (implicit deny)
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxx --protocol all --port all --cidr 0.0.0.0/0

# Apply to instance
aws ec2 modify-instance-attribute \
  --instance-id i-xxxxx \
  --groups sg-forensic-isolation-id
```

**Option B: Snapshot + terminate (for active threats)**
```bash
# Tag for tracking
aws ec2 create-tags --resources i-xxxxx \
  --tags Key=IncidentID,Value=INC-2026-001 \
       Key=Status,Value=Quarantined

# Create snapshots of all volumes FIRST
VOLUMES=$(aws ec2 describe-volumes \
  --filters Name=attachment.instance-id,Values=i-xxxxx \
  --query 'Volumes[].VolumeId' --output text)

for vol in $VOLUMES; do
  aws ec2 create-snapshot --volume-id $vol \
    --description "IR snapshot INC-2026-001 $(date +%Y%m%d-%H%M%S)" \
    --tag-specifications \
      "ResourceType=snapshot,Tags=[{Key=IncidentID,Value=INC-2026-001}]"
done

# Stop instance (preserve for forensics)
aws ec2 stop-instances --instance-ids i-xxxxx
```

### 3. Preservation & Forensics (30 min - 2 hrs)

**Memory capture (if instance still running)**
```bash
# Use SSM for remote memory dump
aws ssm send-command \
  --instance-ids i-xxxxx \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["sudo yum install -y lime-dkms", 
    "sudo insmod /lib/modules/$(uname -r)/extra/lime.ko path=/tmp/memory.lime format=lime",
    "aws s3 cp /tmp/memory.lime s3://forensics-bucket/INC-2026-001/"]'
```

**Create forensic copies**
```bash
# Launch forensic instance from snapshot
SNAPSHOT_ID=$(aws ec2 describe-snapshots \
  --filters Name=tag:IncidentID,Values=INC-2026-001 \
  --query 'Snapshots[0].SnapshotId' --output text)

aws ec2 run-instances \
  --image-id ami-forensic-workstation \
  --instance-type m5.2xlarge \
  --subnet-id subnet-forensics \
  --security-group-ids sg-forensics \
  --block-device-mappings \
    "DeviceName=/dev/sdf,Ebs={SnapshotId=$SNAPSHOT_ID,DeleteOnTermination=false}" \
  --tag-specifications \
    "ResourceType=instance,Tags=[{Key=Purpose,Value=Forensics-INC-2026-001}]"
```

**Analysis checklist**
- `/var/log/` - system/application logs
- `~/.bash_history` - command history
- `/etc/crontab`, `/var/spool/cron/` - scheduled tasks
- `/tmp`, `/var/tmp` - suspicious files
- Active network connections snapshot
- Process list and binary hashes
- IAM role usage logs from CloudTrail

### 4. Containment & Eradication

**Revoke credentials**
```bash
# Revoke instance profile sessions
aws iam put-role-policy --role-name compromised-role \
  --policy-name DenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

# Rotate access keys if found
aws iam update-access-key --access-key-id AKIA... \
  --status Inactive --user-name compromised-user
```

**Clean remediation**
```bash
# Launch clean instance from trusted AMI
# Restore data from backups (not from compromised volume)
# Apply patches and hardening
# Update security groups with least privilege
```

---

## S3 Incident Response

### 1. Initial Triage

**Enable logging immediately (if not already)**
```bash
# Server access logging
aws s3api put-bucket-logging \
  --bucket compromised-bucket \
  --bucket-logging-status \
    "LoggingEnabled={TargetBucket=logging-bucket,TargetPrefix=s3-logs/compromised-bucket/}"

# Object-level logging via CloudTrail
aws cloudtrail put-event-selectors --trail-name security-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::compromised-bucket/*"]
    }]
  }]'
```

**Identify scope**
```bash
# Check bucket policy and ACLs
aws s3api get-bucket-policy --bucket compromised-bucket
aws s3api get-bucket-acl --bucket compromised-bucket
aws s3api get-public-access-block --bucket compromised-bucket

# List recent object modifications
aws s3api list-objects-v2 --bucket compromised-bucket \
  --query 'sort_by(Contents, &LastModified)[-100:].[Key,LastModified]'
```

### 2. Preservation

**Object versioning snapshot**
```bash
# Enable versioning (if not enabled)
aws s3api put-bucket-versioning \
  --bucket compromised-bucket \
  --versioning-configuration Status=Enabled

# Create inventory for point-in-time state
aws s3api put-bucket-inventory-configuration \
  --bucket compromised-bucket \
  --id incident-snapshot \
  --inventory-configuration '{
    "Destination": {
      "S3BucketDestination": {
        "Bucket": "arn:aws:s3:::forensics-bucket",
        "Format": "CSV",
        "Prefix": "inventory/INC-2026-001/"
      }
    },
    "IsEnabled": true,
    "Id": "incident-snapshot",
    "IncludedObjectVersions": "All",
    "Schedule": {"Frequency": "Daily"}
  }'

# Backup critical objects
aws s3 sync s3://compromised-bucket/ \
  s3://forensics-bucket/INC-2026-001/backup/ \
  --include "*" --storage-class GLACIER_IR
```

### 3. Containment

**Restrict access**
```bash
# Apply deny-all bucket policy (preserve for forensics)
aws s3api put-bucket-policy --bucket compromised-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "IncidentResponseDenyAll",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::compromised-bucket",
        "arn:aws:s3:::compromised-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::ACCOUNT:role/ForensicsRole"
        }
      }
    }]
  }'

# Block public access
aws s3api put-public-access-block --bucket compromised-bucket \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

### 4. Investigation

**Analyze access patterns**
```bash
# Query CloudTrail for unauthorized access
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=compromised-bucket \
  --start-time 2026-01-01T00:00:00Z \
  --query 'Events[?contains(EventName, `PutObject`) || contains(EventName, `DeleteObject`)].[EventTime,EventName,Username,SourceIPAddress]'

# Check for ransomware patterns (mass deletion/modification)
aws s3api list-object-versions --bucket compromised-bucket \
  --query 'length(DeleteMarkers[?LastModified > `2026-02-04T00:00:00.000Z`])'
```

**Check for data exfiltration**
- Review VPC Flow Logs for large S3 transfers
- Check GuardDuty findings for Exfiltration:S3/*
- Analyze CloudTrail for `GetObject` from unknown IPs
- Review access logs for unusual download patterns

### 5. Recovery

**Restore from clean backup**
```bash
# Restore specific version
aws s3api copy-object \
  --copy-source compromised-bucket/key?versionId=VERSION_ID \
  --bucket clean-bucket \
  --key restored/key

# Bulk restore from inventory
# Review and restore only validated clean objects
```

---

## Automation & Prevention

**EventBridge + Lambda auto-response**
```python
# lambda-ec2-isolate.py
import boto3

def lambda_handler(event, context):
    ec2 = boto3.client('ec2')
    instance_id = event['detail']['instance-id']
    
    # Create isolation SG
    response = ec2.create_security_group(
        GroupName=f'isolate-{instance_id}',
        Description='Auto-isolation',
        VpcId=event['detail']['vpc-id']
    )
    
    # Apply to instance
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[response['GroupId']]
    )
    
    # Tag and notify
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[{'Key': 'SecurityStatus', 'Value': 'Isolated'}]
    )
```

**Monitoring essentials**
- GuardDuty enabled (runtime threat detection)
- CloudTrail multi-region + object logging
- VPC Flow Logs to S3
- Config rules for compliance drift
- SNS alerts for critical findings

**Hardening checklist**
- IMDSv2 required on all EC2
- S3 block public access at account level
- MFA delete on S3 versioned buckets
- SCPs preventing security control changes
- Backup snapshots encrypted + cross-region
