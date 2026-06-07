
# AWS CLI: Security Group Information

This guide provides useful commands and scripts to gather information about AWS Security Groups (SGs) using the AWS CLI.  
Assumption: you have AWS CLI configured with the required credentials and permissions.  

Reference: [Install AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)

---

## List All Security Groups

**Default region:**
```bash
aws ec2 describe-security-groups \
  --query 'SecurityGroups[*].GroupId' \
  --output text \
  | tr '\t' '\n'
```

**Specific region:**
```bash
aws ec2 describe-security-groups \
  --region us-east-1 \
  --query 'SecurityGroups[*].GroupId' \
  --output text \
  | tr '\t' '\n'
```

---

## List All Security Groups In Use by Instances

```bash
aws ec2 describe-instances \
  --region us-east-1 \
  --query 'Reservations[].Instances[].SecurityGroups[].GroupId' \
  --output text \
  | tr '\t' '\n'
```

---

## List Unused Security Groups

Compare all SGs against ones actually attached to EC2 instances:

```bash
comm -23 \
  <(aws ec2 describe-security-groups --region us-east-1 \
      --query 'SecurityGroups[].GroupId' --output text | tr '\t' '\n' | sort) \
  <(aws ec2 describe-instances --region us-east-1 \
      --query 'Reservations[].Instances[].SecurityGroups[].GroupId' \
      --output text | tr '\t' '\n' | sort | uniq)
```

---

## Export Security Groups to CSV

```bash
aws ec2 describe-security-groups \
  --region us-east-1 \
  --query 'SecurityGroups[*].[Description,GroupId,GroupName,OwnerId,VpcId]' \
  --output text > security-groups-us-east.csv
```

---

## Describe Each Security Group in Detail

```bash
for sg in $(aws ec2 describe-security-groups \
              --region us-east-1 \
              --query 'SecurityGroups[*].GroupId' \
              --output text | tr '\t' '\n'); do
  aws ec2 describe-security-groups \
    --region us-east-1 \
    --group-ids "$sg" \
    --output table
done
```

---

## Script: Find Unused Security Groups

This version uses `jq` to check which SGs are not attached to any ENIs (Elastic Network Interfaces).  
Note: Security groups may also be used by **RDS**, **ELB/ALB**, or **Lambda**, so additional queries may be required for full coverage.

`unused-sg.sh`:

```bash
#!/usr/bin/env bash
# Find unused AWS Security Groups.
# A group is considered unused if not attached to any network interface.
# Requires aws-cli and jq.

set -euo pipefail

TMP_ALL=/tmp/sg.all
TMP_USED=/tmp/sg.used

# All SGs
aws ec2 describe-security-groups \
  | jq -r '.SecurityGroups[] | [.GroupName, .GroupId] | @tsv' \
  | sort > "$TMP_ALL"

# SGs currently in use by ENIs
aws ec2 describe-network-interfaces \
  | jq -r '.NetworkInterfaces[].Groups[] | [.GroupName, .GroupId] | @tsv' \
  | sort -u > "$TMP_USED"

echo "Unused security groups (not attached to any ENIs):"
diff "$TMP_ALL" "$TMP_USED" | grep "^<" | cut -f2-
```

Run:

```bash
bash unused-sg.sh
```

---

## Notes

- Security Groups may be attached to resources besides EC2 instances:
  - **RDS DB instances / clusters**
  - **Elastic Load Balancers (Classic, ALB, NLB)**
  - **Elasticache**
  - **Lambda ENIs**
- For complete accuracy, check SG associations across these services, not just ENIs.
- Always review unused SGs before deleting them, especially in shared VPCs.

---

## References

- [AWS CLI: describe-security-groups](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html)  
- [AWS CLI: describe-network-interfaces](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-network-interfaces.html)  
- [Security Groups in Amazon VPC](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)  

