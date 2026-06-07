## 🔧 Setup

- Install AWS CLI v2  
  ```bash
  brew install awscli   # macOS
  sudo apt-get install -y awscli  # Ubuntu / Debian
  ```
- Install `jq`:  
  ```bash
  brew install jq
  sudo apt-get install jq
  ```
- Configure CLI with credentials/region:  
  ```bash
  aws configure
  ```
- Set AWS CLI to JSON output by default:  
  `~/.aws/config`:
  ```ini
  [default]
  output = json
  region = us-east-1
  ```

---

## 📜 `badfinder.sh`

```bash
#!/usr/bin/env bash
# badfinder.sh
#
# Find problematic AWS resources:
#  - CloudFormation stacks with terminated/stopped EC2s
#  - EC2 instances missing tags: 'owner' or 'expires'
#  - Unattached EBS volumes

set -euo pipefail

BADSTACKS=()
STOPPEDSTACKS=()

echo "🔍 Scanning for misconfigured AWS assets..."

# --- CloudFormation stacks with bad/missing EC2 instances ---
for STACK in $(aws cloudformation list-stacks \
    --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE \
    --query 'StackSummaries[].StackName' --output text); do

    INSTANCE=$(aws cloudformation describe-stack-resources \
        --stack-name "$STACK" \
        --query 'StackResources[?ResourceType==`AWS::EC2::Instance`].PhysicalResourceId' \
        --output text)

    [[ -z "$INSTANCE" ]] && continue

    STATUS=$(aws ec2 describe-instance-status \
        --include-all-instances \
        --instance-ids "$INSTANCE" \
        --query 'InstanceStatuses[].InstanceState.Name' \
        --output text 2>/dev/null || true)

    if [[ -z "$STATUS" ]]; then
        BADSTACKS+=("$STACK")
    elif [[ "$STATUS" == "stopped" ]]; then
        STOPPEDSTACKS+=("$STACK")
    fi
done

echo "⚠️ CloudFormation stacks with missing instances:"
printf '%s\n' "${BADSTACKS[@]}"

echo "🛑 CloudFormation stacks with stopped instances:"
printf '%s\n' "${STOPPEDSTACKS[@]}"

# --- EC2 instances missing tags ---
echo "⚠️ Instances missing 'owner' tag:"
aws ec2 describe-instances \
  --query "Reservations[].Instances[?!contains(Tags[].Key, 'owner')].InstanceId" \
  --output text

echo "⚠️ Instances missing 'expires' tag:"
aws ec2 describe-instances \
  --query "Reservations[].Instances[?!contains(Tags[].Key, 'expires')].InstanceId" \
  --output text

# --- Unattached EBS Volumes ---
echo "💸 Unattached EBS volumes:"
aws ec2 describe-volumes \
  --filters Name=status,Values=available \
  --query "Volumes[].VolumeId" \
  --output text

exit 0
```

### ✅ Improvements over old version

- Uses **`set -euo pipefail`** for safer bash  
- Replaces `grep | awk | sed` chaining with **AWS `--query` filters** and `jq`-less where possible (faster, fewer moving parts)  
- Uses **arrays** (`BADSTACKS=()`) for clarity  
- Works even if AWS throttles partial results (`--query` is server-side efficient filtering)  
- More descriptive emoji/status messages  

---

## 🪄 Example Runs

```bash
./badfinder.sh

🔍 Scanning for misconfigured AWS assets...
⚠️ CloudFormation stacks with missing instances:
dev-test-stack
legacy-db-stack

🛑 CloudFormation stacks with stopped instances:
qa-api-stack

⚠️ Instances missing 'owner' tag:
i-0123456789 i-0abcdef1234

⚠️ Instances missing 'expires' tag:
i-09aabbccddeeff

💸 Unattached EBS volumes:
vol-0abcd12345 vol-09876defgh
```

Now you have a quick triage list of what to clean.

---

## 🎯 Handy One-Liners (Modern AWS CLI + `--query`)

### Get IP addresses

- **Private IP of a running instance:**
  ```bash
  aws ec2 describe-instances \
    --instance-ids i-1234567890abcdef \
    --query 'Reservations[].Instances[].PrivateIpAddress' \
    --output text
  ```
- **Public IP:**
  ```bash
  aws ec2 describe-instances \
    --instance-ids i-1234567890abcdef \
    --query 'Reservations[].Instances[].PublicIpAddress' \
    --output text
  ```
- **Both private + public:**
  ```bash
  aws ec2 describe-instances \
    --instance-ids i-1234567890abcdef \
    --query 'Reservations[].Instances[][PrivateIpAddress,PublicIpAddress]' \
    --output text
  ```

### Find all unattached EBS volumes
```bash
aws ec2 describe-volumes \
  --filters Name=status,Values=available \
  --query 'Volumes[].{VolumeId:VolumeId,Size:Size,AZ:AvailabilityZone}' \
  --output table
```

### EC2s missing specific tags
```bash
aws ec2 describe-instances \
  --query "Reservations[].Instances[?!contains(Tags[].Key, 'owner')].InstanceId" \
  --output text
```

---

## 🧹 Best Practices

- Always test with `--dry-run` where available (for stop/terminate or delete commands).  
- Consider replacing “ad hoc” tag checks with **Service Control Policies (SCPs)**, **AWS Config rules**, or **Cloud Custodian / CloudHealth policies** for enforcement rather than cleanup.  
- Use `aws sso login` or profiles in `~/.aws/config` to clean across multiple accounts.  

---

## 📚 References

- [AWS CLI filtering with JMESPath (`--query`)](https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html)  
- [jq Manual](https://stedolan.github.io/jq/manual/)  
- [CloudFormation describe-stack-resources](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/describe-stack-resources.html)  

##
##



# 📒 AWS CLI + jq Cheatsheet

Handy one‑liners to query and filter AWS resources locally using **AWS CLI** & **jq**.

---

## 🖥 EC2

- **List all instances with Name + State:**
  ```bash
  aws ec2 describe-instances \
    --query 'Reservations[].Instances[].{ID:InstanceId, Name:Tags[?Key==`Name`]|[0].Value, State:State.Name}' \
    --output table
  ```

- **List only running instances:**
  ```bash
  aws ec2 describe-instances \
    --filters "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text
  ```

- **Fetch private IP(s):**
  ```bash
  aws ec2 describe-instances \
    --instance-ids i-1234567890abcdef \
    --query 'Reservations[].Instances[].PrivateIpAddress' \
    --output text
  ```

- **Fetch both private + public IP:**
  ```bash
  aws ec2 describe-instances \
    --instance-ids i-1234567890abcdef \
    --query 'Reservations[].Instances[][PrivateIpAddress,PublicIpAddress]' \
    --output text
  ```

- **Instances missing a tag (`owner`):**
  ```bash
  aws ec2 describe-instances \
    --query "Reservations[].Instances[?!contains(Tags[].Key, 'owner')].InstanceId" \
    --output text
  ```

- **Summarize all EC2s (Name, ID, AZ, State):**
  ```bash
  aws ec2 describe-instances \
    | jq -r '.Reservations[].Instances[] 
       | select(.State.Name!="terminated") 
       | [.Tags[]?|select(.Key=="Name").Value, .InstanceId, .Placement.AvailabilityZone, .State.Name] | @tsv'
  ```

---

## 💽 EBS

- **Total EBS GB:**
  ```bash
  aws ec2 describe-volumes \
    --query '[Volumes[].Size] | sum(@)' \
    --output text
  ```

- **List orphan (unattached) volumes:**
  ```bash
  aws ec2 describe-volumes \
    --filters Name=status,Values=available \
    --query 'Volumes[].{ID:VolumeId,Size:Size,AZ:AvailabilityZone}' \
    --output table
  ```

- **Delete orphan volumes (careful!):**
  ```bash
  for vol in $(aws ec2 describe-volumes --filters Name=status,Values=available --query 'Volumes[].VolumeId' --output text); do
    aws ec2 delete-volume --volume-id "$vol"
  done
  ```

---

## 📦 S3

- **List all buckets:**
  ```bash
  aws s3 ls
  ```

- **Check which buckets are public:**
  ```bash
  for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
    aws s3api get-bucket-acl --bucket "$b" \
      --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers` && Permission==`READ`]' \
      --output text | grep -q . && echo "Public: $b"
  done
  ```

- **Make all buckets private:**
  ```bash
  for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
    aws s3api put-bucket-acl --bucket "$b" --acl private
  done
  ```

---

## 🔐 IAM

- **List users:**
  ```bash
  aws iam list-users --query 'Users[].UserName' --output table
  ```

- **Last used time for a key:**
  ```bash
  aws iam get-access-key-last-used --access-key-id <ACCESS_KEY_ID>
  ```

- **Strong password policy:**
  ```bash
  aws iam update-account-password-policy \
    --minimum-password-length 14 \
    --require-symbols \
    --require-numbers \
    --require-uppercase-characters \
    --require-lowercase-characters
  ```

---

## 🏗 CloudFormation

- **List complete stacks:**
  ```bash
  aws cloudformation list-stacks \
    --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE \
    --query 'StackSummaries[].StackName' \
    --output table
  ```

- **Get stack EC2 IDs:**
  ```bash
  aws cloudformation describe-stack-resources \
    --stack-name mystack \
    --query 'StackResources[?ResourceType==`AWS::EC2::Instance`].PhysicalResourceId' \
    --output text
  ```

---

## 📜 CloudTrail & CloudWatch

- **List all CloudTrail trails:**
  ```bash
  aws cloudtrail describe-trails --query 'trailList[].Name' --output table
  ```

- **Get CloudTrail status:**
  ```bash
  aws cloudtrail get-trail-status --name awslog
  ```

- **List CloudWatch log groups:**
  ```bash
  aws logs describe-log-groups --query 'logGroups[].logGroupName' --output table
  ```

- **List CloudWatch log streams in a group:**
  ```bash
  aws logs describe-log-streams --log-group-name MyAppLogs \
    --query 'logStreams[].logStreamName' --output table
  ```

---

## ✨ jq Tips

- **Turn JSON into table-ready TSV:**  
  `| jq -r '[.field1,.field2] | @tsv'`

- **Check for missing tag keys:**  
  ```bash
  jq '[.Reservations[].Instances[]
      | select(.Tags | map(.Key) | contains(["owner"]) | not)
      | {InstanceId, MissingTags: (["owner","expires"] - (map(.Tags[].Key)))}]'
  ```
- **Pretty-print JSON from AWS:**  
  ```bash
  aws ec2 describe-instances | jq .
  ```

---

# 🎯 Quick Reference

- **Use `--query` (JMESPath) wherever possible** → server-side filtering, faster, less throttling.  
- **Use `--output table` for at-a-glance summaries.**  
- **Use `jq` for more intensive transformations (joins, tag checks, sorting).**  
- **Always try `--dry-run` when modifying resources.**


##
##
