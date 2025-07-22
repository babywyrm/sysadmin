

## 1. Basic Event Listing & Pagination

### 1.1 List latest 10 EC2 write events

Retrieve the timestamp, event name, and user for the most recent EC2 non‑read operations.

```bash
aws cloudtrail lookup-events \
    --max-items 10 \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=ec2.amazonaws.com \
    --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false \
  | jq -r '.Events[] | "\(.EventTime) \(.EventName) by \(.Username)"'
```

### 1.2 Paginate with NextToken

Fetch the next page of results using a saved token.

```bash
NEXT=$(cat last_token.txt)

aws cloudtrail lookup-events \
    --max-items 50 \
    --starting-token "$NEXT" \
  | jq -r '{
      Events: [.Events[].EventName],
      NextToken: .NextToken
    }'
```

---

## 2. Attribute‑based Filtering

### 2.1 Non‑read RDS operations

Show recent RDS write calls.

```bash
aws cloudtrail lookup-events \
    --max-items 20 \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=rds.amazonaws.com \
    --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false \
  | jq '.Events[] | {
      Time: .EventTime,
      Name: .EventName,
      User: .Username
    }'
```

### 2.2 Specific EventName: DeleteBucket

Extract bucket names from DeleteBucket calls.

```bash
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteBucket \
    --max-items 5 \
  | jq -r '.Events[] |
      .CloudTrailEvent     |
      fromjson             |
      .requestParameters   |
      .bucketName'
```

---

## 3. Time‑range Queries

### 3.1 Since a given date

Fetch all events after midnight UTC on July 1, 2025.

```bash
aws cloudtrail lookup-events \
    --start-time "2025-07-01T00:00:00Z" \
    --max-items 100 \
  | jq '.Events[] | {Time: .EventTime, Name: .EventName}'
```

### 3.2 Between two timestamps

List events between July 1 and July 4, 2025.

```bash
aws cloudtrail lookup-events \
    --start-time "2025-07-01T00:00:00Z" \
    --end-time   "2025-07-04T00:00:00Z" \
    --max-items 50 \
  | jq '.Events[] | {Time: .EventTime, Source: .EventSource}'
```

---

## 4. Inspecting Request Parameters

### 4.1 Full `requestParameters`

Get the entire parameters payload for the latest RunInstances call.

```bash
aws cloudtrail lookup-events \
    --max-items 1 \
    --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  | jq '.Events[].CloudTrailEvent | fromjson | .requestParameters'
```

### 4.2 Modified EC2 tags

List each tag key/value from ModifyInstanceAttribute events.

```bash
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyInstanceAttribute \
    --max-items 20 \
  | jq -r '.Events[] |
      .CloudTrailEvent   |
      fromjson           |
      .requestParameters |
      select(.tagSpecifications) |
      .tagSpecifications[]?.tags[]? |
      "\(.key)=\(.value)"'
```

---

## 5. Multi‑Region & Profiles

### 5.1 Loop across regions

Aggregate the last five non‑read events per region.

```bash
for region in us-east-1 us-west-2 eu-central-1; do
  echo "=== $region ==="
  aws cloudtrail lookup-events \
    --region $region \
    --max-items 5 \
    --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false \
  | jq -r '.Events[].EventName'
done
```

### 5.2 Using an assume‑role profile

Run queries under an audit‑only IAM role.

```bash
aws cloudtrail lookup-events \
    --profile audit-role \
    --region us-east-1 \
    --max-items 10 \
  | jq '.Events[] | {Name: .EventName, User: .Username}'
```

---

## 6. Exporting & Reporting

### 6.1 CSV of critical S3 deletes

Output a CSV with timestamp, user, bucket, and key.

```bash
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=s3.amazonaws.com \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
    --max-items 100 \
  | jq -r '.Events[] |
      [.EventTime, .Username,
       (.CloudTrailEvent|fromjson|.requestParameters.bucketName),
       (.CloudTrailEvent|fromjson|.requestParameters.key)] |
      @csv' \
  > s3_deletes.csv
```

### 6.2 JSON report grouped by user

Aggregate events by username.

```bash
aws cloudtrail lookup-events --max-items 200 \
  | jq 'group_by(.Username) |
      map({
        User: .[0].Username,
        Events: map({Name:.EventName, Time:.EventTime})
      })'
```

---

## 7. Automated Monitoring Snippets

### 7.1 Detect console login failures

Alert on failed ConsoleLogin calls.

```bash
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --max-items 50 \
  | jq '.Events[] |
      fromjson? as $e? |
      select($e.errorMessage == "Failed authentication") |
      {Time:$e.eventTime, User:$e.userName}'
```

### 7.2 Identify root‑account usage

Spot any API calls made by the root user.

```bash
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=Root \
    --max-items 20 \
  | jq '.Events[] | {Time:.EventTime, Name:.EventName}'
```


