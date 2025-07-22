# AWS CLI + CloudTrail + jq Examples for SOC

```
# 1. Basic Event Listing & Pagination

## 1.1 List latest 10 EC2 write events:
aws cloudtrail lookup-events \
    --max-items 10 \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=ec2.amazonaws.com \
    --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false \
  | jq -r '.Events[] | "\(.EventTime) \(.EventName) \(.Username)"'

## 1.2 Handle NextToken pagination:
aws cloudtrail lookup-events \
    --max-items 50 \
    --starting-token "$(cat token.txt)" \
  | jq -r '"Events:\n"+(.Events[].EventName|tostring)+"\nNextToken: \(.NextToken)"'


# 2. Filtering by Attributes

## 2.1 Recent write operations on RDS:
aws cloudtrail lookup-events \
    --max-items 20 \
    --lookup-attributes AttributeKey=EventSource,AttributeValue=rds.amazonaws.com \
    --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false \
  | jq '.Events[] | {Time: .EventTime, Name: .EventName, User: .Username}'

## 2.2 Specific EventName = DeleteBucket:
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteBucket \
    --max-items 5 \
  | jq '.Events[] | {Bucket: (.CloudTrailEvent|fromjson|.requestParameters.bucketName), User: .Username}'


# 3. Time‑based Queries

## 3.1 Since a given date:
aws cloudtrail lookup-events \
    --start-time "2025-07-01T00:00:00Z" \
    --max-items 100 \
  | jq '.Events[] | {Time: .EventTime, Name: .EventName}'

## 3.2 Between two timestamps:
aws cloudtrail lookup-events \
    --start-time "2025-07-01T00:00:00Z" \
    --end-time   "2025-07-04T00:00:00Z" \
    --max-items 50 \
  | jq '.Events[] | {Time: .EventTime, Source: .EventSource}'


# 4. Deep‑dive into Request Parameters

## 4.1 Extract full `requestParameters` block:
aws cloudtrail lookup-events \
    --max-items 1 \
    --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  | jq '.Events[].CloudTrailEvent | fromjson | .requestParameters'

## 4.2 List all tags modified on EC2 instances:
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


# 5. Multi‑Region & Profiles

## 5.1 Cross‑region event aggregation:
for region in us-east-1 us-west-2 eu-central-1; do
  echo "=== $region ==="
  aws cloudtrail lookup-events --region $region --max-items 5 \
    --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false \
  | jq -r '.Events[].EventName'
done

## 5.2 Assume role & profile:
aws cloudtrail lookup-events \
    --profile audit-role \
    --region us-east-1 \
    --max-items 10 \
  | jq '.Events[] | {Name: .EventName, User: .Username}'


# 6. Exporting & Reporting

## 6.1 CSV of critical S3 deletes:
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

## 6.2 JSON report grouped by user:
aws cloudtrail lookup-events --max-items 200 \
  | jq 'group_by(.Username) |
      map({User: .[0].Username, Events: map({Name:.EventName, Time:.EventTime})})'


# 7. Automated Monitoring Snippets

## 7.1 Detect console login failures:
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --max-items 50 \
  | jq '.Events[] |
      fromjson? as $e? |
      select($e.errorMessage == "Failed authentication") |
      {Time:$e.eventTime, User:$e.userName}'

## 7.2 Identify root‑account usage:
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=Root \
    --max-items 20 \
  | jq '.Events[] | {Time:.EventTime, Name:.EventName}'
