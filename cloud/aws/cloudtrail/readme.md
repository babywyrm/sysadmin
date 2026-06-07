# CloudTrail Use Cases and AWS CLI Examples

| Use Case                          | Description                                                                 | AWS CLI Command Example                                                                                             |
|-----------------------------------|-----------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| **Console Login Tracking**        | Track who logs in to the AWS Management Console and when.                   | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --region us-east-1 --output json` |
| **EC2 Instance Stopped**          | Find out who stopped an EC2 instance and when.                              | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopInstances --region eu-west-1 --output table` |
| **User Activity Tracking**        | Track specific user activities across AWS services.                         | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=stevenzh --output json`      |
| **S3 Bucket Creation**            | See when new S3 buckets are created and who created them.                   | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateBucket --region us-west-2 --output table` |
| **IAM Role Changes**              | Track changes to IAM roles, such as creation or policy updates.              | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole --output json`      |
| **API Call Logging**              | Capture and analyze all API calls made by users and services.               | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances --region us-east-1 --output json` |
| **Console Login Details (Last N)**| Get the last N console login events, including usernames and timestamps.    | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --max-items 10 --region us-east-1 --output json` |
| **CloudFormation Stacks Events**  | Track AWS CloudFormation stack events like creation, update, and deletion. | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateStack --region us-west-2 --output table` |
| **EC2 Instance Launches**         | Track who launched EC2 instances and when.                                  | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances --output json`    |
| **Security Group Changes**        | See changes made to security groups.                                         | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress --region eu-west-1 --output table` |
| **Billing and Cost Management**   | Monitor billing-related API calls (e.g., cost allocation or changes).        | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateCostAllocation --output json` |
| **Access Key Changes**            | Track when access keys are created, deleted, or modified.                  | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey --region us-east-1 --output json` |
| **AWS Lambda Invocations**        | Track invocations of Lambda functions.                                       | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=Invoke --region us-east-1 --output json` |
| **Multi-Factor Authentication (MFA) Use**| Monitor the use of MFA for enhanced security in API calls.                | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AuthenticateMFA --region eu-west-1 --output table` |
| **CloudWatch Alarms Management**  | Monitor changes to CloudWatch alarms (create, modify, delete).               | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=PutMetricAlarm --output json` |
| **RDS Database Backups**          | Track RDS database snapshots and backups.                                   | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateDBSnapshot --region us-west-1 --output json` |

## Example Use Case Explanation

1. **Console Login Tracking**:
   - **Use Case**: Knowing who logged in and when to ensure no unauthorized access.
   - **Example Command**: 
     ```bash
     aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --region us-east-1 --output json
     ```
   - **What it Does**: This command returns a list of console login events, so you can track who accessed the AWS console.

2. **EC2 Instance Stopped**:
   - **Use Case**: Ensure no EC2 instance was stopped by unauthorized users.
   - **Example Command**:
     ```bash
     aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopInstances --region eu-west-1 --output table
     ```
   - **What it Does**: This fetches who stopped which EC2 instance, including the timestamp.

3. **IAM Role Changes**:
   - **Use Case**: Monitor any changes to IAM roles to ensure proper permissions.
   - **Example Command**:
     ```bash
     aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole --output json
     ```
   - **What it Does**: Retrieves events where IAM roles were created.

4. **CloudFormation Stacks Events**:
   - **Use Case**: Keep track of all stack changes (create, delete, update) in CloudFormation.
   - **Example Command**:
     ```bash
     aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateStack --region us-west-2 --output table
     ```
   - **What it Does**: This command allows you to track stack creation events.

--- CLI**. With commands that target events like **console logins**, **EC2 instance actions**, **IAM role changes**, and more, you can easily track and analyze activity in your AWS environment.
