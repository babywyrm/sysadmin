
##
#
https://0x00sec.org/t/a-blue-team-guide-to-aws-cloudtrail-monitoring/15086
#
##


| Scenario                         | EventName                        | AWS CLI Command                                                                                                                                                                                                                                                                                                                                                                                                                            | Use Case                                                               |
|----------------------------------|----------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| **Successful Console Login**     | `ConsoleLogin`                   | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \  
--region ap-northeast-1 \  
--query "Events[?ErrorCode==null].{User:Username,Time:EventTime,SourceIP:Resources[0].ResourceName}" \  
--output table```                                                                                                                                                                                                                                          | Identify every successful human/AWS-managed-console login.             |
| **Failed Console Login**         | `ConsoleLogin`                   | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \  
--region ap-northeast-1 \  
--query "Events[?ErrorCode=='FailedAuthentication'].{User:Username,Time:EventTime,Error:ErrorCode}" \  
--output table```                                                                                                                                                                                                                                          | Detect brute-force or forgotten-password attempts.                     |
| **EC2 Instance Stop**            | `StopInstances`                  | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=StopInstances \  
--region ap-northeast-1 \  
--query "Events[*].{User:Username,Time:EventTime,Instance:Resources[0].ResourceName}" \  
--output table```                                                                                                                                                                                                                                          | Find who stopped EC2 instances (could indicate disruption).            |
| **EC2 Instance Start**           | `StartInstances`                 | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=StartInstances \  
--region ap-northeast-1 \  
--query "Events[*].{User:Username,Time:EventTime,Instance:Resources[0].ResourceName}" \  
--output table```                                                                                                                                                                                                                                          | Track unexpected EC2 power-ups or recovery actions.                    |
| **EC2 RunInstances**             | `RunInstances`                   | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \  
--region ap-northeast-1 \  
--query "Events[*].{User:Username,Time:EventTime,Image:ResponseElements.instancesSet.items[0].imageId,Instance:ResponseElements.instancesSet.items[0].instanceId}" \  
--output table```                                                                                                                                                                                                                                          | Detect launching of EC2 instances from unapproved or trojaned AMIs.   |
| **IAM User Creation**            | `CreateUser`                     | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \  
--region ap-northeast-1 \  
--query "Events[*].{Admin:Username,Time:EventTime,NewUser:ResponseElements.user.userName}" \  
--output table```                                                                                                                                                                                                                                          | Audit who’s provisioning new IAM users.                               |
| **IAM User Deletion**            | `DeleteUser`                     | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=DeleteUser \  
--region ap-northeast-1 \  
--query "Events[*].{Admin:Username,Time:EventTime,DeletedUser:RequestParameters.userName}" \  
--output table```                                                                                                                                                                                                                                          | Detect potential cover-ups or deprovisioning mistakes.                 |
| **Attach Role Policy**           | `AttachRolePolicy`               | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=AttachRolePolicy \  
--region ap-northeast-1 \  
--query "Events[*].{Admin:Username,Time:EventTime,Role:RequestParameters.roleName,PolicyArn:RequestParameters.policyArn}" \  
--output table```                                                                                                                                                                                                                                          | See who’s granting new permissions to roles.                           |
| **Detach Role Policy**           | `DetachRolePolicy`               | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=DetachRolePolicy \  
--region ap-northeast-1 \  
--query "Events[*].{Admin:Username,Time:EventTime,Role:RequestParameters.roleName,PolicyArn:RequestParameters.policyArn}" \  
--output table```                                                                                                                                                                                                                                          | Monitor removal of privileges from roles.                              |
| **Assume Role**                  | `AssumeRole`                     | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \  
--region ap-northeast-1 \  
--query "Events[*].{Caller:Username,Time:EventTime,Role:RequestParameters.roleArn}" \  
--output table```                                                                                                                                                                                                                                          | Track cross-account or service-account impersonation.                  |
| **S3 Bucket Policy Change**      | `PutBucketPolicy`                | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy \  
--region ap-northeast-1 \  
--query "Events[*].{Admin:Username,Time:EventTime,Bucket:RequestParameters.bucketName}" \  
--output table```                                                                                                                                                                                                                                          | Detect modifications to S3 access controls.                            |
| **Security Group Ingress Added** | `AuthorizeSecurityGroupIngress`  | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \  
--region ap-northeast-1 \  
--query "Events[*].{Admin:Username,Time:EventTime,Group:RequestParameters.groupId,Cidr:RequestParameters.ipPermissions[0].ipRanges[0].cidrIp}" \  
--output table```                                                                                                                                                                                                                                          | Catch opening of new network paths to hosts.                           |
| **Unauthorized API Call**        | *any* + `ErrorCode=UnauthorizedOperation` | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=ErrorCode,AttributeValue=UnauthorizedOperation \  
--region ap-northeast-1 \  
--query "Events[*].{User:Username,Time:EventTime,Operation:EventName}" \  
--output table```                                                                                                                                                                                                                                          | Surface attempts to call APIs without proper rights.                  |
| **SSM Session Start**            | `StartSession`                   | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=StartSession \  
--region ap-northeast-1 \  
--query "Events[*].{User:Username,Time:EventTime,Target:RequestParameters.target}" \  
--output table```                                                                                                                                                                                                                                          | Detect interactive remote shell via SSM Session Manager.              |
| **SSM Command Execution**        | `SendCommand`                    | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand \  
--region ap-northeast-1 \  
--query "Events[*].{Admin:Username,Time:EventTime,Document:RequestParameters.documentName,Targets:RequestParameters.targets}" \  
--output table```                                                                                                                                                                                                                                          | Identify remote commands executed via SSM RunCommand.                 |
| **AMI Registration**             | `RegisterImage`                  | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=RegisterImage \  
--region ap-northeast-1 \  
--query "Events[*].{User:Username,Time:EventTime,ImageId:ResponseElements.imageId}" \  
--output table```                                                                                                                                                                                                                                          | Identify creation of potentially trojaned custom AMIs.                |
| **AMI Deregistration**           | `DeregisterImage`                | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=DeregisterImage \  
--region ap-northeast-1 \  
--query "Events[*].{User:Username,Time:EventTime,ImageId:RequestParameters.imageId}" \  
--output table```                                                                                                                                                                                                                                          | Detect removal of AMIs (cover-up or cleanup).                         |
| **ECR Image Push**               | `PutImage`                       | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=PutImage \  
--region ap-northeast-1 \  
--query "Events[*].{User:Username,Time:EventTime,Repository:RequestParameters.repositoryName,ImageTag:RequestParameters.imageTag}" \  
--output table```                                                                                                                                                                                                                                          | Identify new or updated container image uploads (potentially trojaned).|
| **ECR Image Delete**             | `BatchDeleteImage`               | ```bash<br>aws cloudtrail lookup-events \  
--lookup-attributes AttributeKey=EventName,AttributeValue=BatchDeleteImage \  
--region ap-northeast-1 \  
--query "Events[*].{User:Username,Time:EventTime,Repository:RequestParameters.repositoryName,ImageIds:RequestParameters.imageIds}" \  
--output table```                                                                                                                                                                                                                                          | Detect removal of container images (cover-up).                        |
