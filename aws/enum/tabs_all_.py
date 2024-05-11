import boto3
from tabulate import tabulate

##
##

# Create Boto3 clients for each service
s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')
iam_client = boto3.client('iam')

# Get details of all S3 buckets
response = s3_client.list_buckets()
s3_buckets_data = []
for bucket in response['Buckets']:
    bucket_name = bucket['Name']
    creation_date = bucket['CreationDate']
    region = s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
    owner = s3_client.get_bucket_acl(Bucket=bucket_name)['Owner']['DisplayName']
    s3_buckets_data.append([bucket_name, creation_date, region, owner])

# Get details of all EC2 instances
response = ec2_client.describe_instances()
ec2_instances_data = []
for reservation in response['Reservations']:
    for instance in reservation['Instances']:
        instance_id = instance['InstanceId']
        instance_type = instance['InstanceType']
        state = instance['State']['Name']
        launch_time = instance['LaunchTime']
        tags = ", ".join([f"{tag['Key']}: {tag['Value']}" for tag in instance.get('Tags', [])])
        ec2_instances_data.append([instance_id, instance_type, state, launch_time, tags])

# Get details of all security groups
response = ec2_client.describe_security_groups()
security_groups_data = []
for sg in response['SecurityGroups']:
    group_id = sg['GroupId']
    group_name = sg['GroupName']
    description = sg['Description']
    vpc_id = sg['VpcId']
    security_groups_data.append([group_id, group_name, description, vpc_id])

# Get details of all IAM users
response = iam_client.list_users()
iam_users_data = []
for user in response['Users']:
    user_name = user['UserName']
    creation_date = user['CreateDate']
    groups = ", ".join([group['GroupName'] for group in iam_client.list_groups_for_user(UserName=user_name)['Groups']])
    iam_users_data.append([user_name, creation_date, groups])

# Get details of all IAM groups
response = iam_client.list_groups()
iam_groups_data = []
for group in response['Groups']:
    group_name = group['GroupName']
    creation_date = group['CreateDate']
    policies = ", ".join([policy['PolicyName'] for policy in iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']])
    iam_groups_data.append([group_name, creation_date, policies])

# Display the data in a readable format
print("S3 Buckets:")
print(tabulate(s3_buckets_data, headers=["Bucket Name", "Creation Date", "Region", "Owner"], tablefmt="grid"))
print("\nEC2 Instances:")
print(tabulate(ec2_instances_data, headers=["Instance ID", "Instance Type", "State", "Launch Time", "Tags"], tablefmt="grid"))
print("\nSecurity Groups:")
print(tabulate(security_groups_data, headers=["Group ID", "Group Name", "Description", "VPC ID"], tablefmt="grid"))
print("\nIAM Users:")
print(tabulate(iam_users_data, headers=["Username", "Creation Date", "Groups"], tablefmt="grid"))
print("\nIAM Groups:")
print(tabulate(iam_groups_data, headers=["Group Name", "Creation Date", "Attached Policies"], tablefmt="grid"))


##
##
