import boto3
from tabulate import tabulate

##
##

# Create Boto3 clients for EC2 and AMI
ec2_client = boto3.client('ec2')
ec2_resource = boto3.resource('ec2')

# Get details of all EC2 instances
ec2_instances_data = []
response = ec2_client.describe_instances()
for reservation in response['Reservations']:
    for instance in reservation['Instances']:
        instance_id = instance['InstanceId']
        instance_type = instance['InstanceType']
        state = instance['State']['Name']
        launch_time = instance['LaunchTime']
        ami_id = instance['ImageId']
        tags = ", ".join([f"{tag['Key']}: {tag['Value']}" for tag in instance.get('Tags', [])])
        ec2_instances_data.append([instance_id, instance_type, state, launch_time, ami_id, tags])

# Get details of all AMIs
ami_data = []
response = ec2_client.describe_images(Owners=['self'])
for image in response['Images']:
    ami_id = image['ImageId']
    name = image.get('Name', 'N/A')
    description = image.get('Description', 'N/A')
    creation_date = image['CreationDate']
    ami_data.append([ami_id, name, description, creation_date])

# Correlate AMIs with EC2 instances
correlation_data = []
for instance in ec2_instances_data:
    instance_id = instance[0]
    ami_id = instance[4]
    for ami in ami_data:
        if ami[0] == ami_id:
            correlation_data.append([instance_id, ami_id, ami[1]])

# Display the data in a readable format
print("AMIs:")
print(tabulate(ami_data, headers=["AMI ID", "Name", "Description", "Creation Date"], tablefmt="grid"))
print("\nCorrelation of EC2 Instances with AMIs:")
print(tabulate(correlation_data, headers=["Instance ID", "AMI ID", "AMI Name"], tablefmt="grid"))

##
##

import boto3

# Create a Boto3 client for each service
s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')
iam_client = boto3.client('iam')

# Get details of all S3 buckets
response = s3_client.list_buckets()
print("S3 Buckets:")
for bucket in response['Buckets']:
    bucket_name = bucket['Name']
    creation_date = bucket['CreationDate']
    region = s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
    owner = s3_client.get_bucket_acl(Bucket=bucket_name)['Owner']['DisplayName']
    print(f"Bucket Name: {bucket_name}, Creation Date: {creation_date}, Region: {region}, Owner: {owner}")

# Get details of all EC2 instances
response = ec2_client.describe_instances()
print("\nEC2 Instances:")
for reservation in response['Reservations']:
    for instance in reservation['Instances']:
        instance_id = instance['InstanceId']
        instance_type = instance['InstanceType']
        state = instance['State']['Name']
        launch_time = instance['LaunchTime']
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        print(f"Instance ID: {instance_id}, Instance Type: {instance_type}, State: {state}, Launch Time: {launch_time}, Tags: {tags}")

# Get details of all security groups
response = ec2_client.describe_security_groups()
print("\nSecurity Groups:")
for sg in response['SecurityGroups']:
    group_id = sg['GroupId']
    group_name = sg['GroupName']
    description = sg['Description']
    vpc_id = sg['VpcId']
    print(f"Group ID: {group_id}, Group Name: {group_name}, Description: {description}, VPC ID: {vpc_id}")

# Get details of all IAM users
response = iam_client.list_users()
print("\nIAM Users:")
for user in response['Users']:
    user_name = user['UserName']
    creation_date = user['CreateDate']
    groups = iam_client.list_groups_for_user(UserName=user_name)['Groups']
    groups_str = ", ".join([group['GroupName'] for group in groups])
    print(f"Username: {user_name}, Creation Date: {creation_date}, Groups: {groups_str}")

# Get details of all IAM groups
response = iam_client.list_groups()
print("\nIAM Groups:")
for group in response['Groups']:
    group_name = group['GroupName']
    creation_date = group['CreateDate']
    policies = iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
    policies_str = ", ".join([policy['PolicyName'] for policy in policies])
    print(f"Group Name: {group_name}, Creation Date: {creation_date}, Attached Policies: {policies_str}")

##
##

