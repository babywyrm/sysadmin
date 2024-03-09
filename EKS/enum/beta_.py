import boto3
from datetime import datetime, timezone

##
##

def get_ec2_instance_info(cluster_name, region='us-east-1'):
    eks_client = boto3.client('eks', region_name=region)
    ec2_client = boto3.client('ec2', region_name=region)

    # Get the list of node groups in the EKS cluster
    response = eks_client.list_nodegroups(clusterName=cluster_name)
    nodegroup_names = response['nodegroups']

    for nodegroup_name in nodegroup_names:
        # Describe the instances in the node group
        response = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
        instances = response['nodegroup']['resources']['autoScalingGroups'][0]['instances']

        for instance in instances:
            instance_id = instance['id']

            # Describe the EC2 instance
            ec2_response = ec2_client.describe_instances(InstanceIds=[instance_id])
            ec2_instance = ec2_response['Reservations'][0]['Instances'][0]

            # Extract relevant information
            launch_time = ec2_instance['LaunchTime']
            ami_id = ec2_instance['ImageId']

            # Calculate uptime
            current_time = datetime.now(timezone.utc)
            uptime = current_time - launch_time

            print(f"Instance ID: {instance_id}")
            print(f"Launch Time: {launch_time}")
            print(f"Uptime: {uptime}")
            print(f"AMI ID: {ami_id}")
            print("\n")

# Replace 'your-cluster-name' with the actual EKS cluster name
cluster_name = 'your-cluster-name'
get_ec2_instance_info(cluster_name)

##
##
