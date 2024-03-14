import subprocess
import json
import os,sys,re

##
##

# Function to fetch all EKS clusters in the AWS account
def get_eks_clusters():
    command = "aws eks list-clusters"
    output = subprocess.check_output(command, shell=True)
    data = json.loads(output)
    return data.get('clusters', [])

# Function to fetch EC2 instances associated with a given EKS cluster
def get_ec2_instances(cluster_name):
    command = f"aws ec2 describe-instances --filters Name=tag:eks:cluster-name,Values={cluster_name}"
    output = subprocess.check_output(command, shell=True)
    data = json.loads(output)
    return data.get('Reservations', [])

# Fetch all EKS clusters
clusters = get_eks_clusters()

# Iterate through each cluster and fetch associated EC2 instances
for cluster_name in clusters:
    print(f"Fetching instances for cluster: {cluster_name}")
    instances = get_ec2_instances(cluster_name)
    if not instances:
        print("No instances found.")
        continue
    print("Instances found:")
    for reservation in instances:
        for instance in reservation['Instances']:
            instance_name = instance.get('PrivateDnsName', 'N/A')
            ami_id = instance.get('ImageId', 'N/A')
            launch_time = instance.get('LaunchTime', 'N/A')
            instance_type = instance.get('InstanceType', 'N/A')
            subnet_id = instance.get('SubnetId', 'N/A')
            vpc_id = instance.get('VpcId', 'N/A')
            state = instance['State'].get('Name', 'N/A')
            # Add additional logic to get node group if needed
            node_group = "N/A"
            # Display instance details
            print(f"InstanceName: {instance_name}, AMI: {ami_id}, LaunchTime: {launch_time}, InstanceType: {instance_type}, SubnetID: {subnet_id}, VpcID: {vpc_id}, State: {state}, NodeGroup: {node_group}, Cluster: {cluster_name}")

##
##
