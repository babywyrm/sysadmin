import boto3
import argparse
import os,sys,re
from kubernetes import client, config
from datetime import datetime, timezone
from tabulate import tabulate

##
##

def get_eks_nodes():
    # Load Kubernetes config
    config.load_kube_config()
    v1 = client.CoreV1Api()

    # Get nodes in the EKS cluster
    nodes = v1.list_node()
    eks_instance_ids = {}
    for node in nodes.items:
        instance_id = node.spec.provider_id.split('/')[-1]
        node_info = {
            'instance_id': instance_id,
            'launch_time': node.metadata.creation_timestamp
        }
        eks_instance_ids[instance_id] = node_info
    return eks_instance_ids

def get_ec2_instances(profile_name):
    session = boto3.Session(profile_name=profile_name)
    ec2 = session.client('ec2')
    response = ec2.describe_instances()
    ec2_instance_ids = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            ec2_instance_ids.append({
                'instance_id': instance['InstanceId'],
                'launch_time': instance['LaunchTime']
            })
    return ec2_instance_ids

def check_instances_in_eks(profiles):
    eks_instance_ids = get_eks_nodes()
    all_ec2_instances = []

    for profile in profiles:
        ec2_instances = get_ec2_instances(profile)
        all_ec2_instances.extend(ec2_instances)

    eks_ec2_instances = []
    for instance in all_ec2_instances:
        instance_id = instance['instance_id']
        if instance_id in eks_instance_ids:
            eks_instance = eks_instance_ids[instance_id]
            eks_instance['launch_time'] = instance['launch_time']
            eks_instance['active_duration'] = datetime.now(timezone.utc) - instance['launch_time']
            eks_ec2_instances.append(eks_instance)

    return eks_ec2_instances

def print_table(instances):
    table = []
    for instance in instances:
        table.append([
            instance['instance_id'],
            instance['launch_time'],
            instance['active_duration']
        ])
    headers = ['Instance ID', 'Launch Time', 'Active Duration']
    print(tabulate(table, headers, tablefmt='pretty'))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check if EC2 instances belong to an EKS cluster')
    parser.add_argument('profiles', metavar='P', type=str, nargs='+', help='AWS profiles to check')

    args = parser.parse_args()

    eks_instances = check_instances_in_eks(args.profiles)
    if eks_instances:
        print("The following EC2 instances are part of the EKS cluster:")
        print_table(eks_instances)
    else:
        print("No EC2 instances from the list are part of the EKS cluster.")

##
##
