#!/usr/bin/python3

import os,sys,re

print(sys.executable)

##
##

import boto3
import os

session = boto3.Session(
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
    region_name=os.environ.get('AWS_DEFAULT_REGION')
)

def get_eks_clusters():
    eks_client = session.client('eks')
    clusters = eks_client.list_clusters()['clusters']
    return clusters

def get_ec2_instances(cluster_name, region):
    ec2_client = session.client('ec2', region_name=region)
    filters = [
        {
            'Name': 'tag:eks:cluster-name',
            'Values': [cluster_name]
        }
    ]
    instances = ec2_client.describe_instances(Filters=filters)['Reservations']
    instance_ids = []
    for reservation in instances:
        for instance in reservation['Instances']:
            instance_ids.append(instance['InstanceId'])
    return instance_ids

def main():
    regions = ['us-east-2', 'us-east-1', 'us-west-2', 'eu-west-1'] # add the regions you want to search in
    eks_clusters = get_eks_clusters()
    all_instance_ids = []
    for cluster_name in eks_clusters:
        for region in regions:
            instance_ids = get_ec2_instances(cluster_name, region)
            if instance_ids:
                all_instance_ids += instance_ids
                print(f"Instances for EKS cluster {cluster_name} in region {region}: {instance_ids}")
            else:
                print(f"No instances found for EKS cluster {cluster_name} in region {region}")

    if all_instance_ids:
        print(f"All EC2 instances in EKS clusters across regions: {all_instance_ids}")
    else:
        print("No EC2 instances found in any EKS cluster across regions")

if __name__ == '__main__':
    main()

##
##
