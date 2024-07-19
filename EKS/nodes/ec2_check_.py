import boto3
from kubernetes import client, config

def get_eks_nodes():
    # Load Kubernetes config
    config.load_kube_config()
    v1 = client.CoreV1Api()

    # Get nodes in the EKS cluster
    nodes = v1.list_node()
    eks_instance_ids = [node.spec.provider_id.split('/')[-1] for node in nodes.items]
    return eks_instance_ids

def get_ec2_instances():
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances()
    ec2_instance_ids = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            ec2_instance_ids.append(instance['InstanceId'])
    return ec2_instance_ids

def check_instances_in_eks():
    eks_instance_ids = get_eks_nodes()
    ec2_instance_ids = get_ec2_instances()

    eks_ec2_instances = [instance for instance in ec2_instance_ids if instance in eks_instance_ids]

    return eks_ec2_instances

if __name__ == "__main__":
    eks_instances = check_instances_in_eks()
    if eks_instances:
        print("The following EC2 instances are part of the EKS cluster:")
        for instance in eks_instances:
            print(instance)
    else:
        print("No EC2 instances from the list are part of the EKS cluster.")
