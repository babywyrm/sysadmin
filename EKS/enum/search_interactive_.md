
```
import os,sys,re
import boto3

def get_eks_clusters():
    eks_client = boto3.client('eks')
    response = eks_client.list_clusters()
    clusters = response['clusters']
    return clusters

def get_eks_workloads(cluster_name, namespace):
    eks_client = boto3.client('eks')
    response = eks_client.list_namespaced_workloads(
        name=cluster_name,
        namespace=namespace
    )
    workloads = response['workloads']
    return workloads

def main():
    clusters = get_eks_clusters()

    for cluster_name in clusters:
        eks_client = boto3.client('eks')
        eks_client.describe_cluster(name=cluster_name)
        response = eks_client.list_namespaces(
            name=cluster_name
        )
        namespaces = response['namespaces']
        
        print(f'Cluster: {cluster_name}')

        for namespace in namespaces:
            print(f'Namespace: {namespace}')

            workloads = get_eks_workloads(cluster_name, namespace)
            for workload in workloads:
                print(f'Workload: {workload["workloadName"]}')
                # Additional workload details can be printed here if desired
            print()  # Empty line for readability between namespaces
        print()  # Empty line for readability between clusters

if __name__ == '__main__':
    main()
    
```

Make sure you have the Boto3 library installed (pip install boto3) and have your AWS credentials properly configured (either through environment variables or AWS CLI configuration) to authenticate the AWS SDK.

This script retrieves the list of clusters using the list_clusters method, then it iterates over each cluster to obtain the list of namespaces using the list_namespaces method. For each namespace, it calls the list_namespaced_workloads method to get the workloads. Finally, it prints the cluster, namespace, and workload details accordingly.

Please note that this script assumes you have the necessary IAM permissions to list clusters, describe clusters, list namespaces, and list workloads within the clusters. Make sure the IAM user or role associated with your AWS credentials has the required permissions for these actions.


```
import argparse
import boto3

def get_eks_clusters(regions):
    clusters = []
    for region in regions:
        eks_client = boto3.client('eks', region_name=region)
        response = eks_client.list_clusters()
        clusters.extend(response['clusters'])
    return clusters

# Rest of the code...

def main(regions):
    clusters = get_eks_clusters(regions)
    # Rest of the code...

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Search EKS clusters in specified AWS regions')
    parser.add_argument('-r', '--regions', nargs='+', required=True,
                        help='AWS regions to search EKS clusters in')
    args = parser.parse_args()

    main(args.regions)
In this version, we added an import for the argparse module to handle command-line arguments. The script defines a new argument -r or --regions, which expects one or more AWS region names as input. These region names are then passed to the get_eks_clusters function, which iterates over each region and fetches the EKS clusters for that region.

To run the script, you can execute it with the -r or --regions argument, providing the AWS regions you want to search in:
```


##
##

python script.py -r us-west-2 us-east-1
This command will search for EKS clusters in the us-west-2 and us-east-1 AWS regions. Adjust the region names as per your requirements.

##
##
