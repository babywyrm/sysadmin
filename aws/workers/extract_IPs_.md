To extract IPs from EC2 instances that are EKS worker nodes using the AWS CLI, you can use the aws ec2 describe-instances command to retrieve information about your EC2 instances, filter the results to only include instances that are part of your EKS worker node group, and then extract the IP addresses from the output.

Here's an example command that retrieves the private IP addresses of all instances that are part of your EKS worker node group:

```
aws ec2 describe-instances \
    --filters "Name=tag:eks:cluster-name,Values=<cluster-name>" \
              "Name=tag:eks:nodegroup-name,Values=<nodegroup-name>" \
    --query "Reservations[].Instances[].PrivateIpAddress" \
    --output text
    
```

Replace <cluster-name> and <nodegroup-name> with the names of your EKS cluster and worker node group, respectively.

This command uses the --filters option to only include instances that have the eks:cluster-name and eks:nodegroup-name tags set to the specified values. It then uses the --query option to extract the PrivateIpAddress property of each instance and the --output option to format the output as plain text.

You can also modify this command to retrieve other information about your instances, such as their public IP addresses or instance IDs, by adjusting the --query option. For example, to retrieve the public IP addresses of your instances, you can use the following command:

```
aws ec2 describe-instances \
    --filters "Name=tag:eks:cluster-name,Values=<cluster-name>" \
              "Name=tag:eks:nodegroup-name,Values=<nodegroup-name>" \
    --query "Reservations[].Instances[].PublicIpAddress" \
    --output text
```    
    
Note that these commands assume that your AWS CLI is configured with the necessary credentials and permissions to access your EC2 instances.

##
##
