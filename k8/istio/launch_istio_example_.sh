# Source: https://gist.github.com/d73fb6f4ff490f7e56963ca543481c09

####################
# Create a cluster #
####################

# Follow the instructions from https://github.com/weaveworks/eksctl to intall eksctl if you do not have it already

export AWS_ACCESS_KEY_ID=[...] # Replace [...] with the AWS Access Key ID

export AWS_SECRET_ACCESS_KEY=[...] # Replace [...] with the AWS Secret Access Key

export AWS_DEFAULT_REGION=us-west-2

eksctl create cluster \
    --name chaos \
    --region $AWS_DEFAULT_REGION \
    --node-type t2.large \
    --nodes-max 6 \
    --nodes-min 3 \
    --asg-access \
    --managed

#############################
# Create Cluster Autoscaler #
#############################

IAM_ROLE=$(aws iam list-roles \
    | jq -r ".Roles[] \
    | select(.RoleName \
    | startswith(\"eksctl-chaos-nodegroup\")) \
    .RoleName")

aws iam put-role-policy \
    --role-name $IAM_ROLE \
    --policy-name chaos-AutoScaling \
    --policy-document https://raw.githubusercontent.com/vfarcic/k8s-specs/master/scaling/eks-autoscaling-policy.json

helm repo add stable \
    https://kubernetes-charts.storage.googleapis.com/

helm install aws-cluster-autoscaler \
    stable/cluster-autoscaler \
    --namespace kube-system \
    --set autoDiscovery.clusterName=chaos \
    --set awsRegion=$AWS_DEFAULT_REGION \
    --set sslCertPath=/etc/kubernetes/pki/ca.crt \
    --set rbac.create=true

#################
# Install Istio #
#################

istioctl manifest install \
    --skip-confirmation

export INGRESS_HOST=$(kubectl \
    --namespace istio-system \
    get service istio-ingressgateway \
    --output jsonpath="{.status.loadBalancer.ingress[0].hostname}")

echo $INGRESS_HOST

# Repeat the `export` command if the output of the `echo` command is empty

#######################
# Destroy the cluster #
#######################

IAM_ROLE=$(aws iam list-roles \
    | jq -r ".Roles[] \
    | select(.RoleName \
    | startswith(\"eksctl-chaos-nodegroup\")) \
    .RoleName")

echo $IAM_ROLE

aws iam delete-role-policy \
    --role-name $IAM_ROLE \
    --policy-name chaos-AutoScaling

eksctl delete cluster \
    --name chaos \
    --region $AWS_DEFAULT_REGION

# Delete unused volumes
for volume in `aws ec2 describe-volumes --output text| grep available | awk '{print $8}'`; do 
    echo "Deleting volume $volume"
    aws ec2 delete-volume --volume-id $volume
done

#######################
##
##
