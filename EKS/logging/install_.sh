# Source: https://gist.github.com/30640a949fc64522b5bd289dd87dbb5c

######################
# Create The Cluster #
######################

# Make sure that you're using eksctl v0.1.5+.

# Follow the instructions from https://github.com/weaveworks/eksctl to intall eksctl.

export AWS_ACCESS_KEY_ID=[...] # Replace [...] with AWS access key ID

export AWS_SECRET_ACCESS_KEY=[...] # Replace [...] with AWS secret access key

export AWS_DEFAULT_REGION=us-west-2

export NAME=devops25

mkdir -p cluster

eksctl create cluster \
    -n $NAME \
    -r $AWS_DEFAULT_REGION \
    --kubeconfig cluster/kubecfg-eks \
    --node-type t2.large \
    --nodes-max 9 \
    --nodes-min 3 \
    --asg-access \
    --managed

export KUBECONFIG=$PWD/cluster/kubecfg-eks

###################
# Install Ingress #
###################

kubectl apply \
    -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/1cd17cd12c98563407ad03812aebac46ca4442f2/deploy/mandatory.yaml

kubectl apply \
    -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/1cd17cd12c98563407ad03812aebac46ca4442f2/deploy/provider/aws/service-l4.yaml

kubectl apply \
    -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/1cd17cd12c98563407ad03812aebac46ca4442f2/deploy/provider/aws/patch-configmap-l4.yaml

##################
# Metrics Server #
##################

kubectl create namespace metrics

helm install metrics-server \
    stable/metrics-server \
    --version 2.0.2 \
    --namespace metrics

kubectl -n metrics \
    rollout status \
    deployment metrics-server

##############
# Install CA #
##############

IAM_ROLE=$(aws iam list-roles \
    | jq -r ".Roles[] \
    | select(.RoleName \
    | startswith(\"eksctl-$NAME-nodegroup\")) \
    .RoleName")

echo $IAM_ROLE

aws iam put-role-policy \
    --role-name $IAM_ROLE \
    --policy-name $NAME-AutoScaling \
    --policy-document file://scaling/eks-autoscaling-policy.json

helm install aws-cluster-autoscaler \
    stable/cluster-autoscaler \
    --namespace kube-system \
    --set autoDiscovery.clusterName=$NAME \
    --set awsRegion=$AWS_DEFAULT_REGION \
    --set sslCertPath=/etc/kubernetes/pki/ca.crt \
    --set rbac.create=true

kubectl -n kube-system \
    rollout status \
    deployment aws-cluster-autoscaler
    
##################
# Get Cluster IP #
##################

LB_HOST=$(kubectl -n ingress-nginx \
    get svc ingress-nginx \
    -o jsonpath="{.status.loadBalancer.ingress[0].hostname}")

export LB_IP="$(dig +short $LB_HOST \
    | tail -n 1)"

echo $LB_IP

# Repeat the `export` command if the output is empty

#######################
# Destroy the cluster #
#######################

export AWS_DEFAULT_REGION=us-west-2

aws iam delete-role-policy \
    --role-name $IAM_ROLE \
    --policy-name $NAME-AutoScaling

eksctl delete cluster -n devops25

SG_NAME=$(aws ec2 describe-security-groups \
    --filters Name=group-name,Values=k8s-elb-$LB_NAME \
    | jq -r ".SecurityGroups[0].GroupId")

echo $SG_NAME

aws ec2 delete-security-group \
    --group-id $SG_NAME

for VOLUME in `aws ec2 describe-volumes --region $AWS_DEFAULT_REGION --output text| grep available | awk '{print $8}'`
do
  aws ec2 delete-volume --region $AWS_DEFAULT_REGION --volume-id $VOLUME
done
