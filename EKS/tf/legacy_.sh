# Source: https://gist.github.com/ad78a643e5ccf7bf5fd87b16b29306eb

git clone \
    https://github.com/vfarcic/devops-catalog-code.git

cd devops-catalog-code

git pull

cd terraform-eks

cp files/variables.tf .

cat variables.tf

############################
# Creating The Credentials #
############################

export AWS_ACCESS_KEY_ID=[...]

export AWS_SECRET_ACCESS_KEY=[...]

echo "export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
export AWS_DEFAULT_REGION=us-east-1" \
    | tee creds

source creds

cp files/provider.tf .

cat provider.tf

terraform apply

terraform init

terraform apply

#########################################
# Storing The State In A Remote Backend #
#########################################

cat terraform.tfstate 

cp files/storage.tf .

cat storage.tf

export TF_VAR_state_bucket=doc-$(date +%Y%m%d%H%M%S)

terraform apply

aws s3api list-buckets

terraform show

cat terraform.tfstate

cp files/backend.tf .

cat backend.tf

cat backend.tf \
  | sed -e "s@devops-catalog@$TF_VAR_state_bucket@g" \
  | tee backend.tf

terraform apply

terraform init

terraform apply

##############################
# Creating The Control Plane #
##############################

cp files/k8s-control-plane.tf .

cat k8s-control-plane.tf

open https://docs.aws.amazon.com/eks/latest/userguide/platform-versions.html

export K8S_VERSION=[...] # e.g., 1.15

open https://docs.aws.amazon.com/eks/latest/userguide/eks-linux-ami-versions.html

export RELEASE_VERSION=[...] # e.g., 1.15.11-20200423

terraform apply \
    --var k8s_version=$K8S_VERSION \
    --var release_version=$RELEASE_VERSION

###############################
# Exploring Terraform Outputs #
###############################

cp files/output.tf .

cat output.tf

terraform refresh \
    --var k8s_version=$K8S_VERSION \
    --var release_version=$RELEASE_VERSION

terraform output cluster_name

export KUBECONFIG=$PWD/kubeconfig

aws eks update-kubeconfig \
    --name \
    $(terraform output --raw cluster_name) \
    --region \
    $(terraform output --raw region)

kubectl get nodes

#########################
# Creating Worker Nodes #
#########################

cp files/k8s-worker-nodes.tf .

cat k8s-worker-nodes.tf

terraform apply \
    --var k8s_version=$K8S_VERSION \
    --var release_version=$RELEASE_VERSION

kubectl get nodes

#########################
# Upgrading The Cluster #
#########################

kubectl version --output yaml

open https://docs.aws.amazon.com/eks/latest/userguide/platform-versions.html

export K8S_VERSION=[...] # e.g., 1.16

open https://docs.aws.amazon.com/eks/latest/userguide/eks-linux-ami-versions.html

export RELEASE_VERSION=[...] # e.g., 1.16.8-20200423

terraform apply \
    --var k8s_version=$K8S_VERSION \
    --var release_version=$RELEASE_VERSION

kubectl version --output yaml

################################
# Reorganizing The Definitions #
################################

rm -f *.tf

cat \
    files/backend.tf \
    files/k8s-control-plane.tf \
    files/k8s-worker-nodes.tf \
    files/provider.tf \
    files/storage.tf \
    | tee main.tf

cat main.tf \
    | sed -e "s@bucket = \"devops-catalog\"@bucket = \"$TF_VAR_state_bucket\"@g" \
    | tee main.tf

cp files/variables.tf .

cat variables.tf

cp files/output.tf .

cat output.tf

terraform apply \
    --var k8s_version=$K8S_VERSION \
    --var release_version=$RELEASE_VERSION

############################
# Destroying The Resources #
############################

terraform destroy \
    --var k8s_version=$K8S_VERSION \
    --var release_version=$RELEASE_VERSION

cd ../../
