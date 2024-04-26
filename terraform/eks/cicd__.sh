# Source: https://gist.github.com/6c8f32fef73abb44f5bf9b873d20fc89
#

#######################################################################################################################################
# Applying GitOps And Continuous Delivery (CD) On Infrastructure Using Terraform, Codefresh, And AWS Elastic Kubernetes Service (EKS) #
#######################################################################################################################################

####################
# Getting The Code #
####################

open https://github.com/vfarcic/cf-terraform-eks

# Replace `[...]` with the GitHub organization
export GH_ORG=[...]

git clone https://github.com/$GH_ORG/cf-terraform-eks

cd cf-terraform-eks

cp orig/*.tf .

cp orig/codefresh.yml .

###########################
# Getting AWS Credentials #
###########################

export AWS_ACCESS_KEY_ID=[...]

export AWS_SECRET_ACCESS_KEY=[...]

export AWS_DEFAULT_REGION=us-east-1

###################################
# Preparing Terraform Definitions #
###################################

export BUCKET_NAME=doc-$(date +%Y%m%d%H%M%S)

aws s3api create-bucket \
    --bucket $BUCKET_NAME \
    --region $AWS_DEFAULT_REGION \
    --acl private

cat variables.tf

open https://docs.aws.amazon.com/eks/latest/userguide/platform-versions.html

export VERSION=[...] # e.g., 1.17

open https://docs.aws.amazon.com/eks/latest/userguide/eks-linux-ami-versions.html

export RELEASE_VERSION=[...] # e.g., 1.17.9-20200904

cat variables.tf \
    | sed -e "s@CHANGE_VERSION@$VERSION@g" \
    | sed -e "s@CHANGE_RELEASE@$RELEASE_VERSION@g" \
    | tee variables.tf

cat main.tf

cat main.tf \
    | sed -e "s@CHANGE_BUCKET@$BUCKET_NAME@g" \
    | tee main.tf

cat output.tf

git add .

git commit -m "Initial commit"

git push

###########################################
# Defining A Continuous Delivery Pipeline #
###########################################

cat codefresh.yml

###############################################
# Creating And Configuring Codefresh Pipeline #
###############################################

open https://codefresh.io/

echo $AWS_ACCESS_KEY_ID

echo $AWS_SECRET_ACCESS_KEY

echo $AWS_DEFAULT_REGION

#######################################
# Applying Infrastructure Definitions #
#######################################

terraform init

terraform refresh

export KUBECONFIG=$PWD/kubeconfig

aws eks update-kubeconfig \
    --name \
    $(terraform output cluster_name) \
    --region \
    $(terraform output region) \
    --alias devops-catalog

kubectl get nodes

############################################################
# Using Pull Requests To Preview Changes To Infrastructure #
############################################################

git checkout -b destroy

git add .

git commit -m "Destroying everything"

git push \
    --set-upstream origin destroy

open https://github.com/$GH_ORG/cf-terraform-eks

git checkout master

##
##
