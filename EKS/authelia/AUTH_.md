##
# https://nextlinklabs.com/insights/handling-authentication-in-EKS-clusters-kubernetes-AWS-IAM
##



Here’s the scenario: You want to deploy a fancy new AWS Elastic Kubernetes Service, or EKS cluster as it’s commonly called, running the latest version of Kubernetes.

You have your Terraform all set to run terraform apply but then you think to yourself… "What about user authentication? How’s that going to work?"

Congratulations, you're off to a good start by asking one of the the most important questions. Like it or not, people other than yourself are going to have to access the cluster. This blog post will walk you through how to get authentication working correctly from the beginning!

One important point before we get started, make sure to deploy your cluster with a role that others can assume. AWS EKS maps some integral permissions to the user/role that is used to create the cluster. This will save you from future headaches.
Legend:
Part I: IAM Users and Groups

    Role and Trust Relationship
    Group and Policy
    User and Group

Part II: IAM Roles and EKS

    Terraform
    eksctl (CloudFormation)
    AWS UI (Manual)

Part III: EKS User and Namespace Permissions

    Cluster Role/RoleBinding

Part IV: Review and Testing

Preface

For those without single sign-on (SSO), leveraging IAM Users and Groups is the recommended way of handling authentication. Part I will explain how to manage auth solely via AWS IAM. If you have single sign-on (SSO) and the ability for users to authenticate via the steps found here, then you can skip to Part II.
Part I: IAM Users and Groups

To start with the basics, IAM is defined as Identity and Access Management within AWS. From Amazon's documentation, IAM users represent the person or service who uses the IAM user to interact with AWS. IAM user groups are simply collections of IAM users. You can use user groups to specify permissions for a collection of users, which can make those permissions easier to manage for those users.

For an exhaustive view into IAM users and groups, check out the full documentation from Amazon.

Now let’s get into the specifics of setting this part up.
1. Create IAM Roles

First, start by creating two IAM roles named eks-admin-role and eks-developer-role with the following CLI commands:

aws iam create-role --role-name eks-admin-role --output text --query 'Role.Arn'

aws iam create-role --role-name eks-developer-role --output text --query 'Role.Arn'

Next, you'll need to edit the trust relationship on each of the roles. Here's the JSON you'll need to do that.

{
  "Version":"2012-10-17",
  "Statement": [
    {
      "Effect":"Allow",
      "Principal":{
        "AWS": [
          "arn:aws:iam::<ACCOUNT_ID>:user/<USER>"
        ]
      },
      "Action":"sts:AssumeRole",
      "Condition":{}
    }
  ]
}

2. Create User Groups and Attach Policy

In order to give the users the ability to assume the roles we created above, we must first create 2 IAM assume role policies. Save the following JSON to a file in your current directory and name it eks-admin-assume-role-policy.json and change the relative variables to match your AWS account number.

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAssumeOrganizationAccountRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<ACCOUNT_ID>:role/eks-admin-role"
    }
  ]
}

Run the following command to create the admin policy:

aws iam create-policy --policy-name eks-admin-assume-role-policy --policy-document file://eks-admin-assume-role-policy

Now we need to create the developer assume role policy. Go ahead and create another JSON file named eks-developer-assume-role-policy.json with the following. Again, make sure you change the ACCOUNT_ID variable to your AWS account id.

{
  "Version": "2012-10-17",
  "Statement": [
    {
        "Sid": "AllowAssumeOrganizationAccountRole",
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "arn:aws:iam::<ACCOUNT_ID>:role/eks-developer-role"
    }
  ]
}

Run the following command to create the developer policy:

aws iam create-policy --policy-name eks-developer-assume-role-policy --policy-document file://eks-developer-assume-role-policy

Now that we have the assume role policies created, we're going to need to create 2 IAM user groups called eks-admin-group and eks-developer-group and attach those policies to grant each user within the groups the ability to assume their relative role.

Here's the command line inputs for the groups:

aws iam create-group eks-admin-group

aws iam put-group-policy --group-name eks-admin-group --policy-name eks-admin-assume-role-policy

aws iam create-group eks-developer-group

aws iam put-group-policy --group-name eks-developer-group --policy-name eks-developer-assume-role-policy
3. Add Users to Created Groups

Finally, add the IAM users to the newly created groups with this command line input:

aws iam add-user-to-group --group-name <GROUP> --user-name <USER>
Part II: IAM Roles and EKS

AWS defines an IAM role as an IAM identity that you can create in your account with specific permissions. Per AWS’s documentation, "an IAM role is similar to an IAM user, in that it is an AWS identity with permission policies that determine what the identity can and cannot do in AWS. However, instead of being uniquely associated with one person, a role is intended to be assumable by anyone who needs it."

From Part I, you should now be able to assume a role in AWS IAM via either SSO or AWS IAM Groups. Now you can move on to configuring your aws-auth config map in EKS.

There are a few options here, depending on how you deployed your cluster:
Option 1: Terraform

Terraform is a software based infrastructure as code tool developed by Hashicorp that we highly recommend for all projects to help retain clear and concise definitions for cloud infrastructure.

One of the nicest things about Terraform is that there are a plethora of public modules available. Specifically, there is a public eks module we will be using with all of the boilerplate code already written, so all that's left is defining some variables for your specific setup. The various inputs for the eks module we will be using can be found here.

If you deploy your cluster via Terraform, leverage your Terraform configuration to add the map_roles=[] variable inside the module "eks" { … } section.

map_roles = [
	{
    “groups”:[ “system:bootstrappers”, “system:nodes”],
    "rolearn":“arn:aws:iam::<ACCOUNT_ID>:role/<EKS_NODE_ROLE>”,
    “username”: “system:node:{{EC2PrivateDNSName}”
	},
  {
    "groups": [ "system:masters" ],
    "rolearn": "arn:aws:iam::<ACCOUNT_ID>:role/eks-admin-role",
    "username": "eks-admin"
  },
  {
    "groups": [ "" ],
    "rolearn": "arn:aws:iam::<ACCOUNT_ID>:role/eks-developer-role",
    "username": "eks-developer"
  }
]

You can see an example terraform setup using this method inside the repository below:

https://github.com/terraform-aws-modules/terraform-aws-eks/tree/v16.0.1/examples/basic

Note: The "username" variable above is what you will use in Part III to associate the role to a role binding internally to Kubernetes. If you’d like to read more about Kubernetes RBAC, take a look at this documentation explaining user auth within the cluster.
Option 2: eksctl

For those that are unfamiliar, eksctl is a simple CLI tool for creating and managing clusters on EKS - Amazon's managed Kubernetes service for EC2. You can learn more about it here.

If you created your cluster via eksctl then use the eksctl create iamidentitymapping cli function.

eksctl create iamidentitymapping --cluster <CLUSTER_NAME> --arn arn:aws:iam::<ACCOUNT_ID>:role/eks-admin-role --group system:masters --username eks-admin`

eksctl create iamidentitymapping --cluster <CLUSTER_NAME> --arn arn:aws:iam::<ACCOUNT_ID>:role/eks-developer-role --username eks-developer

eksctl create iamidentitymapping --cluster <CLUSTER_NAME> --arn arn:aws:iam::<ACCOUNT_ID>:role/eks-developer-role --username eks-developer

Option 3: AWS Console (UI)

Lastly, if you created your cluster via the AWS Console/UI, then use the kubectl CLI to edit the config map via vim.

kubectl edit cm/aws-auth -n kube-system

apiVersion: v1
data:
  mapRoles: |
    - groups:
      - system:bootstrappers
      - system:nodes
      rolearn: arn:aws:iam::<ACCOUNT_ID>:role/<EKS_NODE_ROLE>
      username: system:node:{{EC2PrivateDNSName}}
    - groups:
      - system:masters
      rolearn: arn:aws:iam::<ACCOUNT_ID>:role/eks-admin-role
      username: eks-admin
    - groups: []
      rolearn: arn:aws:iam::<ACCOUNT_ID>:role/eks-developer-role
      username: eks-developer
  mapUsers: |
    []
kind: ConfigMap

Note: Do not add the developer role to any pre-created groups in Kubernetes. This way you can manage their permissions via a role and role-binding within Kubernetes.
Part III: EKS User and Namespace Permissions

Once your AWS IAM Roles are mapped to a Kubernetes user, you can create Kubernetes roles and role bindings to give permissions to various users and the AWS IAM roles they are attached to.

Since we already mapped the AWS role "eks-developer-role" to an internal Kubernetes user called "eks-developer" in Part II, we just need to grant that user permissions within the cluster. In order to do this, we need to create a role within the namespace, so that the user will have permissions. In this example we will grant all permissions to eks-developer in a namespace.

Save the following to a file and name it something along the lines of dev-role-cfg.yml, then go ahead and apply it to a namespace of your choosing.

kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: <NAMESPACE>
  name: eks-developer-role #not to be confused with the AWS IAM role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]

Next, we have to tell Kubernetes that we want to map the "eks-developer" user to the "eks-developer-role" we just created above. We do that by creating a "RoleBinding".

Save the following to a file called dev-rolebinding-cfg.yml and go ahead and apply it.

kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: eks-developer-role-binding
  namespace: <NAMESPACE>
subjects:
- kind: ServiceAccount
  name: eks-developer
  apiGroup: ""
roleRef:
  kind: Role
  name: eks-developer-role
  apiGroup: ""

Part IV: Review and Testing

Let's review what should be in place by this point in the setup:

    IAM Roles (Developer and Admin)
    IAM Groups and Assume Role Policies (Developer and Admin)
    EKS aws-auth ConfigMap (mapRoles) update
    EKS Role and RoleBinding (Developer Role)

After you've confirmed each item in the list above, go ahead and assume the role using the AWS CLI command aws sts assume-role. Once assumed from a user in either the admin or developer group, go ahead and configure your .kube/config file locally by running:

aws eks --region <region> update-kubeconfig --name <cluster_name>

Congratulations on making it this far! You are now ready to run commands against the cluster. At this point you should be able to run any commands as admin and only against a specific namespace if you're logging in using the developer group. To avoid losing access to the cluster, it's critical you deploy the cluster with another admin user or role (not your own).

If you still have questions or want more personalized help, please reach out to us! We offer a variety of DevOps Consulting Services, and we're always happy to help companies of any size with their DevOps strategy.
