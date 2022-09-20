When installing Prisma Cloud on AWS EKS, the deployment creates an AWS Classic Load Balancer (ELB) by default, and Prisma Cloud Console is accessed through the ELB. The ELB is internet-facing, with a security group that serves ports 8081 and 8083 to the internet. In many cases, this is not ideal, because anyone on the internet with the load balancer’s DNS name can access Console’s login page.
Starting with version 1.9.0, Kubernetes supports the AWS Network Load Balancer (NLB). Unlike ELBs, NLBs forward the client’s IP through to the node. You can leverage this property to restrict which IPs can access the NLB by setting .spec.loadBalancerSourceRanges in your deployment file. If .spec.loadBalancerSourceRanges is not set, Kubernetes allows traffic from 0.0.0.0/0 to the Node Security Group(s). If nodes have public IP addresses, be aware that non-NLB traffic can also reach all instances in those modified security groups.
If you utilize a mixed environment, it is sometimes necessary to route traffic from services inside the same VPC. In a split-horizon DNS environment, you would need two services to be able to route both external and internal traffic to your endpoints. This is where an internal load balancer would be useful, allowing more restrictive settings to be applied to the load balancer created by the Prisma Cloud Console deployment.
This guide shows you how to change the configuration of your load balancer. It is controlled by annotations added to your Prisma Cloud Console service deployment file.
For more information about Load Balancing in EKS, see the EKS Load Balancing user guide
Provision a Network Load Balancer
Serve Prisma Cloud Console through a Network Load Balancer.
Prerequisites:
You have already created an EKS cluster.
You have twistlock_console.yaml in your current working directory. This deployment file is generated with the twistcli tool.
Open twistlock_console.yaml for editing.
Add the following annotations to the Service:
annotations: service.beta.kubernetes.io/aws-load-balancer-type: nlb
(Optional) To limit which client IP’s can access the Network Load Balancer, specify the following:
spec:
  loadBalancerSourceRanges:
  - "143.231.0.0/16"
The resulting Service YAML in twistlock_console.yaml should look like this:
---
apiVersion: v1
kind: Service
metadata:
  labels:
    name: console
  name: twistlock-console
  namespace: twistlock
  annotations: service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
spec:
  ports:
  - name: communication-port
    port: 8084
  - name: management-port-https
    port: 8083
  - name: mgmt-http
    port: 8081
  loadBalancerSourceRanges:
  - "143.231.0.0/16"
  selector:
    name: twistlock-console
    name: twistlock-console
  type: LoadBalancer
---
Deploy Prisma Cloud Console.
$ kubectl create -f twistlock_console.yaml
Prisma Cloud Console is served through a Network Load Balancer.
Provision an internal load balancer
Serve Console through an internal load balancer.
For the complete Kubernetes install procedure, see Installing Prisma Cloud on Kubernetes.
For internal load balancers, your Amazon EKS cluster must be configured to use at least one private subnet in your VPC. Kubernetes examines the route table for your subnets to identify whether they are public or private. Public subnets have a route directly to the internet using an internet gateway, but private subnets do not.
Prerequisites:
You have already created an EKS cluster.
You have twistlock_console.yaml in your current working directory. This deployment file is generated with the twistcli tool.
Open twistlock_console.yaml for editing
Add the following annotations to the Service.
annotations: service.beta.kubernetes.io/aws-load-balancer-internal: 0.0.0.0/0
The resulting Service YAML in twistlock_console.yaml should look like this:
---
apiVersion: v1
kind: Service
metadata:
  labels:
    name: console
  name: twistlock-console
  namespace: twistlock
  annotations: service.beta.kubernetes.io/aws-load-balancer-internal: 0.0.0.0/0
spec:
  ports:
  - name: communication-port
    port: 8084
  - name: management-port-https
    port: 8083
  - name: mgmt-http
    port: 8081
  selector:
    name: twistlock-console
    name: twistlock-console
  type: LoadBalancer
---
Deploy Prisma Cloud Console.
$ kubectl create -f twistlock_console.yaml
Prisma Cloud Console is served throught an internal Load Balancer.

#
##
##
##
#


Installing AWS LB Controller add on to EKS
Here are the quick installation and configuration steps to install AWS LB Controller on your EKS Cluster.

We presume you have installed EKS Cluster already.

if you have not created it yet. Refer to this article to create EKS Cluster to Karpenter Autoscaling – Terraform

To manage your existing EKS Cluster, AWS provides a CLI named eksctlwhich you can download/install from here.

eksctl can make use of your awscli profiles for authentication and to communicate to your AWS account.

Enabling OIDC in our EKS Cluster
let us begin with enabling OpenID Connect(OIDC) in our EKS Cluster. this lets our IAM roles be associated directly with Kubernetes service accounts.

It is a new feature where you can associate IAM roles with your Kubernetes Service accounts directly. Read more about it here

⇒ eksctl utils associate-iam-oidc-provider \
    --region us-east-2 \
    --cluster gritfyeks \
    --approve
 

Creating IAM Policy
Once we have enabled the OIDC in our EKS cluster. we can go ahead and download the iam_policyconfiguration needed to be created.

You can directly download it using curl

⇒ curl -o iam_policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.2.0/docs/install/iam_policy.json
Content of the iam_policy.json file available in Github if you would like to directly copy


Now you can use this json file to create your iam policy using aws iam create-policycommand

⇒ aws iam create-policy \
    --policy-name AWSLoadBalancerControllerIAMPolicy \
    --policy-document file://iam_policy.json
 

Creating IAM Service Account and Attach the Policy
Now it’s time to create an iamserviceaccount in our EKS cluster.  we are going to use eksctl for the same.

you need to update the clustername and region before trying this out

this creates a service account named aws-load-balancer-controllerin kube-system namespace and this service, account is associated with IAM policy we created earlier.

You might have to just change the following things before running the command

ClusterName
Policy ARN – ( Just AWS Account Number is enough)
AWS account Region
⇒ eksctl create iamserviceaccount \
--cluster ${YOUR_CLUSTER_NAME} --region ${YOUR_AWS_REGION} \
--namespace kube-system \
--name aws-load-balancer-controller \
--attach-policy-arn arn:aws:iam::${YOUR_AWS_ACCOUNT_NUMBER}:policy/AWSLoadBalancerControllerIAMPolicy \
--override-existing-serviceaccounts \
--approve
Now we have the necessary service accounts and OIDC in place. Now we can go ahead and deploy the aws-load-balancer-controller using helm


 

Installing AWS load balancer controller in EKS with Helm
If you do not have helm installed in your local system. Please install it before continuing. you can find more information about helm here

Let us begin with adding the necessary charts and repository to helm

# helm repo add eks https://aws.github.io/eks-charts
# helm repo update
Once you have executed the helm repo add and  helm repo update

you are good to install the aws-load-balancer-controller

⇒ helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=${Your Cluster Name} \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller
Once the helm chart is successfully deployed. we can verify by listing the aws-load-balancer-controller deployment on the kube-system namespace

⇒ kubectl get deployments aws-load-balancer-controller -n kube-system
NAME READY UP-TO-DATE AVAILABLE AGE
aws-load-balancer-controller 2/2 2 2 56s
Once you have validated that the deployment is present and LIVE. Now we can move on to the next phase of this article.

We are going to deploy and test some sample applications in our EKS Cluster.

This is the Image or Application we are going to deploy.



 

Creating a new deployment in EKS Cluster
To test the load balancer we. need to first deploy some applications to the Kubernetes cluster.

I have taken our famous aksarav/tomcat8 image and deployed it to the cluster with the following single line command


⇒ kubectl create deployment tomcatinfra --image=saravak/tomcat8
deployment.apps/tomcatinfra created
But in real-time you would ideally be creating a deployment with YAML with much more customizations

Since our objective is to test the load balancer with EKS am fastening this with single line deployment creation

Now the deployment is created. The next stage is where the Load Balancer is going to be created.

 

Creating AWS External Load Balancer – with K8s Service EKS
Now we need to expose our application as a service.   To keep things simple we are going to use one-liner commands for this

⇒ kubectl expose deployment tomcatinfra --port=80 --target-port=8080 --type LoadBalancer 
  service/tomcatinfra exposed
when you run the kubectl expose command with your deployment name and the port.  Service would be auto-created

Here is the YAML file of the service, if you do not want to use the one-liner command

apiVersion: v1
kind: Service
metadata:
  name: tomcatappsvc
spec:
  ipFamilies:
  - IPv4
  ipFamilyPolicy: SingleStack
  ports:
  - name: http
    port: 80
    targetPort: 8080
  selector:
    app: tomcatinfra
  type: LoadBalancer
 

As you can see, We are also defining what type of service has to be created using --type LoadBalancer in both formats

If all configurations are in place and done right. You would be able to see that a new  Load Balancer is created




By default when you expose a service. it would become a publicaly available load balancer. In order to make it private we need to special annotations. Will get there.

For now, we have tested how to create an External Load Balancer with aws-load-balancer-controller and expose our deployment as a service

Now let us access our application to validate if it is accessible

EKS Load Balancer

 

Creating AWS Internal Load Balancer – with K8s Service EKS
We have seen how to create an external load balancer with service. we have used a one-liner command to expose our deployment.

It has created the External Load Balancer automatically.

Now we are going to see how to create Internal Load Balancer with Service.

By default when you create a service it would expose the load balancer to the public. but this can be controlled using certain annotations

Let us take a look at the YAML file we are going to use to create our service.

As Classic Load Balancer is going to be deprecated shortly by AWS. I have chosen NLB. So we are now going to create internal network load balancer with EKS

apiVersion: v1
kind: Service
metadata:
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
    service.beta.kubernetes.io/aws-load-balancer-scheme: internal
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
spec:
  ipFamilies:
  - IPv4
  ipFamilyPolicy: SingleStack
  ports:
  - name: http
    port: 80
    targetPort: 8080
  selector:
    app: tomcatinfra
  type: LoadBalancer
Our deployment is still the same as we have used in the last example.

kubectl create deployment tomcatinfra --image=saravak/tomcat8
This is a simple Tomcat Application that exposes a port 8080 in our service that’s the target port and our Service Load balancer is going to listen on port 80

TargetPort should always point to the application exposed port. 80 => 8080

Now let us create the service using this YAML file and validate.

kubectl apply -f internalservice.yml
here is a quick video record of me applying this YAML file in my  EKS cluster.



As you have seen in the screen record the internal Load Balancer was created.

Here are some more screenshots I have taken from the AWS console for the Load Balancer

As you can see a new network Load Balancer has been created and the schema is set to internal

It means we have successfully created an internal load balancer using LB Controller

#
#
#




