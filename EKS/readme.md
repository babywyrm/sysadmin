Please check https://aws.github.io/aws-eks-best-practices/ for more comprehensive EKS best practice!
##
##
#
https://gist.github.com/ejlp12/88962c99e1fd0dd5612b9186f305101a
#
##



![eks-architecture](https://user-images.githubusercontent.com/55672787/199869424-7611baa8-c949-4520-9d1f-3126f51c3b05.svg)

![eks-data-plane-connectivity](https://user-images.githubusercontent.com/55672787/199869495-4bf43540-0de4-4075-a68d-16f070078e8e.jpeg)

##
##
## Architecture
- Think about multi-tenancy, isolation for different environment or different workload
    - Isolation at account level using AWS organization
    - Isolation at the network layer ie. different VPC & different cluster
    - Use different Nodes Group (Node pool) for different purpose/category e.g. create dedicated node groups for Operational tools such as CI/CD tool, Monitoring tool, Centralize logging system. 
    - Separate namespace for different workload
 
## Reliability | [Principles](https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/design-principles.html)
- Recommended to use dedicated VPC for EKS
  - [Modular and Scalable Amazon EKS Architecture](https://docs.aws.amazon.com/quickstart/latest/amazon-eks-architecture/welcome.html)
  - Plan your VPC & Subnet CIDR, avoid complexity of using [multiple CIDRs in a VPC](https://aws.amazon.com/premiumsupport/knowledge-center/eks-multiple-cidr-ranges/) and [CNI custom networking](https://docs.aws.amazon.com/eks/latest/userguide/cni-custom-network.html)
- Understand and check [Service Quota of EKS/Fargate](https://docs.aws.amazon.com/eks/latest/userguide/service-quotas.html) and other related services
- Implement [Cluster Autoscaler](https://aws.github.io/aws-eks-best-practices/cluster-autoscaling/) to automatically adjust the  size of an EKS cluster up and down based on scheduling demands.
- Consider the number of worker nodes and service degradation if there is node/AZ failure. 
  - Mind the RTO.
  - Consider to have buffer node. 
- Consider not to choose very large instance type to reduce blast radius.
- Enable Horizontal Pod Autoscaler to use CPU utilization  or custom metrics to scale out pods.
- Use Infrastructure as code (Kubernetes manifest files and templates to provision EKS clusters/nodes etc) to track changes and  provide auditability
- Use [multiple AZs](https://aws.amazon.com/blogs/containers/amazon-eks-cluster-multi-zone-auto-scaling-groups/). Spread out application replicas to different worker node  availability zones for redundancy
  - Mind with your persistent pods that use EBS as PersistentVolume. Use annotation e.g `topology.kubernetes.io/zone=us-east-1c`
- Highly available and scalable worker nodes using Auto Scaling Groups, use node group
  - Consider to use [Managed Node Groups](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html) for easy setup and high available nodes while updates or temination
  - Consider to use Fargate so you don't have to manage worker nodes. But please beware of Fargate limitation.
- Consider to separate Node Group for your application and utility functions eg. Logging databse, Service Mesh Control Plane
- Deploy [aws-node-termination-handler](https://github.com/aws/aws-node-termination-handler). It detects if node will be unavailable/terminated such as Spot interuption then ensure no new work is scheduled there, then drain it, removing any existing work. [Tutorial](https://eksworkshop.com/beginner/150_spotworkers/deployhandler/) | [Announcement](https://aws.amazon.com/about-aws/whats-new/2019/11/aws-supports-automated-draining-for-spot-instance-nodes-on-kubernetes/)
- Configure [Pod Disruption Budgets](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/) (PDBs) to limits the number of Pods of a replicated application that are down simultaneously from [voluntary disruptions](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/#voluntary-and-involuntary-disruptions) eg. when upgrading, rolling deployment and [other use case](https://kubernetes.io/docs/tasks/run-application/configure-pdb/#think-about-how-your-application-reacts-to-disruptions). 
- Use AWS Backup to backup EFS and EBS
- Use EFS for Storage Class : Using EFS does not require pre-provisioning the  capacity and enables more efficient pod migrations between worker nodes  (removing node-attached  storage)
- Install [Node Problem Detector](https://github.com/kubernetes/node-problem-detector) to provide actionable data  to heal clusters.
- Avoid configuration mistake such as using Anti-affinity that makes pod cannot be rescheduled due to node failure.
- Use Liveness and Readiness Probes
- Practice chaos engineering, use [available tools to automate](https://landscape.cncf.io/category=chaos-engineering&format=card-mode&grouping=category).
  - Kill Pods Randomly During Testing
- Implement failure management in microservice level, e.g. Circuit breaker pattern, Control and limit retry calls (exponential backoff), throttling, make services stateless where possible
- Practice how to upgrade the cluster and worker nodes to new version.
  - Practice how to drain the worker nodes.
- Practice Chaos engineering
- Use CI/CD tools, automate and having process flow (approval/review) for infrastructure changes. Consider to implement Gitops.
- Use multi-AZ solution for persistent volume eg. [Thanos+S3 for Prometheus](https://aws.amazon.com/blogs/opensource/improving-ha-and-long-term-storage-for-prometheus-using-thanos-on-eks-with-s3/)

## Performance Efficiency | [Principles](https://docs.aws.amazon.com/wellarchitected/latest/performance-efficiency-pillar/design-principles.html)
- Inform AWS support if you need to pre-scale the Control Plane (Master node & Etcd) in case of sudden load increment
- Choose the right [EC2 instance type](https://aws.amazon.com/ec2/instance-types/) for your worker node.
  - Undestand the [pros & cons](https://learnk8s.io/kubernetes-node-size) of using many small node instances or few large node instances. Consider the OS overhead, time required to pull image in a new instance when it scale, kubelet overhead, system pod overhead, etc.  
  - Understand the pod density limitation ([maximum number of pods](https://github.com/awslabs/amazon-eks-ami/blob/master/files/eni-max-pods.txt) supported by each instance type)
- Use single-AZ node groups if necessary. Typically, one of the best practices is to run a microservice across Multi-AZ for availability, but for some workload (such as Spark) that need micro-second latency, having high network I/O operation and transient, it is make send to use single-AZ.
- Understand the [performance limitation of Fargate](https://github.com/aws/containers-roadmap/issues/715). Do the load test before going to production.
- Ensure your pod requests the resources it needs. Define `request` and `limit` resources such as CPU, memory
- Detect bottleneck/latency in a microservice with X-Ray, or [other tracing/APM products](https://landscape.cncf.io/category=tracing&format=card-mode&grouping=category)
- Choose the right storage backend. Use [Amazon FSx for Lustre](https://aws.amazon.com/fsx/lustre/) and its [CSI Driver](https://github.com/kubernetes-sigs/aws-fsx-csi-driver) if your persistent container need high-performance file system
- Monitor pod & nodes resource consumption and detech bottlenect. You can use CloudWatch, [CloudWatch Container Insight](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html), or [other products](https://landscape.cncf.io/category=monitoring&format=card-mode&grouping=category)
- If needed, launch instances (worker nodes) in [Placement Groups](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html) to leverage low latency without any slowing. You can use this [CloudFormation Template](https://github.com/aws-samples/aws-eks-deep-learning-benchmark/blob/master/blog-post-sample/eks_cluster/amazon-eks-nodegroup-placementgroup.yaml) to add new node groups with non-blocking, non-oversubscribed, fully bi-sectional connectivity.
- If needed, setup [Kubernetes CPU Management policy to 'static'](https://kubernetes.io/docs/tasks/administer-cluster/cpu-management-policies/#cpu-management-policies) for some pods who need exclusive CPUs 
 
## Cost Optimization
- Minimize the wasted (unused) resources when using EC2 as worker node. 
  - Choose the right EC2 instance type and use cluster auto scaling. 
  - Consider to use Fargate 
  - Consider to use a tool like [kube-resource-report](https://github.com/hjacobs/kube-resource-report) to visualizing the slack cost and right sizing the requests for the containers in a pod.
- Use Spot Instances or mix On-Demand and Spot by utilizing [Spot Fleet](https://aws.amazon.com/blogs/aws/ec2-fleet-manage-thousands-of-on-demand-and-spot-instances-with-one-request/). Consider using Spot instances for Test/Staging env.
- Use Reserved Instance or Saving Plans
- Use single-AZ node groups for workload with high network I/O operation (e.g. Spark) to reduce cross-AZ communication. But please validate if running Single-AZ wouldn’t compromise availability of your system.
- Consider managed services for supporting tool such as monitoring, service mesh, cetralized logging, to redure your team effort & cost
- Tag all AWS resources when possible and use Labels to tag Kubernetes resources so that you can easily analyze the cost.
- Consider to use self-manage Kubernetes (not using EKS) for non-HA cluster. You can setup using [Kops](https://github.com/kubernetes/kops) for your small k8s cluster. 
- Use Node Affinities using nodeSelector for pod that requires specific EC2 instance type.
 
## Operation: [Principles](https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/design-principles.html)
- Use IaC tool for provisioning the EKS cluster such as
  - CloudFormation. 
    - [Reference deloyment](https://aws.amazon.com/quickstart/architecture/amazon-eks/)
    - [Deploy self-manage nodes](https://amazon-eks.s3.us-west-2.amazonaws.com/cloudformation/2020-08-12/amazon-eks-nodegroup.yaml)
  - [Terraform](https://learn.hashicorp.com/tutorials/terraform/eks) 
  - [Eksctl](https://eksctl.io/)
  - [AWS CDK](https://medium.com/faun/spawning-an-autoscaling-eks-cluster-52977aa8b467)
- Consider to use package manager like [Helm](https://docs.aws.amazon.com/eks/latest/userguide/helm.html) to helps you install and manage applications.
- Automate cluster management and applicatoin deployment using [GitOps](https://www.weave.works/technologies/gitops/). You can use tools like [Flux](https://fluxcd.io/) or [others](https://github.com/weaveworks/awesome-gitops | [workshop](https://www.eksworkshop.com/intermediate/260_weave_flux/)
- Use [CI/CD tools](https://landscape.cncf.io/category=continuous-integration-delivery&format=card-mode&grouping=category)
- Practice to do EKS upgrade (rolling update), create runbook.
      - [GitHub - hellofresh/eks-rolling-update: EKS Rolling Update is a utility for updating the launch configuration of worker nodes in an EKS cluster.](https://github.com/hellofresh/eks-rolling-update)
      - [Open Sourcing EKS Rolling Update: A Tool for Updating Amazon EKS Clusters](https://engineering.hellofresh.com/open-sourcing-eks-rolling-update-a-tool-for-updating-amazon-eks-clusters-5cef5b497a95)
- Monitoring
  - Understand your Workload Health. Define KPI/SLO and metrics/SLI then monitor through your dashboard & setup alerts
  - Understand your Operational Health. Define KPI and metrics such as mean time to detect an incident (MTTD), and mean time to recovery (MTTR) from an incident. 
  - Use detailed monitoring using [Container Insights for EKS](https://docs.aws.amazon.com/en_pv/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-EKS-quickstart.html) to drill down into service, pods performance. It also provides diagnostic information and consider to view additional metrics and additional levels of granularity when a problem occurs.
  - Monitor [control plane metrics using Prometheus](https://docs.aws.amazon.com/en_pv/eks/latest/userguide/prometheus.html)
  - [Monitoring using Prometheus & Grafana](https://www.eksworkshop.com/intermediate/240_monitoring/)
- Logging
  - Consider DaemonSet vs Sidecar mechanism. DaemonSet is preferable EC2 worker node, but you need to use Sidecar pattern for Fargate.
  - [Control Plane Logging](https://docs.aws.amazon.com/en_pv/eks/latest/userguide/control-plane-logs.html)
  - You can use [EFK stack](https://www.eksworkshop.com/intermediate/230_logging/) or [FluentBit, Kinesis Data Firehouse, S3 and Athena](https://aws.amazon.com/blogs/opensource/centralized-container-logging-fluent-bit/)
- Tracing
  - Monitor fine-graid transaction using X-Ray [eksworkshop.com](https://eksworkshop.com/x-ray/). It is good to monitor blu-green deployment too. [Other tools](https://landscape.cncf.io/category=tracing&format=card-mode&grouping=category)
- Practice the Chaos Engineering, you can automate using [some tools](https://landscape.cncf.io/category=chaos-engineering&format=card-mode&grouping=category)
- Configuration
  - Appmesh + EKS demo / lab: [GitHub - PaulMaddox/aws-appmesh-helm: AWS App Mesh ❤ K8s](https://github.com/PaulMaddox/aws-appmesh-helm)    
  - AWS Cloud Map:
    - [AWS Cloud Map: Easily create and maintain custom maps of your applications | AWS News Blog](https://aws.amazon.com/blogs/aws/aws-cloud-map-easily-create-and-maintain-custom-maps-of-your-applications/)
    - AWS CloudMap + Consul:
      - [AWS re:Invent 2018: NEW LAUNCH! Introducing AWS Cloud Map (CON366) - YouTube](https://youtu.be/fMGd9IUaotE?t=1982)
      - [AWS Cloud Map and Consul Catalog Sync - YouTube](https://www.youtube.com/watch?v=203K6JIpYcI)
      - [Managing Microservice Deployments on AWS with HashiCorp Consul - YouTube](https://www.youtube.com/watch?v=gZLbF26hBps)

## Security | [Principles](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/design-principles.html)
- Understand the [shared responsibility model](https://aws.amazon.com/blogs/containers/introducing-cis-amazon-eks-benchmark/) for different EKS operation modes (self-managed nodes, managed node group, Fargate)
- [AWS Security Best Practices for EKS](https://aws.github.io/aws-eks-best-practices/) 
- Integrating security into your container pipeline | [workshop](https://container-devsecops.awssecworkshops.com/)
- Use [CNI custom networking](https://docs.aws.amazon.com/eks/latest/userguide/cni-custom-network.html), if your pod need to have different Security Group with its nodes, or pods to be placed in private subnets but the node is actually in public subnet.
- [Cloudtrail EKS API log](https://docs.aws.amazon.com/en_pv/eks/latest/userguide/logging-using-cloudtrail.html)
  - Consinder to enable continuous delivery of CloudTrail events to an Amazon S3 bucket by [creating a trail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html) to records events < past 90 days
- Use network policy for East-West traffic: [Calico](https://docs.aws.amazon.com/en_pv/eks/latest/userguide/calico.html) 
- Use [security groups for pods](https://aws.amazon.com/blogs/containers/introducing-security-groups-for-pods/) only for K8s > v1.17. See some [consideration](https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html)
- [Introducing Fine-Grained IAM Roles for Service Accounts | AWS Open Source Blog](https://aws.amazon.com/blogs/opensource/introducing-fine-grained-iam-roles-service-accounts/)
- [Use AWS Key Management Service (KMS) keys to provide envelope encryption of Kubernetes secrets stored](https://aws.amazon.com/blogs/containers/using-eks-encryption-provider-support-for-defense-in-depth/)

###################################
###################################

deploy-to-eks.yml
# eks.yml
on:
  pull_request:
  push:
    branches:         # array of glob patterns matching against refs/heads. Optional; defaults to all
    - master          # triggers on pushes that contain changes in master

name: Build and Deploy to EKS

env:
  AWS_REGION: us-east-2
  CONTAINER_IMAGE: example-eks:${{ github.sha }}

jobs:
  build-and-deploy:
    name: Build and deploy
    runs-on: ubuntu-latest
    steps:
    - name: Context
      env:
        GITHUB_CONTEXT: ${{ toJson(github) }}
      run: |
        echo "$GITHUB_CONTEXT"
    - name: Checkout
      uses: actions/checkout@master

    - name: Setup AWS
      env:
        AWS_HOME: ${{ runner.temp }}/.aws
        AWS_CONFIG_FILE: ${{ runner.temp }}/.aws/config
        AWS_SHARED_CREDENTIALS_FILE: ${{ runner.temp }}/.aws/credentials
      run: |
        # Set the PATH to include our binaries
        mkdir -p "${HOME}/.local/bin"
        export PATH="${HOME}/.local/bin:${PATH}"
        echo "::set-env name=PATH,::${PATH}"
        # Configure AWS
        mkdir -p "${AWS_HOME}"
        echo "::set-env name=AWS_CONFIG_FILE,::${AWS_CONFIG_FILE}"
        echo "::set-env name=AWS_SHARED_CREDENTIALS_FILE,::${AWS_SHARED_CREDENTIALS_FILE}"
        aws configure set default.region $AWS_REGION
        aws configure set default.output json
        aws configure set aws_access_key_id ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws configure set aws_secret_access_key ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        # Validate AWS credentials
        aws sts get-caller-identity
    - name: Setup ECR
      run: |
        # Login to AWS ECR
        $( aws ecr get-login --region $AWS_REGION --no-include-email )
    - name: Setup Kube Context
      env:
        KUBECONFIG: ${{ runner.temp }}/.kube/config
      run: |
        # Setup AWS IAM Authenticator for Kubernetes
        cd $( mktemp -d )
        curl -o aws-iam-authenticator --location https://amazon-eks.s3-us-west-2.amazonaws.com/1.13.7/2019-06-11/bin/linux/amd64/aws-iam-authenticator
        chmod +x ./aws-iam-authenticator
        mv ./aws-iam-authenticator "${HOME}/.local/bin"
        aws-iam-authenticator help
        # Setup kustomize
        cd $( mktemp -d )
        curl -o kustomize --location https://github.com/kubernetes-sigs/kustomize/releases/download/v3.1.0/kustomize_3.1.0_linux_amd64
        chmod u+x ./kustomize
        mv ./kustomize "${HOME}/.local/bin"
        # Setup Kube Config
        mkdir -p "${RUNNER_TEMP}/.kube"
        echo "::set-env name=KUBECONFIG,::${KUBECONFIG}"
        echo "${{ secrets.KUBE_CONFIG_DATA }}" | base64 --decode > "${KUBECONFIG}"
    - name: Build, tag, and save the image
      run: |
        # Build and tag the image
        docker build \
          -t $CONTAINER_IMAGE \
          -t $GITHUB_REPOSITORY:$GITHUB_SHA \
          -t ${{ secrets.AWS_ACCOUNT_ID }}.dkr.ecr.$AWS_REGION.amazonaws.com/$CONTAINER_IMAGE .
        # Save the image so it can be uploaded as an artifact
        docker save $CONTAINER_IMAGE | gzip > ./example-eks.tar.gz
        du -h ./example-eks.tar.gz
    - name: Upload artifact
      uses: actions/upload-artifact@v1.0.0
      with:
        name: docker-image
        path: ./example-eks.tar.gz

    - name: Deploy
      if: github.ref == 'refs/heads/master'
      run: |
        # Push image to AWS ECR
        docker push ${{ secrets.AWS_ACCOUNT_ID }}.dkr.ecr.$AWS_REGION.amazonaws.com/$CONTAINER_IMAGE
        # Apply configuration to cluster
        export KUBECONFIG="${RUNNER_TEMP}/.kube/config"
        kustomize edit set image ${{ secrets.AWS_ACCOUNT_ID }}.dkr.ecr.$AWS_REGION.amazonaws.com/example-eks:${GITHUB_SHA}
        kustomize build . | kubectl apply -f -
        # Verify deployment
        kubectl rollout status deployment/aws-example-octodex
        # List Public IP of cluster
        kubectl get services -o wide
notes.md
Notes
Capturing some notes on how I setup my EKS cluster, as it took several attempts 😂 😳

AWS Account
I created a brand new AWS account, since I kept bumping up against limits when using the existing GitHub / Professional Services AWS. I made a careful note of:

My AWS account id
My Access Key ID
My Secret Access Key
Despite what the AWS docs say, I used my root credentials throughout this demo, just to save time.

Installation
I followed the steps from this guide to setup aws, eksctl, kubectl, and aws-iam-authenticator locally:

pip install awscli --upgrade --user

# Install eksctl
brew tap weaveworks/tap

brew install weaveworks/tap/eksctl

eksctl version
# [ℹ]  version.Info{BuiltAt:"", GitCommit:"", GitTag:"0.3.1"}
Install and Configure kubectl for Amazon EKS
It's already done for us on macOS (thanks homebrew 🙇):

which kubectl
# /usr/local/bin/kubectl

which aws-iam-authenticator
# /Users/swinton/go/bin/aws-iam-authenticator
Create Your Amazon EKS Cluster and Worker Nodes
Despite what this page says, I just did:

eksctl create cluster
I had to wait for my AWS account to be approved before this would work. It seems the account has to be approved for each region separately, when it comes to EKS.

Eventually I was able to get an EKS cluster running in the us-east-2 region.

Access the cluster
# When your cluster is ready, test that your kubectl configuration is correct
kubectl get svc
Generate a kube config
CLUSTER_NAME=fabulous-monster-1565378541  # this was generated from the above eksctl create cluster command 
AWS_DEFAULT_REGION=us-east-2
aws eks update-kubeconfig --name $CLUSTER_NAME --region $AWS_DEFAULT_REGION
This generates a ~/.kube/config file, I then base64-encoded the contents of this file and saved it as a secret, KUBE_CONFIG_DATA, in my @bbq-beets repo.

cat ~/.kube/config | base64 | pbcopy
ECR
For the demo to work, it's also necessary to create an ECR registry, in the same AWS region as the EKS cluster (us-east-2 in my case). I did this directly via the AWS console:

Screen Shot 2019-08-13 at 2 57 08 PM

I then updated the kube config.yml to match this ECR registry URI.

Secrets
The following secrets are also required:

Screen Shot 2019-08-13 at 2 49 11 PM

AWS_ACCOUNT_ID: My AWS account id
AWS_ACCESS_KEY_ID: My Access Key ID for my root account, which isn't the ideal, but it works
AWS_SECRET_ACCESS_KEY: My Secret Access Key for my root account, which isn't the ideal, but it works
AWS_ECR_PASSWORD: The password for ECR, obtained via aws ecr get-login --region $AWS_REGION --no-include-email
KUBE_CONFIG_DATA: From the above, cat ~/.kube/config | base64 | pbcopy

###############
##
##
##


TL;DR: In this guide, you will learn how to create clusters on the AWS Elastic Kubernetes Service (EKS) with eksctl and Terraform. By the end of the tutorial, you will automate creating three clusters (dev, staging, prod) complete with the ALB Ingress Controller in a single click.

EKS is a managed Kubernetes service, which means that Amazon Web Services (AWS) is fully responsible for managing the control plane.

In particular, AWS:

    Manages Kubernetes API servers and the etcd database.
    Runs the Kubernetes control-plane across three availability zones.
    Scales the control-plane as you add more nodes to your cluster.
    Provides a mechanism to upgrade your control plane to a newer version.
    Rotates certificates.
    And more.

If you're running your cluster, you should still build all of those features.

However, when you use EKS, you outsource them to Amazon Web Service for a price: USD0.10 per hour per cluster.

    Please notice that Amazon Web Services has a 12 months free tier promotion when you sign up for a new account. However, EKS is not part of the promotion.

The rest of the guide assumes that you have an account on Amazon Web Service.

If you don't, you can sign up here.

This is a hands-on guide — if you prefer to look at the code, you can do so here.
Table of contents

    Three popular options to provision an EKS cluster
    But first, let's set up the AWS account
    Eksctl: the quickest way to provision an EKS cluster
    You can also define eksctl clusters in YAML, but the tools has its limits
    You can provision an EKS cluster with Terraform too
    Eksctl vs Terraform — pros and cons
    Testing the cluster by deploying a simple Hello World app
    Routing traffic into the cluster with the ALB Ingress Controller
    Provisioning a full cluster with Ingress with the Helm provider
    Fully automated Dev, Staging, Production environments with Terraform modules
    Summary and next steps

Three popular options to provision an EKS cluster

There are three popular options to run and deploy an EKS cluster:

    You can create the cluster from the AWS web interface.
    You can use the eksctl command-line utility.
    You can define the cluster as using code with a tool such as Terraform.

Even if it is listed as the first option, creating a cluster using the AWS interface is discourage and for a good reason.

There are plenty of configuration options and screens that you have to complete before you can use the cluster.

When you create the cluster manually, can you be sure that:

    You did not forget to change one of the parameters?
    You can repeat precisely the same steps while creating a cluster for other environments?
    When there is a change, you can apply the same modifications in sequence to all clusters without any mistake?

The process is error-prone and doesn't scale well if you have more than a single cluster.

A better option is to define a file that contains all the configuration flags and use that as a blueprint to create the cluster.

And that's precisely what you can do with tools such as eksctl and Terraform.
But first, let's set up the AWS account

Before you can start using eksctl and Terraform, you have to install the AWS CLI.

This tool is necessary to authenticate your requests to your account on Amazon Web Services.

You can find the official documentation on how to install the AWS CLI here.

After you install the AWS CLI you should run:

bash

aws --version
aws-cli/2.0.40 Python/3.8.5 Darwin/19.6.0 source/x86_64

If you can see the version in the output, that means the installation is successful.

Next, you need to link your account to the AWS CLI.

For this part, you will need:

    AWS Access Key ID.
    AWS Secret Access Key.
    Default region name.
    Default output format.

The essential parts you need are the first two: the Access Key ID and the Secret Access Key.

Those credentials are displayed only once after you create a user on the AWS web interface.

To do so, follow these instructions:

    Log in to your AWS Management Console.
    1/13

    Log in to your AWS Management Console.
    Next 

Now that you have the keys, you enter all the details:

bash

aws configure
AWS Access Key ID [None]: <enter the access key>
AWS Secret Access Key [None]: <enter the secret key>
Default region name [None]: <eu-west-2>
Default output format [None]: <None>

    Please notice that the list of available regions can be found here

The AWS CLI lets you interact with AWS without using the web interface.

You can try listing all your EKS clusters with:

bash

aws eks list-clusters
{
    "clusters": []
}

An empty list — it makes sense, you haven't created any yet.

Now that you have your account on AWS set up, it's time to use eksctl.
Eksctl: the quickest way to provision an EKS cluster

Eksctl is a convenient command-line tool to create an EKS cluster with a few simple commands.

So what's the difference with the AWS CLI?

Isn't the AWS CLI enough to create resources?

The AWS CLI has a command to create an EKS cluster: aws eks create-cluster.

However, the command only creates a control plane.

It does not create any worker node, set up the authentication, permissions, etc.

On the other hand, eksctl is an aws eks on steroids.

With a single command, you have a fully functioning cluster.

Before diving into an example, you should install the eksctl binary.

You can find the instructions on how to install eksctl from the official project page.

You can verify that eksctl is installed correctly with:

bash

eksctl version
0.25.0

Eksctl uses the credentials from the AWS CLI to connect to your account.

So you can spin up a cluster with:

bash

eksctl cluster create

The command makes a few assumptions about the cluster that you want:

    It creates a control plane (managed by AWS).
    It joins two workers nodes.
    It selects the m5.large as an instance type.
    It creates the cluster in the us-west-2 region.

If the cluster isn't quite what you had in mind, you can easily customise the settings to fit your needs.

Of course, you can change the region or include an instance type that is covered by the free tier offer such as a t2.micro.

Also, why not including autoscaling?

You can create a new cluster with:

bash

eksctl create cluster \
  --name learnk8s-cluster \
  --node-type t2.micro \
  --nodes 3 \
  --nodes-min 3 \
  --nodes-max 5 \
  --region eu-central-1

The command creates a control plane:

    In the region eu-central-1 (Frankfurt).
    With cluster name as "learnk8s-cluster".
    Using t2.micro instances.
    The worker instances will autoscale based on load (from 3 to a maximum of 5 nodes).

    Please notice that the command could take about 15 to 20 minutes to complete.

In this time, eksctl:

    Uses the AWS CLI credentials to connect to your account on AWS.
    Creates cloud formation templates for the EKS cluster as well as the node groups. That includes AMI images, versions, volumes, etc.
    Creates all the necessary networking plumbing such as the VPC, subnets, and IP addresses.
    Generates the credentials needed to access the Kubernetes cluster — the kubeconfig.

While you are waiting for the cluster to be provisioned, you should download kubectl — the command-line tool to connect and manage the Kubernetes cluster.

Kubectl can be downloaded from here.

You can check that the binary is installed successfully with:

bash

kubectl version --client

It should give you the version as the output.

Once your cluster is ready, you will be greeted by the following line.

bash

[output truncated]
[✔]  EKS cluster "learnk8s-cluster" in "eu-central-1" region is ready

You can verify that the cluster is running by using:

bash

eksctl get cluster --name learnk8s-cluster --region eu-central-1

It works!

Let's list all the Pods in the cluster:

bash

kubectl get pods --all-namespaces
kube-system   aws-node-j4x9b            1/1     Running   0          4m11s
kube-system   aws-node-lzqkd            1/1     Running   0          4m12s
kube-system   aws-node-vj7rh            1/1     Running   0          4m12s
kube-system   coredns-5fdf64ff8-7zb4g   1/1     Running   0          10m
kube-system   coredns-5fdf64ff8-x5dfd   1/1     Running   0          10m
kube-system   kube-proxy-67967          1/1     Running   0          4m12s
kube-system   kube-proxy-765wd          1/1     Running   0          4m12s
kube-system   kube-proxy-gxjdn          1/1     Running   0          4m11s

You can see from the kube-system namespace, that Kubernetes created the mandatory pods needed to run the cluster.

With this, you have successfully created and connected to a fully functional Kubernetes cluster.

Congrats!

Contain your excitement, though — you will immediately destroy the cluster.

There's a better way to create clusters with eksctl, and that's by defining what you want in a YAML file.
You can also define eksctl clusters in YAML, but the tools has its limits

When you have all the cluster configuration in a single file, you can:

    Store in Git or any other version control.
    Share it with your friends and colleagues.
    Recall what the last configuration applied to the cluster was.

Before exploring the YAML configuration for eksctl, let's destroy the current cluster with:

bash

eksctl delete cluster --name learnk8s-cluster --region eu-central-1

Do not forget to let the command finish and do its job, otherwise terminating prematurely may leave a few dangling resources (which you will be billed for).

You should see the following command output after the deletion is completed:

bash

[output truncated]
[✔]  all cluster resources were deleted

Eksctl lets you create clusters that are defined in YAML format.

You can define your cluster and node specification and pass that file to eksctl so it can create the resources.

Let's have a look at how it works.

Create a cluster.yaml file with the following content:

cluster.yaml

apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: learnk8s
  region: eu-central-1
nodeGroups:
  - name: worker-group
    instanceType: t2.micro
    desiredCapacity: 3
    minSize: 3
    maxSize: 5

You can already guess what the above cluster will look like when deployed.

It's the same cluster that you created earlier with the command line arguments, but this time all of the requirements are stored in the YAML.

It's a cluster:

    In the region eu-central-1 (Frankfurt).
    With cluster name as "learnk8s-cluster".
    Using t2.micro instances.
    The worker instances will autoscale based on load (from 3 to a maximum of 5 nodes).

You can create a cluster by feeding the YAML configuration with:

bash

eksctl create cluster -f cluster.yaml

Again, be patient here.

The command will need 10-15 minutes to complete provisioning the resources.

You can verify that the cluster was created successfully with:

bash

eksctl get cluster --name learnk8s
NAME         VERSION    STATUS
learnk8s        1.17    ACTIVE

And you are done, you've successfully provisioned a cluster with eksctl and YAML.

If you want, you can save that file in version control.

You may ask yourself what happens when you apply the same configuration again?

Does it update the cluster?

Let's try:

bash

eksctl create cluster -f cluster.yaml
[✖]  Stack [eksctl-learnk8s-cluster] already exists status code: 400

You won't be able to amend the specification since the create command is only used in the beginning to make the cluster.

At the moment, there is no command designed to read the YAML and update the cluster to the latest changes.

    Please notice that the feature is on the roadmap, though.

If you want to describe the cluster as a static file, but incrementally update the configuration, you might find Terraform more suitable.
You can provision an EKS cluster with Terraform too

Terraform is an open-source Infrastructure as Code tool.

Instead of writing the code to create the infrastructure, you define a plan of what you want to be executed, and you let Terraform create the resources on your behalf.

The plan isn't written in YAML though.

Instead Terraform uses a language called HCL - HashiCorp Configuration Language.

In other words, you use HCL to declare the infrastructure you want to be deployed, and Terraform executes the instructions.

Terraform uses plugins called providers to interface with the resources in the cloud provider.

This further expands with modules as a group of resources and are the building blocks that you are going to use to create a cluster.

But let's take a break from the theory and see those concepts in practice.

Before you can create a cluster with Terraform, you should install the binary.

You can find the instructions how to install the Terraform CLI from the official documentation.

Verify that the Terraform tool has been installed correctly with:

bash

terraform version
Terraform v0.13.5

Now start by creating a new folder, and in that folder create a file named main.tf.

The .tf extension is for Terraform files.

In the main.tf copy and paste the following code:

main.tf

provider "aws" {
  region = "ap-south-1"
}

data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_id
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
  load_config_file       = false
  version                = "~> 1.11"
}

data "aws_availability_zones" "available" {
}

locals {
  cluster_name = "my-cluster"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "2.47.0"

  name                 = "k8s-vpc"
  cidr                 = "172.16.0.0/16"
  azs                  = data.aws_availability_zones.available.names
  private_subnets      = ["172.16.1.0/24", "172.16.2.0/24", "172.16.3.0/24"]
  public_subnets       = ["172.16.4.0/24", "172.16.5.0/24", "172.16.6.0/24"]
  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "12.2.0"

  cluster_name    = "${local.cluster_name}"
  cluster_version = "1.17"
  subnets         = module.vpc.private_subnets

  vpc_id = module.vpc.vpc_id

  node_groups = {
    first = {
      desired_capacity = 1
      max_capacity     = 10
      min_capacity     = 1

      instance_type = "m5.large"
    }
  }

  write_kubeconfig   = true
  config_output_path = "./"
}

    You can find the code in this GitHub repository too.

That's a lot of code!

Bear in mind with me.

You will learn everything about it as soon as you're done creating the cluster.

In the same folder, run:

bash

terraform init

The command will initialise Terraform and create two more folders as well as a state file.

The state file is used to keep track of the resources that have been created already.

Consider this as a checkpoint, without it Terraform won't know what has been already created or updated.

There is another command that you can utilize in your undertaking with Terraform.

To quickly check if the configuration doesn't have any configuration errors you can do so with:

bash

terraform validate
Success! The configuration is valid.

Next, you should run:

bash

terraform plan
[output truncated]
Plan: 42 to add, 0 to change, 0 to destroy.

Terraform will perform a dry-run and will prompt you a detailed summary of what resources is about to create.

If you feel confident that everything looks fine, you can create the resources with:

bash

terraform apply
Apply complete! Resources: 42 added, 0 changed, 0 destroyed.

You will be asked to confirm your choices — just type yes.

The process takes about 20 minutes to provision all resources, which is the same time it takes for eksctl to create the cluster.

When it's complete, if you inspect the current folder, you should notice a few new files:

bash

tree .
.
├── kubeconfig_my-cluster
├── main.tf
├── terraform.tfstate
└── terraform.tfstate.backup

terraform.tfstate and terraform.tfstate.backup are the two files used by Terraform to keep track of what resources were created.

The kubeconfig_my-cluster is the kubeconfig for the newly created cluster.

You can test the connection with the cluster by using that file with:

bash

KUBECONFIG=./kubeconfig_my-cluster kubectl get pods --all-namespaces
NAMESPACE     NAME                       READY   STATUS    AGE
kube-system   aws-node-kbncq             1/1     Running   10m
kube-system   coredns-56666f95ff-l5ppm   1/1     Running   23m
kube-system   coredns-56666f95ff-w9brq   1/1     Running   23m
kube-system   kube-proxy-98vcw           1/1     Running   10m

Excellent the cluster is ready to be used.

If you prefer to not prefix the KUBECONFIG environment variable to every command, you can export it with:

bash

export KUBECONFIG="${PWD}/kubeconfig_my-cluster"

The export is valid only for the current terminal session.

Now that you've created the cluster, it's time to go back and discuss the Terraform file.

The Terraform file that you just executed is divided into two blocks:

main.tf

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "2.47.0"

  name                 = "k8s-vpc"
  cidr                 = "172.16.0.0/16"
  private_subnets      = ["172.16.1.0/24", "172.16.2.0/24", "172.16.3.0/24"]
  public_subnets       = ["172.16.4.0/24", "172.16.5.0/24", "172.16.6.0/24"]

  # truncated
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "12.2.0"

  cluster_name    = "${local.cluster_name}"
  cluster_version = "1.17"
  subnets         = module.vpc.private_subnets

  vpc_id = module.vpc.vpc_id

  # truncated
}

The first block is the VPC module.

In this part, you instruct Terraform to create:

    A VPC.
    Three private and three public subnets.
    A single NAT gateway.
    Tags for the subnets.

The tags for subnets are quite crucial as those are used by AWS to automatically provision public and internal load balancers in the appropriate subnets.

The second important block in the Terraform file is the EKS cluster module:

main.tf

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "2.47.0"

  name                 = "k8s-vpc"
  cidr                 = "172.16.0.0/16"
  private_subnets      = ["172.16.1.0/24", "172.16.2.0/24", "172.16.3.0/24"]
  public_subnets       = ["172.16.4.0/24", "172.16.5.0/24", "172.16.6.0/24"]

  # truncated
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "12.2.0"

  cluster_name    = "${local.cluster_name}"
  cluster_version = "1.17"
  subnets         = module.vpc.private_subnets

  vpc_id = module.vpc.vpc_id

  # truncated
}

The EKS module is in charge of:

    Creating the control plane.
    Setting up autoscaling groups.
    Setting up the proper security groups.
    Creating the kubeconfig file.
    And more.

Notice how the EKS cluster has to be created into a VPC.

Also, the worker nodes for your Kubernetes cluster should be deployed in the private subnets.

You can define those two constraints with:

main.tf

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "2.47.0"

  # truncated
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "12.2.0"

  cluster_name    = "${local.cluster_name}"
  cluster_version = "1.17"
  subnets         = module.vpc.private_subnets

  vpc_id = module.vpc.vpc_id

  # truncated
}

The last part of the Terraform file is the following:

main.tf

data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_id
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
  load_config_file       = false
  version                = "~> 1.11"
}

The code is necessary to:

    Set up the right permissions to connect to the cluster.
    Poll the cluster to make sure it's ready.

And that's all!
Eksctl vs Terraform — pros and cons

You can already tell the main differences between eksctl and Terraform:

    Both create an EKS cluster.
    Both export a valid kubeconfig file.
    The configuration for eksctl is more concise.
    Terraform is more granular. You have to craft every single resource carefully.

So which one should you use?

For small experiments, you should consider eksctl.

With a short command you can quickly create a cluster.

For production infrastructure where you want to configure every single detail of your cluster, you should consider using Terraform.

But there's another readon why you should pick Terraform, and that's incremental updates.

Let's imagine that you want to add a second pool of server to your cluster.

Perhaps you want to add GPU nodes to your cluster so that you can train your machine learning models.

You can amend the file as follows:

main.tf

# truncated

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "12.2.0"

  cluster_name    = "${local.cluster_name}"
  cluster_version = "1.17"
  subnets         = module.vpc.private_subnets

  vpc_id = module.vpc.vpc_id

  node_groups = {
    first = {
      desired_capacity = 1
      max_capacity     = 10
      min_capacity     = 1

      instance_type = "m5.large"
    }
    gpu = {
      desired_capacity = 1
      max_capacity     = 10
      min_capacity     = 1

      instance_type = "p3.2xlarge"
    }
  }

  write_kubeconfig   = true
  config_output_path = "./"
}

    You can find the amended code in this GitHub repository.

You can dry run the changes with:

bash

terraform plan
[output truncated]
Plan: 2 to add, 0 to change, 0 to destroy.

Once you're ready, you can apply the changes with:

bash

terraform apply
[output truncated]
Apply complete! Resources: 2 added, 0 changed, 0 destroyed.

You can verify that the cluster now has two nodes (one for each pool) with:

bash

KUBECONFIG=./kubeconfig_my-cluster kubectl get nodes --all-namespaces
NAME                                          STATUS   VERSION
ip-172-16-1-111.ap-south-1.compute.internal   Ready    v1.17.11-eks-cfd
ip-172-16-3-44.ap-south-1.compute.internal    Ready    v1.17.11-eks-cfd

You've configured and updated the cluster, but still, you haven't deployed any application.

Let's create a simple deployment.
Testing the cluster by deploying a simple Hello World app

You can create a Deployment with the following YAML definition:

deployment.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello-kubernetes
spec:
  selector:
    matchLabels:
      name: hello-kubernetes
  template:
    metadata:
      labels:
        name: hello-kubernetes
    spec:
      containers:
        - name: app
          image: paulbouwer/hello-kubernetes:1.8
          ports:
            - containerPort: 8080

Please notice that you can find all the Kubernetes resources in the GitHub repository.

You can submit the definition to the cluster with:

bash

kubectl apply -f deployment.yaml

To see if your application runs correctly, you can connect to it with kubectl port-forward.

First, retrieve the name of the Pod:

bash

kubectl get pods
NAME                                READY   STATUS    RESTARTS
hello-kubernetes-78f676b77c-wfjdz   1/1     Running   0

You can connect to the Pod with:

bash

kubectl port-forward <hello-kubernetes-wfjdz> 8080:8080

The command:

    Connects to the Pod with name hello-kubernetes-wfjdz.
    Forwards all the traffic from port 8080 on the Pod to port 8080 on your computer.

If you visit http://localhost:8080 on your computer, you should be greeted by the application.

Great!

Exposing the application with kubectl port-forward is an excellent way to test the app quickly, but it isn't a long term solution.

If you wish to route live traffic to the Pod, you should have a more permanent solution.

In Kubernetes, you can use a Service of type: LoadBalancer to expose your Pods.

You can use the following code:

service-loadbalancer.yaml

apiVersion: v1
kind: Service
metadata:
  name: hello-kubernetes
spec:
  type: LoadBalancer
  ports:
    - port: 80
      targetPort: 8080
  selector:
    name: hello-kubernetes

You can submit the YAML file with:

bash

kubectl apply -f service-loadbalancer.yaml

As soon you submit the command, AWS provisions a Classic Load Balancer and connects it to your Pod.

It might take a while for the load balancer to be provisioned.

Eventually, you should be able to describe the Service and retrieve the load balancer's endpoint.

bash

kubectl describe service hello-kubernetes
Name:                     hello-kubernetes
Namespace:                default
Labels:                   <none>
Annotations:              Selector: name=app
Type:                     LoadBalancer
IP:                       10.100.183.219
LoadBalancer Ingress:     a9d048.ap-south-1.elb.amazonaws.com
Port:                     <unset>  80/TCP
TargetPort:               3000/TCP
NodePort:                 <unset>  30066/TCP
Endpoints:                172.16.3.61:3000
Session Affinity:         None
External Traffic Policy:  Cluster

If you visit that URL in your browser, you should see the app live.

Excellent!

There's only an issue, though.

The load balancer that you created earlier serves one service at the time.

Also, it has no option to provide intelligent routing based on paths.

So if you have multiple services that need to be exposed, you will need to create the same amount of load balancers.

Imagine having ten applications that have to be exposed.

If you use a Service to type: LoadBalancer for each of them, you might end up with ten Classic Load Balancers.

That wouldn't be a problem if those load balancers weren't so expensive.

How can you get around this issue?

In Kubernetes, there's another resource that is designed to solve that problem: the Ingress.

The Ingress has two parts:

    The first is the Ingress manifest which is the same as Deployment or Service in Kubernetes. This is defined by the kind part in the YAML manifest.
    The second part is the Ingress controller. This is the actual part that controls the load balancers, so they know how to serve the requests and forward the data to the Pods.

In other words, the Ingress controller acts as a reverse proxy that routes the traffic to your Pods.
The Ingress in Kubernetes

The Ingress routes the traffic based on paths, domains, headers, etc., which consolidates multiple endpoints in a single resource that runs inside Kubernetes.

With this, you can serve multiple services at the same time from one exposed load balancer.

There're several Ingress controllers that you can use:

    Nginx Ingress
    Ambassador
    Traefik
    And more.

In this part you will use the ALB Ingress Controller — an Ingress controller that integrates nicely with the Application Load Balancer.
Routing traffic into the cluster with the ALB Ingress Controller

The ALB Ingress Controller is a Pod that helps you control the Application Load Balancer from Kubernetes.

Instead of setting up Listeners, TargetGroups or Listener Rules from the ALB, you can install the ALB Ingress controller that acts as a translator between Kubernetes and the actual ALB.

In other words, when you create an Ingress manifest in Kubernetes, the controller converts the request into something that the ALB understands (Listeners, TargetGroups, etc.)

Let's have a look at an example.

ingress.yaml

apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: hello-kubernetes
spec:
  rules:
    - http:
        paths:
          - path: /
            backend:
              serviceName: hello-kubernetes
              servicePort: 80

The following Kubernetes Ingress manifest routes all the traffic from path / to the Pods targeted by the hello-kubernetes Service.

As soon as you submit the resource to the cluster with kubectl apply -f ingress.yaml, the ALB Ingress controller is notified of the new resource.

And it creates:

    A TargetGroup for each Kubernetes Service.
    A Listener Rule for the / path in the ingress resource. This ensures traffic to a specific path is routed to the correct Kubernetes Service.

The ALB Ingress controller is convenient since you can control your infrastructure uniquely from Kubernetes — there's no need to fiddle with AWS anymore.

    Let's consider the following EKS cluster with three nodes, a Deployment with 2 Pods and a Service.
    1/12

    Let's consider the following EKS cluster with three nodes, a Deployment with 2 Pods and a Service.
    Next 

Now that you know the theory, it's time to put into practice.

First, you should install the ALB Ingress controller.

There're two crucial steps that you need to complete to install the controller:

    Grant the relevant permissions to your worker nodes.
    Install the Kubernetes resources (such as Deployment, Service, ConfigMap, etc.) necessary to install the controller.

Let's tackle the permissions first.

Since the Ingress controller runs as Pod in one of your Nodes, all the Nodes should have permissions to describe, modify, etc. the Application Load Balancer.

The following file contains the AIM Policy for your workers nodes.

Download the policy and save it in the same folder as your Terraform file main.tf.

    You can always refer to the full code in the GitHub repository.

Edit your main.tf code and append the following line in your module module.eks:

main.tf

module "eks" {
  # truncated

  write_kubeconfig   = true
  config_output_path = "./"

  workers_additional_policies = [aws_iam_policy.worker_policy.arn]
}

resource "aws_iam_policy" "worker_policy" {
  name        = "worker-policy"
  description = "Worker policy for the ALB Ingress"

  policy = file("iam-policy.json")
}

Before applying the change to the infrastructure, let's do a dry-run with:

bash

terraform plan
[output truncated]
Plan: 1 to add, 1 to change, 0 to destroy.

If you're confident that the change is correct, you can apply with:

bash

terraform apply
[output truncated]
Apply complete! Resources: 1 added, 1 changed, 0 destroyed.

Great, the first step is completed.

The actual ALB Ingress Controller (the Kubernetes resources such as Pod, ConfigMaps, etc.) can be installed with Helm — the Kubernetes package manager.

You should download and install the Helm binary.

You can find the instructions on the official website.

You can verify that Helm was installed correctly with:

bash

helm version

The output should contain the version number.

Helm is a tool that templates and deploys YAML in your cluster.

You can write the YAML yourself, or you can download a package written by someone else.

In this case, you want to install the collection of YAML files necessary to run the ALB Ingress Controller.

First, add the following repository to Helm:

bash

helm repo add incubator http://storage.googleapis.com/kubernetes-charts-incubator

Now you can download and install the ALB Ingress Controller in your cluster with:

bash

helm install ingress incubator/aws-alb-ingress-controller \
  --set autoDiscoverAwsRegion=true \
  --set autoDiscoverAwsVpcID=true \
  --set clusterName=my-cluster

Verify that the Ingress controller is running with:

bash

kubectl get pods -l "app.kubernetes.io/instance=ingress"

Excellent, you completed step 2 of the installation.

Now you're ready to use the Ingress manifest to route traffic to your app.

You can use the following Ingress manifest definition:

ingress.yaml

apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: hello-kubernetes
  annotations:
    alb.ingress.kubernetes.io/scheme: internet-facing
    kubernetes.io/ingress.class: alb
spec:
  rules:
    - http:
        paths:
          - path: /
            backend:
              serviceName: hello-kubernetes
              servicePort: 80

Pay attention to the following fields:

    metadata.annotations.kubernetes.io/ingress.class is used to select the right Ingress controller in the cluster.
    metadata.annotations.kubernetes.io/alb.ingress.kubernetes.io/scheme can be configured to use internal or public-facing load balancers.

    You can explore the full list of annotations here.

You can submit the Ingress manifest to your cluster with:

bash

kubectl apply -f ingress.yaml

It may take a few minutes (the first time) for the ALB to be created, but eventually, you will see the following output from kubectl describe ingress:

bash

kubectl describe ingress hello-kubernetes
Name:             hello-kubernetes
Namespace:        default
Address:          81495355-default-hellokube-e642.ap-south-1.elb.amazonaws.com
Default backend:  default-http-backend:80
Rules:
  Host        Path  Backends
  ----        ----  --------
  *
              /   hello-kubernetes:80 (172.16.3.61:8080)

Excellent, you can use the "Address" to visit your application in the browser.

Congratulations!

You've managed to deploy a fully working cluster that can route live traffic!

Are you done now?

In the spirit of automating all aspects of creating a cluster, is there a way to start the full cluster with a single command?

At the moment, you have to:

    Provision the cluster with Terraform.
    Install the ALB Ingress Controller with Helm.

Can you combine those steps?
Provisioning a full cluster with Ingress with the Helm provider

You can extend Terraform with plugins called providers.

So far you've utilised two providers:

    The AWS provider, to create, modify and delete AWS resources.
    The Kubernetes provider, as a dependency of the EKS Terraform module.

Terraform has several plugins and one of those is the Helm provider.

What if you could execute Helm from Terraform?

You could create the entire cluster with a single command!

Before you use Helm with Terraform, let's delete the existing Ingress controller with:

bash

helm delete ingress

Let's include Helm in your main.tf like this:

main.tf

# at the bottom of main.tf append:

provider "helm" {
  version = "1.3.1"
  kubernetes {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
    token                  = data.aws_eks_cluster_auth.cluster.token
    load_config_file       = false
  }
}

resource "helm_release" "ingress" {
  name       = "ingress"
  chart      = "aws-alb-ingress-controller"
  repository = "http://storage.googleapis.com/kubernetes-charts-incubator"
  version    = "1.0.2"

  set {
    name  = "autoDiscoverAwsRegion"
    value = "true"
  }
  set {
    name  = "autoDiscoverAwsVpcID"
    value = "true"
  }
  set {
    name  = "clusterName"
    value = local.cluster_name
  }
}

    You can find the full code on GitHub.

Terraform has to download and initialise the Helm provider before you can do a dry-run:

bash

terraform init
terraform plan
[output truncated]
Plan: 1 to add, 0 to change, 0 to destroy.

You can finally amend your cluster and install the ALB Ingress Controller with a single command:

bash

terraform apply
[output truncated]
Apply complete! Resources: 1 added, 0 changed, 0 destroyed.

Excellent, you should verify that the application still works as expected by visiting your app.

If you forgot what the URL was, you could retrieve it with:

bash

kubectl describe ingress hello-kubernetes
Name:             hello-kubernetes
Namespace:        default
Address:          81495355-default-hellokube-e642.ap-south-1.elb.amazonaws.com
Default backend:  default-http-backend:80
Rules:
  Host        Path  Backends
  ----        ----  --------
  *
              /   hello-kubernetes:80 (172.16.3.61:8080)

Success!

If you now destroy your cluster, you can recreate with a single command: terraform apply.

There's no need to install and run Helm anymore.

And there's another benefit in having the cluster defined with code and created with a single command.

You can template the Terraform code and create copies of your cluster.

In the next part, you will create three identical environments: dev, staging and production.
Fully automated Dev, Staging, Production environments with Terraform modules

One of the most common tasks when provisioning infrastructure is to create separate environments.

It's a popular practice to provision three environments:

    A development environment where you can test your changes and integrate them with other colleagues.
    A staging environment used to sign-off requirements.
    A production environment.

Since you want your apps to progress through the environments, you might want to provision not one, but three clusters, once for each environment.

When you don't have infrastructure is code, you are forced to click on the user interface and repeat the same choice.

But since now you've master Terraform you can refactor your code and create three (or more) environments with a single command!

The beauty of Terraform is that you can use the same code to generate several clusters with different names.

You can parametrise the name of your resources and create clusters that are exact copies.

You can reuse the existing Terraform code and provision three clusters simultaneously using Terraform modules and expressions.

    Before you execute the script, it's a good idea to destroy any cluster that you created previously with terraform destroy.

The expression syntax is straightforward.

You define a variable like this:

example_var.tf

variable "cluster_name" {
  default = "my-cluster"
}

You can append the definition at the top of your main.tf.

Later, you can reference the variable in the VPC and EKS modules like this:

main.tf

module "vpc" {
  # truncated
  name            = "k8s-${var.cluster_name}-vpc"
}

module "eks" {
  # truncated
  cluster_name    = "eks-${var.cluster_name}"
}

When you execute the usual terraform apply command, you can override the variable with a different name.

For example:

bash

terraform apply -var="cluster_name=dev"

The command will provision a new cluster with the name "dev".

In isolation, expressions are not particularly useful.

Let's have a look at an example.

If you execute the following commands, what do you expect?

Is Terraform creating two clusters or update the dev cluster to a staging cluster?

bash

terraform apply -var="cluster_name=dev"
# and later
terraform apply -var="cluster_name=staging"

The code updates the dev cluster to a staging cluster.

It's overwriting the same cluster!

But what if you wish to create a copy?

You can use the Terraform modules to your advantage.

Terraform modules use variables and expressions to encapsulate resources.

Move your main.tf in a subfolder called cluster and create an empty main.tf.

bash

mkdir -p cluster
mv main.tf iam-policy.json cluster
.
├── cluster
│   ├── iam-policy.json
│   └── main.tf
└── main.tf

From now on you can use the code that you've created as a reusable module.

In the root main.tf you can reference to that module with:

main.tf

module "dev_cluster" {
  source        = "./cluster"
  cluster_name  = "dev"
}

And since the module is reusable, you can create more than a single cluster:

main.tf

module "dev_cluster" {
  source        = "./cluster"
  cluster_name  = "dev"
}

module "staging_cluster" {
  source        = "./cluster"
  cluster_name  = "staging"
}

module "production_cluster" {
  source        = "./cluster"
  cluster_name  = "production"
}

You can find the full code changes in the GitHub repository.

You can preview the changes with:

bash

terraform plan
[output truncated]
Plan: 141 to add, 0 to change, 0 to destroy.

You can apply the changes and create three clusters that are exact copies with:

bash

terraform apply

All three cluster have the ALB Ingress Controller installed, so they are ready to handle production traffic.

What happens when you update the cluster module?

When you modify a property, all clusters will be updated with the same property.

If you wish to customise the properties on a per environment basis, you should extract the parameters in variables and change them from root main.tf.

Let's have a look at an example.

You might want to run smaller instances such as t2.micro in dev and staging and leave the m5.large instance type for production.

You an refactor the code and extract the instance type as a variable:

main.tf

module "eks" {
  # truncated

  node_groups = {
    first = {
      desired_capacity = 1
      max_capacity     = 10
      min_capacity     = 1

      instance_type = var.instance_type
    }
  }
}

variable "instance_type" {
  default = "m5.large"
}

Later, you can modify the root main.tf file with the instance type:

main.tf

module "dev_cluster" {
  source        = "./cluster"
  cluster_name  = "dev"
  instance_type = "t2.micro"
}

module "staging_cluster" {
  source        = "./cluster"
  cluster_name  = "staging"
  instance_type = "t2.micro"
}

module "production_cluster" {
  source        = "./cluster"
  cluster_name  = "production"
  instance_type = "m5.large"
}

Excellent!

As you can imagine, you can add more variables in your module and create environments with different configurations.

This marks the end of your journey!

A recap on what you've built so far:

    So you've created an EKS cluster with Terraform.
    You integrated the ALB Ingress controller as part of the cluster creation.
    You parametrised the cluster and created a reusable module.
    You used the module to provision copies of your cluster (one for each environment: dev, staging and production).
    You made the module more flexible by allowing small customisations such as changing the instance type.

Well done!
Summary and next steps

Having the infrastructure defined as code makes your job easier.

If you wish to change the version of the cluster, you can do it in a centralised manner and have it applied to all clusters.

The setup described above is only the beginning, if you're provisioning production-grade infrastructure you should look into:

    How to structure your Terraform in global and environment-specific layers.
    Managing Terraform state and how to work with the rest of your team.
    How to use External DNS to link your Route53 to your ALB Ingress controller.
    How to set up TLS with cert-manager.
    How to set up a private Elastic Container Registry (ECR).

And the beauty is that External DNS and Cert Manager are available as charts, so you could integrate them with your Helm provider and have all the cluster updated at the same time.

##########################
##
##


