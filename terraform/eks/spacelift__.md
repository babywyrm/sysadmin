##
#
https://spacelift.io/blog/bootstrap-complete-amazon-eks-clusters-with-eks-blueprints-for-terraform
#
##


Bootstrap Complete Amazon EKS Clusters with EKS Blueprints for Terraform
Ioannis Moustakis
20 Oct 2023
·
14 min read
Reviewed by: 
Flavius Dinu
eks blueprints terraform
In this blog post, we will explore Amazon EKS Blueprints for Terraform, a set of patterns that make it easier and quicker for users to provision complete Amazon Elastic Kubernetes Service(EKS) clusters. 

If you are new to Terraform or interested in other Terraform concepts, these Terraform tutorials on Spacelift’s blog might be handy. Similarly, check these Kubernetes blog posts if you are learning about Kubernetes.

We will cover:

What is Amazon EKS Blueprints for Terraform
Core concepts and architecture
Getting started with EKS Blueprints for Terraform
What is Amazon EKS Blueprints for Terraform
Adopting Kubernetes as your container orchestration platform is a challenging task. Before considering application deployments, you must design a robust Kubernetes setup, install operational tooling, and build a platform on top of which we will host workloads.

Kubernetes offers a vibrant ecosystem of popular open-source tools that we can leverage to build our production-grade clusters, commonly called addons. Selecting and implementing the appropriate tooling for your needs and integrating, and in the case of EKS, integrating the cluster to the rest of your AWS setup is a time-consuming and operationally heavy task.

We will look at the EKS Blueprints for Terraform framework to facilitate and fast-track this process. By leveraging EKS Blueprints, we can provision purpose-built, “batteries-included,” and Well-Architected EKS clusters that contain any necessary operational tooling and AWS integrations out-of-the-box, allowing us to start onboarding applications as fast as possible.

The EKS Blueprints are hosted on GitHub, open-source, well-documented, and easy to start. The blueprints can be used to create EKS clusters across accounts and regions, manage cluster configuration and operational software with Infrastructure as Code (IaC) and GitOps principles, and manage team permissions. This framework consolidates tools and best practices for securing, scaling, and operating a central container orchestration platform. EKS blueprints are also available for CDK, but this blog post will focus on the Terraform version.

Amazon EKS Blueprints for Terraform - core concepts and architecture
This part discusses the main parts of Amazon EKS Blueprints for Terraform, its principle components, and how they fit together.

EKS Blueprints Patterns
Amazon EKS Blueprints for Terraform is basically a collection of patterns and snippets designed to provide a reference based on standard operational tooling and cluster configuration scenarios. Look at the official documentation for a detailed list of supported patterns. If you think a pattern is missing, feel free to open an issue on the GitHub repository.

Cluster
When discussing a cluster in this scope, we refer to an Amazon EKS cluster. The framework currently supports AWS Fargate, managed, and self-managed node groups. To configure new clusters, the framework leverages the terraform-aws-modules/eks/aws module.

Add-on
Addons are tools that extend the functionality of Kubernetes. They allow you to configure the operational software for deploying robust and Well-Architected EKS clusters. Some add-ons are supported directly via EKS, and some others are provisioned at deployment time by leveraging the Terraform Helm provider.

Add-ons can deploy both Kubernetes-specific resources and AWS resources needed to support addon functionality. EKS Blueprints allows you to manage your addons directly via Terraform (by leveraging the Terraform Helm provider) or via GitOps with ArgoCD.

Teams
EKS Blueprints supports team management and easily configuring cluster access. It currently supports two teams, `application` and `platform` teams. The platform teams are the users responsible for managing, deploying, and administering the EKS cluster, whereas the application teams consume cluster resources to run their applications.

Pipelines
As a best practice, we should build CI/CD pipelines for provisioning EKS clusters, tooling, and add-ons. Every configuration change should undergo a code review process and deployed into the target environments via Continuous Integration and Continuous Delivery methods.

Application/Workload
An application or a workload is a set of software components that were developed by the applications teams and need to run in the EKS clusters. Each application has its own characteristics and needs, and the platform team needs to ensure the correct isolation and security mechanisms to avoid interference between different workloads. The framework leverages a GitOps approach for deploying applications onto clusters.

GitOps
GitOps is a framework and a set of best practices designed to help teams automate and streamline version control and software deployment. It is based on the concept of having the desired state of our infrastructure and application deployment configuration stored in Git repositories as our source of truth.

Getting started with EKS Blueprints for Terraform
In this section, we will go through a guide to get started with EKS Blueprints for Terraform and start building your “batteries-included” clusters as soon as possible with minimal hustle. 

To follow along, you will need these tools:

aws cli
kubectl 
Terraform
After you have installed the necessary tooling, make sure to configure the AWS CLI to interact with AWS.

1. Provision an EKS cluster
Let’s go ahead and deploy the Terraform manifests to provision the VPC and associated networking resources, the EKS cluster, and EKS Blueprints Addons. You can find the code in this repository if you wish to follow along.

For the needs of this demo, we will use the terraform-aws-modules/vpc/aws and terraform-aws-modules/eks/aws modules to provision the basis of our networking infrastructure and an EKS cluster.

You can find the initial skeleton of our setup on this directory of the code repository. There we define the necessary versions, variables for the providers and create a VPC and an EKS cluster as a basis.

In typical Terraform fashion, we run terraform init and terraform apply.

It may take up to ~15 minutes to create the EKS cluster. 

To connect to our newly created cluster, you can use this command from the command line:

aws eks --region us-east-1 update-kubeconfig --name eks_blueprints
You should be able to see the two nodes that we configured by running:

kubectl get nodes

NAME                          STATUS   ROLES    AGE   VERSION
ip-10-0-40-189.ec2.internal   Ready    <none>   18h   v1.27.3-eks-a5565ad
ip-10-0-49-117.ec2.internal   Ready    <none>   18h   v1.27.3-eks-a5565ad
As you might have noticed, we have also configured a few EKS-based addons with the eks module, such as: coredns, kube-proxy, vpc-cni, and aws-ebs-csi-driver. 

Let’s check what has been deployed by running kubectl get pods -n kube-system. Notice (among others) some pods related to these addons. 
```
aws-node-2mtq7                                        1/1     Running   0          83m
aws-node-cbq94                                        1/1     Running   0          83m
coredns-7f6585bf44-jtr4p                           1/1     Running   0          83m
coredns-7f6585bf44-vgbjm                        1/1     Running   0          83m
ebs-csi-controller-67c46c99b8-wdfw5        6/6     Running   0          83m
ebs-csi-controller-67c46c99b8-xqbgd        6/6     Running   0          83m
ebs-csi-node-6dznw                                   3/3     Running   0          83m
ebs-csi-node-7t487                                    3/3     Running   0          83m
kube-proxy-7srfd                                        1/1     Running   0          83m
kube-proxy-cpmqn                                     1/1     Running   0          83m
```

To validate that we can successfully use an EBS volume, let’s deploy a demo StatefulSet:

ebs_statefulset_example.yaml
```
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: test-ebs
  namespace: default
spec:
  selector:
    matchLabels:
      app: nginx
  serviceName: nginx
  replicas: 1
  minReadySeconds: 10
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
        - name: nginx
          image: registry.k8s.io/nginx-slim:0.8
          ports:
            - containerPort: 80
              name: test-ebs
          volumeMounts:
            - name: example-mount
              mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
    - metadata:
        name: example-mount
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: "gp2"
        resources:
          requests:
            storage: 12Gi
```

Let’s deploy it by executing

kubectl apply -f kubernetes_manifests/ebs_statefulset_example.yaml
Then, let’s validate that the persistent volume claim is in Bound state and the pod has started successfully.

kubectl get pvc
NAME  STATUS   VOLUME   CAPACITY   ACCESS MODES   STORAGECLASS   AGE
 ebs-xx   Bound    pvc-XXXX    12Gi             RWO                           gp2                        6s

kubectl get pods
NAME         READY   STATUS    RESTARTS   AGE
test-ebs-0   1/1            Running           0             10s
To clean up, execute:

kubectl delete -f kubernetes_manifests/ebs_statefulset_example.yaml
kubectl delete pvc  ebs-xx
2. Configure different Teams as Admins and Tenants
Next, we would like to use EKS blueprints to configure different access levels for different teams and use cases. We can achieve that using the terraform-aws-eks-blueprints-teams module. First, let’s create the platform team definition by adding this code to a teams.tf file:

platform_team.tf

module "eks_blueprints_platform_team" {
  source = "aws-ia/eks-blueprints-teams/aws"
  version = "~> 1.0"

  name = "platform-team"

  # Enables elevated, admin privileges for this team
  enable_admin = true

  # Define who can impersonate the team-platform Role
  users = [
    data.aws_caller_identity.current.arn,
    try(data.aws_iam_role.eks_admin_role_name[0].arn,  data.aws_caller_identity.current.arn),
  ]
  cluster_arn = module.eks.cluster_arn
  oidc_provider_arn = module.eks.oidc_provider_arn

  labels = {
    "elbv2.k8s.aws/pod-readiness-gate-inject" = "enabled",
    "appName" = "platform-team-app",
    "projectName" = "project-platform",
  }

  annotations = {
    team = "platform"
  }

  namespaces = {
    "team-platform" = {

      resource_quota = {
        hard = {
          "requests.cpu" = "10000m",
          "requests.memory" = "20Gi",
          "limits.cpu" = "20000m",
          "limits.memory" = "50Gi",
          "pods" = "20",
          "secrets" = "20",
          "services" = "20"
        }
      }

      limit_range = {
        limit = [
          {
            type = "Pod"
            max = {
              cpu = "1000m"
              memory = "1Gi"
            },
        
            min = {
              cpu = "10m"
              memory = "4Mi"
            }
          },
          {
            type = "PersistentVolumeClaim"
            min = {
              storage = "24M"
            }
          }
        ]
      }
    }
  }
}
Here, we set this team with admin privileges, create a role that the team members can impersonate, create a dedicated namespace for the team’s needs, and, since this is a shared cluster, set up resource quotas and limitations for the namespace.

We must run terraform init again since we are adding new modules. Go ahead and execute terraform apply again.

After successfully deploying the platform team changes, we can validate that a new namespace team-platform exists:

kubectl get namespace

NAME              STATUS   AGE
default           Active   19h
kube-node-lease   Active   19h
kube-public       Active   19h
kube-system       Active   19h
team-platform     Active   22s
We can also inspect the resource quotas we configured above:

kubectl describe resourcequotas -n team-platform

Name:            team-platform
Namespace:       team-platform
Resource         Used  Hard
--------         ----  ----
limits.cpu       0     20
limits.memory    0     50Gi
pods             0     20
requests.cpu     0     10
requests.memory  0     20Gi
secrets          0     20
services         0     20
Similarly, let’s define two development teams as tenants of our platform; team-a and team-b. For this, we will use the same module one more time with multiple teams’ definitions using the for_each functionality.

dev_teams.tf

###############################################################################
#Dev Teams
###############################################################################


module "eks_blueprints_dev_teams" {
  source = "aws-ia/eks-blueprints-teams/aws"
  version = "~> 1.0"

  for_each = {
    a = {
      labels = {
        "elbv2.k8s.aws/pod-readiness-gate-inject" = "enabled",
        "appName" = "team-a-app",
        "projectName" = "project-a",
      }
    }
    b = {
      labels = {
        "elbv2.k8s.aws/pod-readiness-gate-inject" = "enabled",
        "appName" = "team-b-app",
        "projectName" = "project-b",
      }
    }
  }
  name = "team-${each.key}"

  users = [data.aws_caller_identity.current.arn]
  cluster_arn = module.eks.cluster_arn
  oidc_provider_arn = module.eks.oidc_provider_arn

  labels = merge(
    {
      team = each.key
    },
    try(each.value.labels, {})
  )

  annotations = {
    team = each.key
  }

  namespaces = {
    "team-${each.key}" = {
      labels = merge(
        {
          team = each.key
        },
        try(each.value.labels, {})
      )

      resource_quota = {
        hard = {
          "requests.cpu" = "100",
          "requests.memory" = "20Gi",
          "limits.cpu" = "200",
          "limits.memory" = "50Gi",
          "pods" = "15",
          "secrets" = "10",
          "services" = "20"
        }
      }

      limit_range = {
        limit = [
          {
            type = "Pod"
            max = {
              cpu = "2"
              memory = "1Gi"
            }
            min = {
              cpu = "10m"
              memory = "4Mi"
            }
          },
          {
            type = "PersistentVolumeClaim"
            min = {
              storage = "24M"
            }
          },
          {
            type = "Container"
            default = {
              cpu = "50m"
              memory = "24Mi"
            }
          }
        ]
      }
    }
  }

  tags = local.tags

}
Using the code above, we configure each team’s specific namespace, quotas, and IAM role. To showcase this example, we will pass the current user as a member of these teams using the data.aws_caller_identity.current.arn argument.

To provide the newly created development teams access to the cluster, we must edit the aws_auth_roles section of the eks module in the main.tf file. Go ahead and edit accordingly:

aws_auth_roles = flatten([
  {
    # The ARN of the IAM role
    rolearn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.eks_admin_role_name}"
    # The user name within Kubernetes to map to the IAM role
    username = "ops-role"
    # A list of groups within Kubernetes to which the role is mapped; Checkout K8s Role and Rolebindings
    groups = ["system:masters"]
  },
  module.eks_blueprints_platform_team.aws_auth_configmap_role,
  [for team in module.eks_blueprints_dev_teams : team.aws_auth_configmap_role]
])
Lastly, let’s create an outputs.tf file with the different IAM roles per team to try them out. 

outputs.tf

output "eks_blueprints_platform_teams_configure_kubectl" {
  description = "Configure kubectl for Platform Team: make sure you're logged in with the correct AWS profile and run the following command to update your kubeconfig"
  value = "aws eks --region ${var.aws_region} update-kubeconfig --name ${module.eks.cluster_name} --role-arn ${module.eks_blueprints_platform_team.iam_role_arn}"
}

output "eks_blueprints_dev_teams_configure_kubectl" {
  description = "Configure kubectl for each Dev Application Teams: make sure you're logged in with the correct AWS profile and run the following command to update your kubeconfig"
  value = [for team in module.eks_blueprints_dev_teams : "aws eks --region ${var.aws_region} update-kubeconfig --name ${module.eks.cluster_name} --role-arn ${team.iam_role_arn}"]
}
We must run terraform init again since we are adding new modules. Go ahead and execute terraform apply again.

After applying the changes, we see the newly created IAM roles as outputs:

Outputs:

eks_blueprints_dev_teams_configure_kubectl = [
  "aws eks --region us-east-1 update-kubeconfig --name eks_blueprints  --role-arn arn:aws:iam::XXXXXXXXXX:role/team-team-a-YYYYYYYYYYYYY",
  "aws eks --region us-east-1 update-kubeconfig --name eks_blueprints  --role-arn arn:aws:iam::XXXXXXXXXX:role/team-team-b-ZZZZZZZZZZZZZZ",
]
We also see that our new namespaces have been created successfully.

kubectl get ns
NAME              STATUS   AGE
default           Active   73m
kube-node-lease   Active   73m
kube-public       Active   73m
kube-system       Active   73m
team-platform     Active   69m
team-a       Active   31m
team-b       Active   31m
Let’s use the first command we got as output to authenticate to the cluster as team-a member. 

aws eks --region us-east-1 update-kubeconfig --name eks_blueprints  --role-arn arn:aws:iam::XXXXXXXXXX:role/team-team-a-YYYYYYYYYYYYY
Now that we are impersonating team-a, let’s try to list the pods in namespace team-a and namespace team-b:

kubectl get pods -n team-a
No resources found in team-a namespace.

kubectl get pods -n team-b
Error from server (Forbidden): pods is forbidden: User "team-a" cannot list resource "pods" in API group "" in the namespace "team-b"
We validated that we only have read access on the dedicated team-a namespace.

Configure kubectl back to the creator of the cluster with the initial command we used to connect:

aws eks --region us-east-1 update-kubeconfig --name eks_blueprints
💡 You might also like:

SaaS not an option? Install Spacelift Self-Hosted on AWS
How to Automate Terraform Deployments
Why DevOps Engineers Recommend Spacelift
3. Add operational addons with EKS Blueprints
Now that we have our cluster up and running and set up the appropriate permissions to host different teams as tenants let’s add some key EKS add-ons to prepare our cluster for running workloads.

For the needs of this demo, we will install the AWS Load Balancer Controller to expose applications with load balancers and ingresses, Metrics Server to fetch CPU and memory metrics for our pods, and Karpenter for autoscaling cluster nodes.

To achieve this, we will configure the github.com/aws-ia/terraform-aws-eks-blueprints/modules/kubernetes-addons module. We also need a helm provider to configure some of these add-ons via helm. 

eks_blueprints_addons.tf

provider "helm" {
  kubernetes {
    host = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command = "aws"
      # This requires the awscli to be installed locally where Terraform is executed
      args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

module "eks_blueprints_addons" {
  source = "aws-ia/eks-blueprints-addons/aws"
  version = "~> 1.0"

  cluster_name = module.eks.cluster_name
  cluster_endpoint = module.eks.cluster_endpoint
  cluster_version = module.eks.cluster_version
  oidc_provider_arn = module.eks.oidc_provider_arn

  tags = local.tags
}
We must run terraform init again since we are adding a new module. Go ahead and execute terraform apply again.

AWS Load Balancer Controller addon
Alright, now that we configured the new module, let’s go ahead and enable some add-ons. Next, we will deploy the AWS Load Balancer Controller addon to allow EKS to provision application and network load balancers and create ingresses to expose our apps to the outside world.

In the same module we configured previously for the EBS CSI Driver, add this line enable_aws_load_balancer_controller = true towards the end. 

After running terraform applyonce more, we can check the applied components by checking for pods in the kube-system namespace and validate that an ingressclass has been created:

kubectl get ingressclass
NAME   CONTROLLER            PARAMETERS   AGE
alb        ingress.k8s.aws/alb       <none>              2m43s
To test the new controller, we will deploy a sample application with an Ingress component.

ingress_example.yaml

---
apiVersion: v1
kind: Namespace
metadata:
  name: game-2048
---
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: game-2048
  name: deployment-2048
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: app-2048
  replicas: 5
  template:
    metadata:
      labels:
        app.kubernetes.io/name: app-2048
    spec:
      containers:
      - image: public.ecr.aws/l6m2t8p7/docker-2048:latest
        imagePullPolicy: Always
        name: app-2048
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  namespace: game-2048
  name: service-2048
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
  type: NodePort
  selector:
    app.kubernetes.io/name: app-2048
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  namespace: game-2048
  name: ingress-2048
  annotations:
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
spec:
  ingressClassName: alb
  rules:
    - http:
        paths:
        - path: /
          pathType: Prefix
          backend:
            service:
              name: service-2048
              port:
                number: 80
kubectl apply -f kubernetes_manifests/ingress_example.yaml

kubectl get ingress -n game-2048
NAME           CLASS   HOSTS   ADDRESS                                          PORTS   AGE
ingress-2048  alb            *       2048-ingressXXX.elb.amazonaws.com   80          4s
We notice that an Application Load Balancer has been provisioned to expose our app. You can also go ahead in your AWS Console and check it out. 

To clean up, execute:

kubectl delete -f kubernetes_manifests/ingress_example.yaml
Metrics Server addon
Next, let’s also enable the Metrics Server addon, an efficient source of container resource metrics for Kubernetes built-in autoscaling pipelines.

In the same module configuration block, set enable_metrcis_server to true and re-apply. 

Validate that the pod is running on the kube-system namespace and execute:

kubectl top pods -n kube-system
To get CPU and Memory metrics for the running pods.

Karpenter addon
Next up, Karpenter is an open-source tool for autoscaling cluster nodes when pods can’t be scheduled. It assesses the collective resource needs of pending pods and selects the best instance type for them.

Furthermore, its consolidation feature proactively repositions pods, potentially replacing nodes with more cost-effective alternatives decreasing cluster expenses.

Let’s go ahead and prepare the Karpenter configuration. We add this line to our “eks_blueprints” module:

enable_karpenter = true
We must also authorize Karpenter nodes to connect to the EKS cluster by modifying the aws auth config.

Go to your EKS module configuration in main.tf and set your aws auth config like this:

manage_aws_auth_configmap = true
aws_auth_roles = flatten([
  {
    # The ARN of the IAM role
    rolearn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.eks_admin_role_name}"
    # The user name within Kubernetes to map to the IAM role
    username = "ops-role"
    # A list of groups within Kubernetes to which the role is mapped; Checkout K8s  Role and Rolebindings
    groups = ["system:masters"]
  },
  module.eks_blueprints_platform_team.aws_auth_configmap_role,
  [for team in module.eks_blueprints_dev_teams : team.aws_auth_configmap_role],
  {
    rolearn = module.eks_blueprints_addons.karpenter.node_iam_role_arn
    username = "system:node:{{EC2PrivateDNSName}}"
    groups = [
      "system:bootstrappers",
      "system:nodes",
    ]
  }
])
The last step, create a karpenter.tf file and add the below configuration to create an Instance Profile, a Provisioner, and a Node Template.

karpenter.tf

################################################################################
# Karpenter
################################################################################

resource "kubectl_manifest" "karpenter_provisioner" {
  yaml_body = <<-YAML
    apiVersion: karpenter.sh/v1alpha5
    kind: Provisioner
    metadata:
      name: default
    spec:
      requirements:
        - key: "karpenter.k8s.aws/instance-category"
          operator: In
          values: ["c", "m"]
        - key: "karpenter.k8s.aws/instance-cpu"
          operator: In
          values: ["8", "16", "32"]
        - key: "karpenter.k8s.aws/instance-hypervisor"
          operator: In
          values: ["nitro"]
        - key: "topology.kubernetes.io/zone"
          operator: In
          values: ${jsonencode(local.azs)}
        - key: "kubernetes.io/arch"
          operator: In
          values: ["arm64", "amd64"]
         - key: "karpenter.sh/capacity-type" # If not included, the webhook for the AWS cloud provider will default to on-demand
           operator: In
           values: ["spot", "on-demand"]
      kubeletConfiguration:
        containerRuntime: containerd
        maxPods: 110
      limits:
        resources:
          cpu: 1000
      consolidation:
        enabled: true
      providerRef:
        name: default
      ttlSecondsUntilExpired: 604800 # 7 Days = 7 * 24 * 60 * 60 Seconds
  YAML

  depends_on = [
    module.eks_blueprints_addons
  ]
}


resource "kubectl_manifest" "karpenter_node_template" {
  yaml_body = <<-YAML
    apiVersion: karpenter.k8s.aws/v1alpha1
    kind: AWSNodeTemplate
    metadata:
      name: default
    spec:
      subnetSelector:
        karpenter.sh/discovery: ${module.eks.cluster_name}
      securityGroupSelector:
        karpenter.sh/discovery: ${module.eks.cluster_name}
      instanceProfile:
${module.eks_blueprints_addons.karpenter.node_instance_profile_name}
      tags:
        karpenter.sh/discovery: ${module.eks.cluster_name}
  YAML
}
We will need to run terraform init and terraform apply again. 

Notice the Karpenter pods up and running:

get pods -n karpenter
NAME                        READY   STATUS    RESTARTS   AGE
karpenter-6fbf95b49-sl7hb   1/1     Running   0          19m
karpenter-6fbf95b49-xd96x   1/1     Running   0          19m
Let’s create a dummy deployment to test if Karpenter works as expected and can provision new nodes:

kubectl apply -f kubernetes_manifests/autoscale_karpenter_example.yaml
After that, let’s check Karpenter logs to see what’s happening:

kubectl logs -l app.kubernetes.io/instance=karpenter -n karpenter -f

2023-09-18T17:47:39.057Z	INFO	controller.provisioner.cloudprovider	launched instance	{"commit": "d7e22b1-dirty", "provisioner": "default", "id": "i-XXXXXXXX", "hostname": "ip-XXXXX.ec2.internal", "instance-type": "c5.4xlarge", "zone": "us-east-1b", "capacity-type": "spot", "capacity": {"cpu":"16","ephemeral-storage":"20Gi","memory":"30310Mi","pods":"110"}}
Karpenter was able to provision a “c5.4xlarge” EC2 instance, and our deployment is now up and running!

Clean up the deployment with

kubectl delete -f kubernetes_manifests/autoscale_karpenter_example.yaml
Karpenter will delete the cluster node after a while automatically since it’s not needed anymore.

Our demo reaches an end here as we have seen how to bootstrap an EKS cluster with operational tooling, such as Karpenter for autoscaling and AWS Loadbalancer controller for exposing applications.

For a complete list of add-ons that can be configured with EKS Blueprints, check out the official documentation and the GitHub repository.

4. Clean up
To avoid paying for resources that you have created with this demo, run:

terraform destroy
Key points
In this blog post, we explored the EKS Blueprints for Terraform as an enabler to implement and adopt EKS and provision complete “batteries-included” clusters. We went over the motivation behind this solution, its core concepts, and architecture, and finally, we ran a hands-on demo of provisioning an EKS cluster with Terraform and setting up various tooling as EKS Blueprints addons. 

We encourage you also to explore how Spacelift makes it easy to work with Terraform. If you need any help managing your Terraform infrastructure, building more complex workflows based on Terraform, and managing AWS credentials per run, instead of using a static pair on your local machine, Spacelift is a fantastic tool for this. It supports Git workflows, policy as code, programmatic configuration, context sharing, drift detection, and many more great features right out of the box. You can also see Spacelift integration with AWS, with our Cloud Integrations section and our update to support account-level AWS integrations. Try it for free or book a demo with one of our engineers.

Thank you for reading, and I hope you enjoyed this as much as I did!
