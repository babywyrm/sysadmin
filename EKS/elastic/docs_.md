
Chapter 3 The Guide to Helm & EKS

##
#
https://www.densify.com/kubernetes-tools/helm-eks
#
##

Kubernetes (also known as K8s) is one of the center stage tools of the cloud native ecosystem. Over the years, it has continued to grow exponentially in enterprise adoption, with Amazon EKS showing substantial popularity over other Kubernetes cloud service offerings (at least in Google searches). However, like Nigel Poulton often says, "Kubernetes, is Kubernetes, is Kubernetes'', highlighting the agnostic nature of the platform regardless of where it's running. So when it comes to making use of Amazon EKS, you'll still be dealing with the familiar but distinct Kubernetes resources such as Pods, ConfigMaps, Deployments and Services, to mention a few. They each play an important role, and deploying applications to your EKS cluster will usually require more than one of these Kubernetes objects.

As you can imagine, the larger your application is, the more K8s resources you'll have to manage in terms of writing YAML files. Furthermore, you will have to manually deploy these objects just to get your application working. That is, unless you use Helm. Helm is a package manager that optimises management and deployments of K8s resources to streamline the journey of getting your application running. In this article, you'll learn what Helm is, how it works, and more importantly, how to make use of it with your Amazon EKS cluster.
What is Helm?

Helm is a package manager that works very similar to brew, choco, apt and yum on Mac OS, Windows, Debian and Red Hat, respectively. It is used for software installation and gives you the advantage of using a single command to install something. The alternative would be to follow a manual approach which is susceptible to several unresolved dependencies that are hard to piece together. For example, if you followed a manual process to deploy a frontend application on an EKS cluster, it would likely involve running the following commands at the bear minimum:

kubectl apply -f frontend-pod.yaml
kubectl apply -f frontend-service.yaml
kubectl apply -f ingress.yaml

This might not seem like a big deal for a small application, but you’re asking for trouble if you intend to do this at scale. In the following subsections, I will outline how Helm solves this problem.
Helm Architecture

Using Helm, you can package your application into what is known as a Helm chart. A Helm chart is simply a directory with some files in a specific structure that adhere to the chart specification for describing the resources to be installed on Kubernetes. It may also contain any other resource definitions that are required to run an application or service on your EKS cluster. That directory structure looks like this:

    The top-level directory name should match the name of your chart.
    chart.yaml: This file contains metadata such as information about the chart version, the name and description of the chart, and who authored the chart. It also typically includes details about dependencies (like MongoDB or PostgreSQL) which, prior to Helm 3, used to be tracked in a separate file named requirements.yaml.
    values.yaml: This file stores default configuration values that can be overridden during installation and upgrade.
    templates: Templates are Kubernetes manifests that are potentially annotated with templating directives.

You can read more about Helm chart best practices.
How Helm Manages Packages

Helm Chart
    As highlighted above, charts are a bunch of K8s resource definitions (the yaml files), and Helm manages these charts. Helm uses this information along with a config to instantiate a released object.
Running vs Desired State
    If a Helm chart has been released, Helm can determine what the current state of the environment is versus the desired state and make changes as needed. So if you are working with EKS, Helm will know what has already been deployed and is currently running in the EKS cluster.
Least Invasive Change
    In the event that there is a change to a release, Helm will only change what has been updated since the last release. For example, if you update the version of your frontend container, you don't have to tear down the entire package. Helm will simply increment the frontend container.
Release Tracking
    Helm versions releases. So if something goes wrong, the release can be rolled back to a previous version.

How Helm Helps with Installations and Releases

Single command install
    Using the helm install command, a chart can be released using a Helm repository.
Provide insights for releases
    With the helm status command, it is possible to see the details of the running state of a release.
Perform simple update/upgrades
    With the helm upgrade command, you can apply changes to a chart (e.g. versioning a service) and helm will do the update for you.
Provide the ability to rollback
    Helm tracks releases and versions them. By using the helm rollback command, it is possible to revert to a previous release.
Simplify Deployment
    Charts can be created by the application expert and released by someone else with a single command.
Single Command Uninstall
    By using helm uninstall, the reverse of the installation can be done. This makes a cleaner removal, as all components that are defined are also removed.

Why use Helm with Amazon EKS?

Amazon EKS (Amazon Elastic Container Service for Kubernetes) is a managed service that makes it easy for you to run Kubernetes on AWS without the need to setup, provision or maintain your own control plane. It is Kubernetes compliant and has a managed control plane. AWS is responsible for provisioning, running, managing and auto-scaling the K8s master and etcd nodes across multiple AWS AZs (Availability Zones) for high availability. Users are responsible for adding and managing the EC2 worker nodes, unless they opt for the Fargate serverless engine. Amazon EKS clusters run within Amazon VPCs. In order to communicate with the cluster, you have to configure it to either have public endpoint access control, private endpoint access control or both.

Using Helm with Amazon EKS offers a huge benefit when it comes to alleviating management overhead. The combination of the two takes away the burden of expertly managing and scaling the cluster control plane, and removes the chaos that comes with managing a number of YAML files to deploy applications. This frees up software developers to focus on application development and gives DevOps engineers the opportunity to focus on optimising the cluster environment.

Helm makes it easier to successfully manage your workloads on EKS clusters. With the use of Helm charts from third party repositories, DevOps engineers don’t have to re-invent the wheel by creating complex charts. They can rather make use of pre-existing resources and configure them to suit their cluster environments. Popular Helm charts that would be no stranger to a number of EKS cluster environments would include the Nginx Controller, ALB Ingress Controller, Prometheus, Grafana and Fluentd, to name a few. Third party tools such as these add a great deal of value, but are also very complex to work with when following a self-managed approach. Leveraging the work (and ongoing contributions) of the developer community through usage of open-source Helm charts minimises the effort to deploy such robust tools onto an EKS cluster.
You like our article?

Follow our LinkedIn monthly digest to receive more free educational content like this.
Follow LinkedIn K8s digest
Automated, Intelligent Container Sizing

Kubernetes Vertical Pod Autoscaling doesn’t recommend pod limit values or consider I/O. Densify identifies mis-provisioned containers at a glance and prescribes the optimal configuration.

Densify has partnered with Intel to offer one year of free resource optimization software licensing to qualified companies.
Intel + Densify
See if your company qualifies
Visualization of memory resource risk
Deploying Nginx to Amazon EKS using Helm

In this section you will deploy an nginx container to an Amazon EKS cluster. Before going any further, there are a few prerequisites to have in place in order for you to successfully carry out the next steps.

    Helm v3 installed
    AWS CLI installed and configured with an IAM profile
    The eksctl command line utility
    The Kubernetes command line tool, kubectl

Create The EKS Cluster

Creating an EKS cluster can be a complex and time consuming task. At the minimum, it requires a good understanding of the AWS VPC networking landscape, the relevant IAM roles for the cluster control plane and nodes, and their respective security groups. However, all of this heavy lifting, in terms of configuration and setup, is abstracted away and taken care of when you use the eksctl command line tool. To create an EKS cluster, you provide eksctl with a configuration file that details the specifics for the type of setup you want. These files can be very basic or long and complex depending on your desired outcome. For this example, I’m going to keep it simple and provide some basic configuration such as the name of the cluster, the region it should be deployed to, my desired networking for API cluster accessibility and some specifics for the node group. You can create a YAML file and save it as cluster.yaml.

apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
 name: your-eks-cluster
 region: eu-west-1

vpc:
 clusterEndpoints:
   publicAccess:  true
   privateAccess: true

nodeGroups:
 - name: ng-1
   instanceType: t3.medium
   desiredCapacity: 2

You can proceed to create a cluster, and all the required resources, by running the command below in the same directory as your EKS cluster configuration file:

eksctl create cluster -f cluster.yaml

Once the EKS cluster has been created, you can update your kubeconfig and connect to the cluster.

aws eks --region eu-west-1 update-kubeconfig --name your-eks-cluster
Create The Helm Chart

Helm makes it easy for you to get started with creating a chart by simply running the helm create command. You are going to name your chart ‘frontend’, so the first step is to run the following command:

helm create frontend

This command will generate a new chart directory with a number of relevant files and folders that are required for a basic functioning chart.

frontend
├── Chart.yaml 
├── .helmignore 
├── charts 
├── templates 
│   ├── NOTES.txt 
│   ├── _helpers.tpl
│   ├── deployment.yaml
│   ├── ingress.yaml
│   ├── service.yaml
│   ├── serviceaccount.yaml
│   └── tests
│       └── test-connection.yaml 
└── values.yaml

If you take a look at the values.yaml file you will see that the image repository is set to pull images from the official nginx repository. Scroll down the values.yaml file to the service configuration and you will see that it is set to ClusterIP by default. You won’t be able to access your application outside of the cluster with this default configuration, but you can proceed with installation anyhow.

You can ensure that your kubectl command line tool is correctly configured to communicate with your EKS cluster with the following command:

kubectl config current-context

You should see a response with the Amazon Resource Name (ARN) for your EKS cluster. To install the application with Helm, run the helm install command in the directory of the chart.

helm install frontend .

This will deploy your application, and to verify that the pod is running successfully, you can use kubectl to fetch the pods in the default namespace of your EKS cluster.

kubectl get pods

Once you’ve confirmed that the pod is running, the next step will be to upgrade your application. This upgrade will involve an update to the configuration of the service. You can modify the service type from ClusterIP to LoadBalancer in the values.yaml file. This will make the application publicly accessible. You can then save the file and run the helm upgrade command.

helm upgrade frontend .

Once the upgrade is complete, you can get the domain name (listed under External IP) from the service. Keep in mind, the load balancer typically takes a few minutes to get fully setup and configured.

kubectl get svc

Once your load balancer is ready, you can access the nginx application running in your EKS cluster using the generated domain name presented in the description of the service.
Tips for Using Helm

Helm version 3 offers many improvements over its version 2, even though many teams still use the older version. The best known improvement is the elimination of Tiller as the required server-side agent. Below we highlight a couple of the other improvements that are worth keeping in mind.

One challenge with v2 was a lack of certainty when it came to knowing exactly what you are deploying onto your EKS cluster. When you used Helm charts created by other software developers, it was difficult to know what kind of issues you may be introducing to your own cluster.

You can mitigate this in either version of Helm by issuing the install or upgrade commands with the --dry-run flag which will render all of the K8s objects that will be deployed and display the list on the screen. You can also issue the template command to see a rendering prior to deployment. It may go without saying, but is also recommended to only use trusted repositories and read all of the notes prior to using the chart.

Another challenge with Helm v2 was that when it failed, it did so quietly. This means that, often, it was too late to catch the issue by the time you realized it’s happening. For example, when you deleted a chart, Helm had forgotten to remove that chart from Kubernetes, and now you must have remembered to do it yourself manually. This would have been an extra step to add on your checklist as an administrator. The command validation is more clear version 3 so this is not so much of an issue anymore.

An additional recommendation would be for you to enable the debug flag for verbose output and read the Helm response after each issued command. The message will tell you whether the command was successful or not. In the delete example, it will indicate if a delete command has failed.
Conclusion

It goes without saying that Helm is a very useful, if not necessary, tool for managing Amazon EKS at scale, freeing teams up from writing an unmanageable amount of YAML files and having to maintain them. One of its greatest benefits is the ability to publish and use standard or even crowd-sourced Helm charts, which are managed by others with similar needs. Using Helm in conjunction with Amazon EKS solves a management overhead problem for integrated microservice teams, giving software developers and DevOps engineers the room to focus on optimisation of other key areas.
