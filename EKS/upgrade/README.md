
##
#
https://aws.github.io/aws-eks-best-practices/upgrades/
#
##

Best Practices for Cluster Upgrades¶
This guide shows cluster administrators how to plan and execute their Amazon EKS upgrade strategy. It also describes how to upgrade self-managed nodes, managed node groups, Karpenter nodes, and Fargate nodes. It does not include guidance on EKS Anywhere, self-managed Kubernetes, AWS Outposts, or AWS Local Zones.

Overview¶
A Kubernetes version encompasses both the control plane and the data plane. To ensure smooth operation, both the control plane and the data plane should run the same Kubernetes minor version, such as 1.24.

Control plane — The control plane version is defined by the Kubernetes API server. In EKS clusters, this is managed by AWS. Upgrades to the control plane version are started using the AWS API.
Data plane — The data plane version references the version of the Kubelet running on your nodes. Different nodes in the same cluster may have different versions. See the version of all nodes with kubectl get nodes.
Keep your cluster updated¶
Keeping up with Kubernetes releases is a critical component of the shared responsibility model when adopting EKS and Kubernetes.

Past a certain point (usually 1 year), the Kubernetes community stops releasing bug and CVE patches. Additionally, the Kubernetes project does not encourage CVE submission for deprecated versions. This means that vulnerabilities specific to an older version of Kubernetes may not even be reported, leaving you exposed with no notice and no remediation options in the case of a vulnerability.

We consider this to be an unacceptable security posture for EKS and our customers, leading to the current policy of automatic upgrades to newer versions. Review the EKS version support policy.

If your cluster is not upgraded before the end of support date, it will be automatically upgraded to the next supported version. Review the Version FAQ for more information. Without proper testing and preparation this may disrupt workloads and controllers. It is highly recommended you stay up to date with Kubernetes releases in EKS.

Develop a well-documented process for handling cluster upgrades. Build runbooks and tooling to support cluster upgrades.

Plan to regularly upgrade your cluster. To keep up with EKS Kubernetes releases, upgrade clusters at least once per year.

Review the EKS release calendar¶
Review the EKS Kubernetes release calendar to learn when new versions are coming, and when support for specific versions end. Generally, EKS releases three minor versions of Kubernetes annually, and each minor version is supported for about 14 months.

Additionally, review the upstream Kubernetes release information.

Understand how the shared responsibility model applies to cluster upgrades¶
You are responsible for initiating upgrade for both cluster control plane as well as the data plane. Learn how to initiate an upgrade. When you initiate a cluster upgrade, AWS manages upgrading the cluster control plane. You are responsible for upgrading the data plane, including Fargate pods and other add-ons. You must validate and plan upgrades for workloads running on your cluster to ensure their availability and operations are not impacted after cluster upgrade

Upgrade clusters in-place¶
EKS supports an in-place cluster upgrade strategy. This maintains cluster resources, and keeps cluster configuration consistent (e.g., API endpoint, OIDC, ENIs, load balancers). This is less disruptive for cluster users, and it will use the existing workloads and resources in the cluster without requiring you to redeploy workloads or migrate external resources (e.g., DNS, storage).

When performing an in-place cluster upgrade, it is important to note that only one minor version upgrade can be executed at a time (e.g., from 1.24 to 1.25).

This means that if you need to update multiple versions, a series of sequential upgrades will be required. Planning sequential upgrades is more complicated, and has a higher risk of downtime. In this situation, evaluate a blue/green cluster upgrade strategy.

Upgrade your control plane and data plane in sequence¶
To upgrade a cluster you will need to take the following actions:

Review the Kubernetes and EKS release notes.
Take a backup of the cluster. (optional)
Identify and remediate deprecated and removed API usage in your workloads.
Ensure Managed Node Groups, if used, are on the same Kubernetes version as the control plane. EKS managed node groups and nodes created by EKS Fargate Profiles only support 1 minor version skew between the control plane and data plane.
Upgrade the cluster control plane using the AWS console or cli.
Review add-on compatibility. Upgrade your Kubernetes add-ons and custom controllers, as required.
Update kubectl.
Upgrade the cluster data plane. Upgrade your nodes to the same Kubernetes minor version as your upgraded cluster.
Use the EKS Documentation to create an upgrade checklist¶
The EKS Kubernetes version documentation includes a detailed list of changes for each version. Build a checklist for each upgrade.

For specific EKS version upgrade guidance, review the documentation for notable changes and considerations for each version.

EKS 1.27
EKS 1.26
EKS 1.25
EKS 1.24
EKS 1.23
EKS 1.22
Upgrade add-ons and components using the Kubernetes API¶
Before you upgrade a cluster, you should understand what versions of Kubernetes components you are using. Inventory cluster components, and identify components that use the Kubernetes API directly. This includes critical cluster components such as monitoring and logging agents, cluster autoscalers, container storage drivers (e.g. EBS CSI, EFS CSI), ingress controllers, and any other workloads or add-ons that rely on the Kubernetes API directly.

Tip

Critical cluster components are often installed in a *-system namespace


kubectl get ns | grep '-system'
Once you have identified components that rely the Kubernetes API, check their documentation for version compatibility and upgrade requirements. For example, see the AWS Load Balancer Controller documentation for version compatibility. Some components may need to be upgraded or configuration changed before proceeding with a cluster upgrade. Some critical components to check include CoreDNS, kube-proxy, VPC CNI, and storage drivers.

Clusters often contain many workloads that use the Kubernetes API and are required for workload functionality such as ingress controllers, continuous delivery systems, and monitoring tools. When you upgrade an EKS cluster, you must also upgrade your add-ons and third-party tools to make sure they are compatible.

See the following examples of common add-ons and their relevant upgrade documentation:

Amazon VPC CNI: For the recommended version of the Amazon VPC CNI add-on for each cluster version, see Updating the Amazon VPC CNI plugin for Kubernetes self-managed add-on. When installed as an Amazon EKS Add-on, it can only be upgraded one minor version at a time.
kube-proxy: See Updating the Kubernetes kube-proxy self-managed add-on.
CoreDNS: See Updating the CoreDNS self-managed add-on.
AWS Load Balancer Controller: The AWS Load Balancer Controller needs to be compatible with the EKS version you have deployed. See the installation guide for more information.
Amazon Elastic Block Store (Amazon EBS) Container Storage Interface (CSI) driver: For installation and upgrade information, see Managing the Amazon EBS CSI driver as an Amazon EKS add-on.
Amazon Elastic File System (Amazon EFS) Container Storage Interface (CSI) driver: For installation and upgrade information, see Amazon EFS CSI driver.
Kubernetes Metrics Server: For more information, see metrics-server on GitHub.
Kubernetes Cluster Autoscaler: To upgrade the version of Kubernetes Cluster Autoscaler, change the version of the image in the deployment. The Cluster Autoscaler is tightly coupled with the Kubernetes scheduler. You will always need to upgrade it when you upgrade the cluster. Review the GitHub releases to find the address of the latest release corresponding to your Kubernetes minor version.
Karpenter: For installation and upgrade information, see the Karpenter documentation.
Verify basic EKS requirements before upgrading¶
AWS requires certain resources in your account to complete the upgrade process. If these resources aren’t present, the cluster cannot be upgraded. A control plane upgrade requires the following resources:

Available IP addresses. To update the cluster, Amazon EKS requires up to five available IP addresses from the subnets that you specified when you created your cluster.
EKS IAM role: The control plane IAM role is still present in the account with the necessary permissions.
EKS security group: Control plane primary security group still available in the account with the necessary access rules.
If your cluster has secret encryption enabled, then make sure that the cluster IAM role has permission to use the AWS Key Management Service (AWS KMS) key.
Verify available IP addresses¶
To update the cluster, Amazon EKS requires up to five available IP addresses from the subnets that you specified when you created your cluster.

To verify that your subnets have enough IP addresses to upgrade the cluster you can run the following command:


CLUSTER=<cluster name>
aws ec2 describe-subnets --subnet-ids \
  $(aws eks describe-cluster --name ${CLUSTER} \
  --query 'cluster.resourcesVpcConfig.subnetIds' \
  --output text) \
  --query 'Subnets[*].[SubnetId,AvailabilityZone,AvailableIpAddressCount]' \
  --output table

----------------------------------------------------
|                  DescribeSubnets                 |
+---------------------------+--------------+-------+
|  subnet-067fa8ee8476abbd6 |  us-east-1a  |  8184 |
|  subnet-0056f7403b17d2b43 |  us-east-1b  |  8153 |
|  subnet-09586f8fb3addbc8c |  us-east-1a  |  8120 |
|  subnet-047f3d276a22c6bce |  us-east-1b  |  8184 |
+---------------------------+--------------+-------+
The VPC CNI Metrics Helper may be used to create a CloudWatch dashboard for VPC metrics.

Verify EKS IAM role¶
To verify that the IAM role is available and has the correct assume role policy in your account you can run the following commands:


CLUSTER=<cluster name>
ROLE_ARN=$(aws eks describe-cluster --name ${CLUSTER} \
  --query 'cluster.roleArn' --output text)
aws iam get-role --role-name ${ROLE_ARN##*/} \
  --query 'Role.AssumeRolePolicyDocument'

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "eks.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
Verify EKS security group¶
To verify that the security groups exist in your account you can run the following commands:


CLUSTER=<cluster name>
aws ec2 describe-security-groups \
  --group-ids $(aws eks describe-cluster \
    --query 'cluster.resourcesVpcConfig.securityGroupIds[*]' \
    --name ${CLUSTER} --output text)

{                                                                                                                                      
    "SecurityGroups": [                                                                                                                
        {                                                                                                                              
            "Description": "Communication between the control plane and worker nodegroups",                                            
            "GroupName": "eksctl-prefix-cluster-ControlPlaneSecurityGroup-HFO1JTSFWL1J",
If you see output like the following then you should double check the security groups used by your cluster and available in your account.


An error occurred (InvalidGroupId.Malformed) when calling the DescribeSecurityGroups operation: Invalid id:
If the security groups aren't found, review Amazon EKS security group requirements and considerations. You may need to recreate the cluster if the eks-cluster-sg-my-cluster-uniqueID security group has been deleted.

Migrate to EKS Add-ons¶
Amazon EKS automatically installs add-ons such as the Amazon VPC CNI plugin for Kubernetes, kube-proxy, and CoreDNS for every cluster. Add-ons may be self-managed, or installed as Amazon EKS Add-ons. Amazon EKS Add-ons is an alternate way to manage add-ons using the EKS API.

You can use Amazon EKS Add-ons to update vesions with a single command. For Example:


aws eks update-addon —cluster-name my-cluster —addon-name vpc-cni —addon-version version-number \
--service-account-role-arn arn:aws:iam::111122223333:role/role-name —configuration-values '{}' —resolve-conflicts PRESERVE
Check if you have any EKS Add-ons with:


aws eks list-addons --cluster-name <cluster name>
Warning

EKS Add-ons are not automatically upgraded during a control plane upgrade. You must initiate EKS add-on updates, and select the desired version.

You are responsible for selecting a compatible version from all available versions. Review the guidance on add-on version compatibility.
Amazon EKS Add-ons may only be upgraded one minor version at a time.
Learn more about what components are available as EKS Add-ons, and how to get started.

Learn how to supply a custom configuration to an EKS Add-on.

Identify and remediate removed API usage before upgrading the control plane¶
You should identify API usage of removed APIs before upgrading your EKS control plane. To do that we recommend using tools that can check a running cluster or static, rendered Kubernetes manifest files.

Running the check against static manifest files is generally more accurate. If run against live clusters, these tools may return false positives.

A deprecated Kubernetes API does not mean the API has been removed. You should check the Kubernetes Deprecation Policy to understand how API removal affects your workloads.

Kube-no-trouble¶
Kube-no-trouble is an open source command line utility with the command kubent. When you run kubent without any arguments it will use your current KubeConfig context and scan the cluster and print a report with what APIs will be deprecated and removed.


kubent

4:17PM INF >>> Kube No Trouble `kubent` <<<
4:17PM INF version 0.7.0 (git sha d1bb4e5fd6550b533b2013671aa8419d923ee042)
4:17PM INF Initializing collectors and retrieving data
4:17PM INF Target K8s version is 1.24.8-eks-ffeb93d
4:l INF Retrieved 93 resources from collector name=Cluster
4:17PM INF Retrieved 16 resources from collector name="Helm v3"
4:17PM INF Loaded ruleset name=custom.rego.tmpl
4:17PM INF Loaded ruleset name=deprecated-1-16.rego
4:17PM INF Loaded ruleset name=deprecated-1-22.rego
4:17PM INF Loaded ruleset name=deprecated-1-25.rego
4:17PM INF Loaded ruleset name=deprecated-1-26.rego
4:17PM INF Loaded ruleset name=deprecated-future.rego
__________________________________________________________________________________________
>>> Deprecated APIs removed in 1.25 <<<
------------------------------------------------------------------------------------------
KIND                NAMESPACE     NAME             API_VERSION      REPLACE_WITH (SINCE)
PodSecurityPolicy   <undefined>   eks.privileged   policy/v1beta1   <removed> (1.21.0)
It can also be used to scan static manifest files and helm packages. It is recommended to run kubent as part of a continuous integration (CI) process to identify issues before manifests are deployed. Scanning manifests is also more accurate than scanning live clusters.

Kube-no-trouble provides a sample Service Account and Role with the appropriate permissions for scanning the cluster.

Pluto¶
Another option is pluto which is similar to kubent because it supports scanning a live cluster, manifest files, helm charts and has a GitHub Action you can include in your CI process.


pluto detect-all-in-cluster

NAME             KIND                VERSION          REPLACEMENT   REMOVED   DEPRECATED   REPL AVAIL  
eks.privileged   PodSecurityPolicy   policy/v1beta1                 false     true         true
Update Kubernetes workloads. Use kubectl-convert to update manifests¶
After you have identified what workloads and manifests need to be updated, you may need to change the resource type in your manifest files (e.g. PodSecurityPolicies to PodSecurityStandards). This will require updating the resource specification and additional research depending on what resource is being replaced.

If the resource type is staying the same but API version needs to be updated you can use the kubectl-convert command to automatically convert your manifest files. For example, to convert an older Deployment to apps/v1. For more information, see Install kubectl convert pluginon the Kubernetes website.

kubectl-convert -f <file> --output-version <group>/<version>

Configure PodDisruptionBudgets and topologySpreadConstraints to ensure availability of your workloads while the data plane is upgraded¶
Ensure your workloads have the proper PodDisruptionBudgets and topologySpreadConstraints to ensure availability of your workloads while the data plane is upgraded. Not every workload requires the same level of availability so you need to validate the scale and requirements of your workload.

Make sure workloads are spread in multiple Availability Zones and on multiple hosts with topology spreads will give a higher level of confidence that workloads will migrate to the new data plane automatically without incident.

Here is an example workload that will always have 80% of replicas available and spread replicas across zones and hosts

```
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: myapp
spec:
  minAvailable: "80%"
  selector:
    matchLabels:
      app: myapp
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 10
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - image: public.ecr.aws/eks-distro/kubernetes/pause:3.2
        name: myapp
        resources:
          requests:
            cpu: "1"
            memory: 256M
      topologySpreadConstraints:
      - labelSelector:
          matchLabels:
            app: host-zone-spread
        maxSkew: 2
        topologyKey: kubernetes.io/hostname
        whenUnsatisfiable: DoNotSchedule
      - labelSelector:
          matchLabels:
            app: host-zone-spread
        maxSkew: 2
        topologyKey: topology.kubernetes.io/zone
        whenUnsatisfiable: DoNotSchedule
```
        
AWS Resilience Hub has added Amazon Elastic Kubernetes Service (Amazon EKS) as a supported resource. Resilience Hub provides a single place to define, validate, and track the resilience of your applications so that you can avoid unnecessary downtime caused by software, infrastructure, or operational disruptions.

Use Managed Node Groups or Karpenter to simplify data plane upgrades¶
Managed Node Groups and Karpenter both simplify node upgrades, but they take different approaches.

Managed node groups automate the provisioning and lifecycle management of nodes. This means that you can create, automatically update, or terminate nodes with a single operation.

In the default configuration, Karpenter automatically creates new nodes using the latest compatible EKS Optimized AMI. As EKS releases updated EKS Optimized AMIs or the cluster is upgraded, Karpenter will automatically start using these images. Karpenter also implements Node Expiry to update nodes.

Karpenter can be configured to use custom AMIs. If you use custom AMIs with Karpenter, you are responsible for the version of kubelet.

Track the version skew of nodes. Ensure Managed Node Groups are on the same version as the control plane before upgrading¶
The upstream Kubernetes project supports minor version skew between the control plane and data plane—specifically the API server and kubelet—of 2 minor versions. If your EKS version is 1.25 then the oldest kubelet you can use is 1.23.

This version skew is different for EKS managed node groups and nodes created by EKS Fargate Profiles. They only support 1 minor version skew between the control plane and data plane (e.g., EKS 1.25 with 1.24 kubelet).

Enable node expiry for Karpenter managed nodes¶
One way Karpenter implements node upgrades is using the concept of node expiry. This reduces the planning required for node upgrades. When you set a value for ttlSecondsUntilExpired in your provisioner, this activates node expiry. After nodes reach the defined age in seconds, they’re safely drained and deleted. This is true even if they’re in use, allowing you to replace nodes with newly provisioned upgraded instances. When a node is replaced, Karpenter uses the latest EKS-optimized AMIs. For more information, see Deprovisioning on the Karpenter website.

Karpenter doesn’t automatically add jitter to this value. To prevent excessive workload disruption, define a pod disruption budget, as shown in Kubernetes documentation.

If you configure ttlSecondsUntilExpired on a provisioner, this applies to existing nodes associated with the provisioner.

Use Drift feature for Karpenter managed nodes¶
Karpenter's Drift feature can automatically upgrade the Karpenter-provisioned nodes to stay in-sync with the EKS control plane. Karpenter Drift currently needs to be enabled using a feature gate. Karpenter's default configuration uses the latest EKS-Optimized AMI for the same major and minor version as the EKS cluster's control plane.

After an EKS Cluster upgrade completes, Karpenter's Drift feature will detect that the Karpenter-provisioned nodes are using EKS-Optimized AMIs for the previous cluster version, and automatically cordon, drain, and replace those nodes. To support pods moving to new nodes, follow Kubernetes best practices by setting appropriate pod resource quotas, and using pod disruption budgets (PDB). Karpenter's deprovisioning will pre-spin up replacement nodes based on the pod resource requests, and will respect the PDBs when deprovisioning nodes.

Use eksctl to automate upgrades for self-managed node groups¶
Self managed node groups are EC2 instances that were deployed in your account and attached to the cluster outside of the EKS service. These are usually deployed and managed by some form of automation tooling. To upgrade self-managed node groups you should refer to your tools documentation.

For example, eksctl supports deleting and draining self-managed nodes.

Some common tools include:

eksctl
kOps
EKS Blueprints
Backup the cluster before upgrading¶
New versions of Kubernetes introduce significant changes to your Amazon EKS cluster. After you upgrade a cluster, you can’t downgrade it.

Velero is an community supported open-source tool that can be used to take backups of existing clusters and apply the backups to a new cluster.

Note that you can only create new clusters for Kubernetes versions currently supported by EKS. If the version your cluster is currently running is still supported and an upgrade fails, you can create a new cluster with the original version and restore the data plane. Note that AWS resources, including IAM, are not included in the backup by Velero. These resources would need to be recreated.

Restart Fargate deployments after upgrading the control plane¶
To upgrade Fargate data plane nodes you need to redeploy the workloads. You can identify which workloads are running on fargate nodes by listing all pods with the -o wide option. Any node name that begins with fargate- will need to be redeployed in the cluster.

Evaluate Blue/Green Clusters as an alternative to in-place cluster upgrades¶
Some customers prefer to do a blue/green upgrade strategy. This can have benefits, but also includes downsides that should be considered.

Benefits include:

Possible to change multiple EKS versions at once (e.g. 1.23 to 1.25)
Able to switch back to the old cluster
Creates a new cluster which may be managed with newer systems (e.g. terraform)
Workloads can be migrated individually
Some downsides include:

API endpoint and OIDC change which requires updating consumers (e.g. kubectl and CI/CD)
Requires 2 clusters to be run in parallel during the migration, which can be expensive and limit region capacity
More coordination is needed if workloads depend on each other to be migrated together
Load balancers and external DNS cannot easily span multiple clusters
While this strategy is possible to do, it is more expensive than an in-place upgrade and requires more time for coordination and workload migrations. It may be required in some situations and should be planned carefully.

With high degrees of automation and declarative systems like GitOps, this may be easier to do. You will need to take additional precautions for stateful workloads so data is backed up and migrated to new clusters.

Review these blogs posts for more information:

Kubernetes cluster upgrade: the blue-green deployment strategy
Blue/Green or Canary Amazon EKS clusters migration for stateless ArgoCD workloads
Track planned major changes in the Kubernetes project — Think ahead¶
Don’t look only at the next version. Review new versions of Kubernetes as they are released, and identify major changes. For example, some applications directly used the docker API, and support for Container Runtime Interface (CRI) for Docker (also known as Dockershim) was removed in Kubernetes 1.24. This kind of change requires more time to prepare for.

Review all documented changes for the version that you’re upgrading to, and note any required upgrade steps. Also, note any requirements or procedures that are specific to Amazon EKS managed clusters.

Kubernetes changelog
Specific Guidance on Feature Removals¶
Removal of Dockershim in 1.25 - Use Detector for Docker Socket (DDS)¶
The EKS Optimized AMI for 1.25 no longer includes support for Dockershim. If you have a dependency on Dockershim, e.g. you are mounting the Docker socket, you will need to remove those dependencies before upgrading your worker nodes to 1.25.

Find instances where you have a dependency on the Docker socket before upgrading to 1.25. We recommend using Detector for Docker Socket (DDS), a kubectl plugin..

Removal of PodSecurityPolicy in 1.25 - Migrate to Pod Security Standards or a policy-as-code solution¶
PodSecurityPolicy was deprecated in Kubernetes 1.21, and has been removed in Kubernetes 1.25. If you are using PodSecurityPolicy in your cluster, then you must migrate to the built-in Kubernetes Pod Security Standards (PSS) or to a policy-as-code solution before upgrading your cluster to version 1.25 to avoid interruptions to your workloads.

AWS published a detailed FAQ in the EKS documentation.

Review the Pod Security Standards (PSS) and Pod Security Admission (PSA) best practices.

Review the PodSecurityPolicy Deprecation blog post on the Kubernetes website.

Deprecation of In-Tree Storage Driver in 1.23 - Migrate to Container Storage Interface (CSI) Drivers¶
The Container Storage Interface (CSI) was designed to help Kubernetes replace its existing, in-tree storage driver mechanisms. The Amazon EBS container storage interface (CSI) migration feature is enabled by default in Amazon EKS 1.23 and later clusters. If you have pods running on a version 1.22 or earlier cluster, then you must install the Amazon EBS CSI driver before updating your cluster to version 1.23 to avoid service interruption.

Review the Amazon EBS CSI migration frequently asked questions.

Additional Resources¶
ClowdHaus EKS Upgrade Guidance¶
ClowdHaus EKS Upgrade Guidance is a CLI to aid in upgrading Amazon EKS clusters. It can analyze a cluster for any potential issues to remediate prior to upgrade.

GoNoGo¶
GoNoGo is an alpha-stage tool to determine the upgrade confidence of your cluster add-ons.
