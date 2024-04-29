Monitoring AWS EKS Audit Logs with Falco
Seifeddine Rajhi
Seifeddine Rajhi

##
#
https://medium.com/@seifeddinerajhi/monitoring-aws-eks-audit-logs-with-falco-d797e76b4260
#
##





🔍 Detecting Threats in AWS EKS Audit Logs with Falco


🔎 Introduction:
AWS EKS Audit Logs provide a detailed record of all activity on your EKS cluster, including user actions, API calls, and system events. This information can be used to track changes to your cluster, detect suspicious activity, and troubleshoot problems.

Falco is a Kubernetes threat detection engine that can be used to monitor AWS EKS Audit Logs for suspicious activity. Falco uses a set of rules to detect events that may indicate a security breach or attack. For example, Falco can detect events such as:

Containers running with elevated privileges
Containers accessing sensitive files or resources
Containers communicating with known malicious IP addresses
By monitoring AWS EKS Audit Logs with Falco, you can improve the security of your Kubernetes clusters and detect threats early.

In this blog post, we will show you how to configure Falco to monitor AWS EKS Audit Logs. We will also discuss some of the benefits of using Falco to monitor EKS Audit Logs.


Faclo: what is it and How it works:
Falco is a Kubernetes threat detection engine. Falco supports Kubernetes Audit Events to track the changes defined in k8s audit rules made to your cluster.

Unfortunately, AWS EKS is a managed Kubernetes service, and it only can send audit logs to CloudWatch. It means there is no direct way for Falco to inspect the EKS audit events.

We need to implement a solution to ship audit logs from CloudWatch to Falco. There are three solutions.

https://github.com/sysdiglabs/ekscloudwatch
https://github.com/xebia/falco-eks-audit-bridge (I will not recommend this solution. It is a bit complex and requires extra setup like setup S3 bucket and AWS Kinesis Firehose service)
Kubernetes Audit Events Plugin for EKS: This plugin supports consuming Kubernetes Audit Events stored in Cloudwatch Logs for the EKS Clusters.
Prerequisites:
Enable Audit in EKS cluster:


Enable IAM Roles for Service Accounts (IRSA) on the EKS cluster if you have not enabled it yet.


Install falco server:
The deployment of Falco in a Kubernetes cluster is managed through a Helm chart. This chart manages the lifecycle of Falco in a cluster by handling all the k8s objects needed by Falco to be seamlessly integrated in your environment.

Based on the configuration in values.yaml file, the chart will render and install the required k8s objects. Keep in mind that Falco could be deployed in your cluster using a daemonset or a deployment.

Before installing Falco in a Kubernetes cluster, a user should check that the kernel version used in the nodes is supported by the community. Also, before reporting any issue with Falco (missing kernel image, CrashLoopBackOff and similar), make sure to read about the driver section and adjust your setup as required.

Adding falcosecurity repository:
Before installing the chart, add the falcosecurity charts repository:

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
Installing the Chart
To install the chart with the release name falco in namespace falco run:

helm install falco falcosecurity/falco --namespace falco \
--create-namespace --values-k8saudit.yaml
where values.yaml :

# -- Disable the drivers since we want to deploy only the k8saudit plugin.
driver:
  enabled: false

# -- Disable the collectors, no syscall events to enrich with metadata.
collectors:
  enabled: false

# -- Deploy Falco as a deployment. One instance of Falco is enough. Anyway the number of replicas is configurabale.
controller:
  kind: deployment
  deployment:
    # -- Number of replicas when installing Falco using a deployment. Change it if you really know what you are doing.
    # For more info check the section on Plugins in the README.md file.
    replicas: 1


falcoctl:
  artifact:
    install:
      # -- Enable the init container. We do not recommend installing (or following) plugins for security reasons since they are executable objects.
      enabled: true
    follow:
      # -- Enable the sidecar container. We do not support it yet for plugins. It is used only for rules feed such as k8saudit-rules rules.
      enabled: true
  config:
    artifact:
      install:
        # -- Do not resolve the depenencies for artifacts. By default is true, but for our use case we disable it.
        resolveDeps: false
        # -- List of artifacts to be installed by the falcoctl init container.
        # Only rulesfiles, we do no recommend plugins for security reasonts since they are executable objects.
        refs: [k8saudit-rules:0.6]
      follow:
        # -- List of artifacts to be followed by the falcoctl sidecar container.
        # Only rulesfiles, we do no recommend plugins for security reasonts since they are executable objects.
        refs: [k8saudit-rules:0.6]

services:
  - name: k8saudit-webhook
    type: NodePort
    ports:
      - port: 9765 # See plugin open_params
        nodePort: 30007
        protocol: TCP

falco:
  rules_file:
    - /etc/falco/k8s_audit_rules.yaml
    - /etc/falco/rules.d
  plugins:
    - name: k8saudit
      library_path: libk8saudit.so
      init_config:
        ""
        # maxEventBytes: 1048576
        # sslCertificate: /etc/falco/falco.pem
      open_params: "http://:9765/k8s-audit"
    - name: json
      library_path: libjson.so
      init_config: ""
  # Plugins that Falco will load. Note: the same plugins are installed by the falcoctl-artifact-install init container.
  load_plugins: [k8saudit, json]
After a few minutes, Falco instances should be running on all your nodes. The status of Falco pods can be inspected through kubectl:

kubectl get pods -n falco -o wide
If everything went smoothly, you should observe an output similar to the following, indicating that all Falco instances are up and running in you cluster.

helm will also expose a service with the helm application name prefix. It is falco in this deployment.

ekscloudwatch: Forward EKS CloudWatch k8s audit events to Sysdig:
The following instructions show how to deploy a simple application that reads EKS Kubernetes audit logs and forwards them to the Sysdig Secure agent. The steps below show an example configuration implemented with the AWS console, but the same can be done with scripts, API calls or Infrastructure-as-Code configurations.

These instructions have been tested with eks.5 on Kubernetes v1.14.

EKS setup: enable CloudWatch audit logs:
Your EKS cluster needs be configured to forward audit logs to CloudWatch, which is disabled by default.

Open the EKS dashboard from the AWS console
Select your cluster > Logging > Update and enable Audit

EKS setup: configure the VPC endpoint:
Your VPC needs an endpoint for the service com.amazonaws.<your-region>.logs, accessible from all the EKS security groups.

Open the VPC dashboard from the AWS console
Select Endpoints > Create Endpoints
Select Find service by name, enter com.amazonaws.<your-region>.logs and click "Verify".
Under VPC select your cluster’s VPC
Select all security groups
EKS setup: configure EC2 instance profiles and roles:
The EC2 instances that make up your EKS cluster must have the necessary permission to read CW logs. Usually, they all use the same IAM Role, so that is the one to configure.

Open the EC2 dashboard from the AWS console.
Select the AWS EC2 instances that are configured as cluster nodes.
Select the associated IAM Role, which should be the same for all nodes.
Find the policy CloudWatchReadOnlyAccess and attach it.

Configure IAM role and policy for IRSA:
Create a policy called ekscloudwatch-eks-cw-policy then create a role with a Trust Relationship for and attach the policy above which is called ekscloudwatch-eks-cw-role in this deployment

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "logs:List*",
                "logs:Get*",
                "logs:FilterLogEvents",
                "logs:Describe*",
                "cloudwatch:List*",
                "cloudwatch:Get*",
                "cloudwatch:Describe*"
            ],
            "Resource": "arn:aws:logs:*:*:log-group:/aws/eks/*"
        }
    ]
}
Edit arn:aws:iam::12345678910:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/1847B92748AB2A2XYZ and oidc.eks.eu-west-1.amazonaws.com/id/1847B92748AB2A2XYZ:sub called it ekscloudwatch-eks-cw-rolein this example for serviceaccount in falco namespace

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::12345678910:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/1847B92748AB2A2XYZ"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.eu-west-1.amazonaws.com/id/1847B92748AB2A2XYZ:sub": "system:serviceaccount:falco:ekscloudwatch"
        }
      }
    }
  ]
}
Edit role-arn and cluster_name and region Edit namespace if you are using a different namespace than falco Edit endpoint: "http://falco-k8saudit-webhook:9765/k8s-audit" if you installed falco with a different name than falco.

apiVersion: v1
kind: ServiceAccount
metadata:
    name: ekscloudwatch
    namespace: falco
    annotations:
      eks.amazonaws.com/role-arn: "arn:aws:iam::12345678910:role/ekscloudwatch-eks-cw-role"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ekscloudwatch-config
  namespace: falco
data:
  # Required: Endpoint to forward audit events to, such as Sysdig Secure agent
  # The agent must expose a k8s audit server (k8s_audit_server_port must be configured in the agent as well)
  # Assumed that falco helm name is falco. If you use different name, change  falco with your helm name in the endpoint value.
  endpoint: "http://falco-k8saudit-webhook:9765/k8s-audit"

  # Required: Cloudwatch polling interval
  cw_polling: "5m"

  # Required: CloudWatch query filter
  cw_filter: '{ $.sourceIPs[0] != "::1" && $.sourceIPs[0] != "127.0.0.1" }'

  # Optional: the EKS cluster name
  # This can be omitted if the EC2 instance can perform the ec2:DescribeInstances action
  cluster_name: "my-eks-cluster"
  aws_region: "eu-west-1" #please change this with your region
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: eks-cloudwatch
  namespace: falco
spec:
  minReadySeconds: 5
  replicas: 1
  selector:
    matchLabels:
      app: eks-cloudwatch
  template:
    metadata:
      labels:
        app: eks-cloudwatch
    spec:
      serviceAccountName: ekscloudwatch
      securityContext:
        fsGroup: 65534 # to be able to read Kubernetes and AWS token files
      containers:
        - image: sysdiglabs/k8sauditlogforwarder:ekscloudwatch-0.3
          imagePullPolicy: Always
          name: eks-cloudwatch-container
          env:
            - name: ENDPOINT
              valueFrom:
                configMapKeyRef:
                  name: ekscloudwatch-config
                  key: endpoint
            - name: CLUSTER_NAME
              valueFrom:
                configMapKeyRef:
                  name: ekscloudwatch-config
                  key: cluster_name
            - name: AWS_REGION
              valueFrom:
                configMapKeyRef:
                  name: ekscloudwatch-config
                  key: aws_region
            - name: CW_POLLING
              valueFrom:
                configMapKeyRef:
                  name: ekscloudwatch-config
                  key: cw_polling
            - name: CW_FILTER
              valueFrom:
                configMapKeyRef:
                  name: ekscloudwatch-config
                  key: cw_filter
1. Edit the value of eks.amazonaws.com/role-arn in serviceaccount with your role arn

eks.amazonaws.com/role-arn: "arn:aws:iam::12345678910:role/ekscloudwatch-eks-cw-role"
2. Edit cluster_name: "my-eks-cluster" with your cluster name in configmap

3. Edit endpoint: "http://falco-k8saudit-webhook:9765/k8s-audit" if you installed falco with a different name than falco.

4. Don’t forget to set your region aws_region. If you don’t set ekscloudwatch will call ec2 imdsv1 to get the region name.

Deploy ekscloudwatch:

kubectl apply -f .
You can get details of the rules at: https://github.com/falcosecurity/rules/tree/main/rules

Kubernetes Audit Events Plugin for EKS:
This plugin extends Falco to support Kubernetes Audit Events from AWS EKS clusters as a new data source. For more details about what Audit logs are, see the README of k8saudit plugin.

Functionality:

This plugin supports consuming Kubernetes Audit Events stored in Cloudwatch Logs for the EKS Clusters, see AWS official documentation for details.

Capabilities:

The k8saudit-eks uses the field extraction methods of the k8saudit plugin as the format for the Audit Logs is same.

Event Source:

The event source for Kubernetes Audit Events from EKS is k8s_audit, it allows to use same rules than k8saudit plugin.

Configuration:

Here’s an example of configuration of falco.yaml:

plugins:
  - name: k8saudit-eks
    library_path: libk8saudit-eks.so
    init_config:
      region: "us-east-1"
      profile: "default"
      shift: 10
      polling_interval: 10
      use_async: false
      buffer_size: 500
    open_params: "my-cluster"
  - name: json
    library_path: libjson.so
    init_config: ""

load_plugins: [k8saudit-eks, json]
Initialization Config:

profile: The Profile to use to create the session, env var AWS_PROFILE if present
region: The Region of your EKS cluster, env var AWS_REGION is used if present
use_async: If true then async extraction optimization is enabled (Default: true)
polling_interval: Polling Interval in seconds (default: 5s)
shift: Time shift in past in seconds (default: 1s)
buffer_size: Buffer Size (default: 200)
Open Parameters A string which contains the name of your EKS Cluster (required).

Rules:

The k8saudit-eks plugin ships with no default rule for test purpose, you can use the same rules than those for k8saudit plugin. See here.

To test if it works anyway, you can still use this one for example:

- required_engine_version: 15
- required_plugin_versions:
  - name: k8saudit-eks
    version: 0.2.0

- rule: Dummy rule
  desc: >
    Dummy rule
  condition: >
    ka.verb in (get,create,delete,update)
  output: user=%ka.user.name verb=%ka.verb target=%ka.target.name target.namespace=%ka.target.namespace resource=%ka.target.resource
  priority: WARNING
  source: k8s_audit
  tags: [k8s]
AWS IAM Policy Permissions:

This plugin retrieves Kubernetes audit events from Amazon CloudWatch Logs and it therefore needs appropriate permissions to perform these actions. If you use a profile or associate a role to the service account in Kubernetes with an OIDC provider, you need to grant it permissions.

Here is a AWS IAM policy document that satisfies the requirements:

{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Sid":"ReadAccessToCloudWatchLogs",
      "Effect":"Allow",
      "Action":[
        "logs:Describe*",
        "logs:FilterLogEvents",
        "logs:Get*",
        "logs:List*"
      ],
      "Resource":[
        "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:/aws/eks/${CLUSTER_NAME}/cluster:*"
      ]
    }
  ]
}
The three placeholders REGION, ACCOUNT_ID, and CLUSTER_NAME which must be replaced with fitting values.

Running locally:

This plugin requires Falco with version >= 0.35.0.

falco -c falco.yaml -r rules/k8s_audit_rules.yaml
17:48:41.067076000: Warning user=eks:certificate-controller verb=get target=eks-certificates-controller target.namespace=kube-system resource=configmapsEvents detected: 1
Rule counts by severity:
   WARNING: 1
Triggered rules by rule name:
   Dummy rule: 1
Syscall event drop monitoring:
   - event drop detected: 0 occurrences
   - num times actions taken: 0
Running in EKS:

When running Falco with the k8saudit-eks plugin in a kubernetes cluster, you can't have more than 1 pod at once. The plugin pulls the logs from Cloudwatch Logs, having multiple instances will lead to multiple gatherings of the same logs and the duplication of alerts.

You can use the official Falco helm chart to deploy it with the k8saudit-eks plugin as 1 replica deployment. You can also use it to associate the IAM role you created (see AWS IAM Policy Permissions).

See this example of values.yaml.

tty: true
kubernetes: false #disable the collection of k8s metadata
falco:
  rules_file:
    - /etc/falco/k8s_audit_rules.yaml #rules to use
    - /etc/falco/rules.d
  plugins:
    - name: k8saudit-eks
      library_path: libk8saudit-eks.so
      init_config:
        region: ${REGION} #replace with your region
        shift: 10
        polling_interval: 10
        use_async: false
        buffer_size: 500
      open_params: ${CLUSTER_NAME} #replace with your cluster name
    - name: json
      library_path: libjson.so
      init_config: ""
  load_plugins: [k8saudit-eks, json] #plugins to load
driver:
  enabled: false #disable the collection of syscalls
collectors:
  enabled: false #disable the collection of container metadata
controller:
  kind: deployment
  deployment:
    replicas: 1 #1 replica deployment to avoid duplication of alerts
falcoctl: #use falcoctl to install automatically the plugin and the rules
  indexes:
  - name: falcosecurity
    url: https://falcosecurity.github.io/falcoctl/index.yaml
  artifact:
    install:
      enabled: true
    follow:
      enabled: true
  config:
    artifact:
      allowedTypes:
        - plugin
        - rulesfile
      install:
        resolveDeps: false
        refs: [k8saudit-rules:0, k8saudit-eks:0, json:0]
      follow:
        refs: [k8saudit-rules:0]
serviceAccount:
  create: true
  annotations:
    - eks.amazonaws.com/role-arn: arn:aws:iam::${ACCOUNT_ID}:role/${ROLE} #if you use an OIDC provider, you can attach a role to the service account
Conclusion:
In order to enhance your Kubernetes security strategy, it is important to be attentive to new features and improvements, incorporating those that will let you gain visibility into suspicious events or misconfigurations like Kubernetes audit log events.

The information gathered in these logs can be very useful to understand what is going on in our cluster, and can even be required for compliance purposes.

Tuning the rules with care and using less verbose mode when required can also help us lower costs when using a SaaS centralized logging solution.

But what really makes a difference here is the use of Falco as a threat detection engine. Choosing it to be your webhook backend is the first step towards enforcing Kubernetes security best practices, detecting misuse, and filling the gap between what you think the cluster is running and what’s actually running.

Thank you for Reading, see you in the next post. 🤟
