##
#
https://aws.amazon.com/blogs/containers/hardeneks-validating-best-practices-for-amazon-eks-clusters-programmatically/
#
##



HardenEKS: Validating Best Practices For Amazon EKS Clusters Programmatically
by Doruk Ozturk, Joshua Kurz, and Jacob Mevorach | on 26 MAY 2023 | in Amazon Elastic Kubernetes Service, Best Practices, Containers, Technical How-to, Thought Leadership | Permalink |  Share
Introduction

HardenEKS is an open source Python-based Command Line Interface (CLI). We created HardenEKS to make it easier to programmatically validate if an Amazon Elastic Kubernetes Service (Amazon EKS)  cluster follows best practices defined in AWS’ EKS Best Practices Guide (EBPG). The EBPG is an essential resource for Amazon EKS operators who seek easier Day 2 Operations. The guide includes chapters that cover security, reliability, autoscaling, networking, and scalability. HardenEKS has incorporated and codified the pillars of the EBPG into a set of rules. HardenEKS was released in November of 2022. After the initial release, HardenEKS generated considerably high interest and gained traction both from internal AWS teams and AWS customers.

We invite you to learn more about HardenEKS and to use it to validate best practices against Amazon EKS clusters. We wanted to make it easy for Amazon EKS operators to ensure their clusters were following best practices. The EKS Best Practice Guide is very detailed and contains a vast amount of information on how to best run and secure an Amazon EKS cluster. It can be a large undertaking to read through each piece of the best practice guide and determine if a specific cluster is following the guidelines. HardenEKS condenses the best practices into a programmable module that can be ran against any Amazon EKS cluster. Check out our documentation to learn more.
What is HardenEKS?

The EBPG currently covers six pillars of best practices for Amazon EKS clusters: Security, Reliability, Autoscaling, Networking, Scalability, and Windows Containers. HardenEKS focuses on Amazon EKS best practice rules that have programmable logic, which can be implemented in code. Today there are more than 40 automated rules integrated, with HardenEKS with more being added.

HardenEKS isn’t required to run as an operator. This means that there is no installation required to validate best practices against your Amazon EKS cluster. Instead, all rules are validated externally, which allows for safer and less intrusive means of validating the best practices. By remaining external, HardenEKS can be run by all experience levels. If you wanted to use HardenEKS to help achieve ongoing and automated surveillance, you could accomplish this by running HardenEKS on a regular schedule through a means of your choosing.
Walkthrough

In this walkthrough, we download and install HardenEKS. Next, We validate all rules against a running Amazon EKS cluster and return a generated report. After the report is generated, we discuss some details of how the report is structured. Afterwards, we take a deep dive into a sample best practice and show how fixing the best practice changes the report output.

To quickly start:

python3 -m venv /tmp/.venv
source /tmp/.venv/bin/activate
pip install hardeneks
hardeneks --export-html report.html
open report.html

The previous command results in creation of an html file with rules that are violated. Below is a screenshot of the generated report that HardenEKS returns. HardenEKS validates each EBPG section against a cluster. If a rule is broken, then HardenEKS prints out details of the configuration that broke the rule and associates the EKS Best Practice information alongside of the details.

Screenshot of a sample HardenEKS report with various policy violations.

Each result has a link associated with it, which leads to information about best practices for that specific violation. The results can be used to help understand if there are any issues with a cluster that you want to remediate.

In the previous example, the report indicates that the Amazon Elastic Block Store (Amazon EBS) volumes used by this cluster don’t have encryption at rest configured as per the recommendations in the EBPG.

Screenshot of a report which shows encrypted Amazon EBS StorageClass violation mitigated.

Once we follow the recommendations in the EBPG and configure Amazon EBS encryption by setting the encryption flag to true on the Amazon EBS StorageClass parameters. You can regenerate the report to confirm there is no longer a recommendation to change the configuration encryption for our Amazon EBS volumes, because we’re adhering to best practices as described in the EBPG.

That’s it! You have successfully validated your cluster against the EBPG and successfully updated configuration to follow best practices for Amazon EBS encryption. After you run the report, you can take the results and determine which configuration to update.
Using HardenEKS to Continually Validate a Clusters Configuration and Detect Drift

Before and after major changes to a cluster are made, HardenEKS takes a baseline of a cluster’s configuration status. Once changes are made, a new baseline can be taken and the process continues. This process can also be done on a regular schedule to ensure that no major changes have occurred to a cluster and best practices are being followed in an automated fashion. Examining baselines and looking for differences between them is something that can be used to detect drift between different configurations, which is an important part of maintaining Amazon EKS clusters and ensures no unintended changes have occurred. HardenEKS helps Amazon EKS operators ensure their clusters continually meet the standards of a well-architected Kubernetes cluster by offering a JSON output.

HardenEKS offers the ability to export to JSON. By doing this, it’s possible to tie other tools into HardenEKS’s output and perform automated validation. Here is an example of how to export data as JSON and inspect the results of reports for to validate changes.

python3 -m venv /tmp/.venv
source /tmp/.venv/bin/activate
pip install hardeneks

# write StorageClass.yaml with encryption parameter false
cat > StorageClass.yaml <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-sc
provisioner: ebs.csi.aws.com
parameters:
  csi.storage.k8s.io/fstype: xfs
  type: io1
  iopsPerGB: "50"
  encrypted: "false"
EOF

kubectl apply -f StorageClass.yaml
hardeneks --export-json report.json
kubectl delete -f StorageClass.yaml

# write StorageClass.yaml with encryption parameter true
cat > StorageClass.yaml <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-sc
provisioner: ebs.csi.aws.com
parameters:
  csi.storage.k8s.io/fstype: xfs
  type: io1
  iopsPerGB: "50"
  encrypted: "true"
EOF

kubectl apply -f StorageClass.yaml
hardeneks --export-json report2.json

# Shows the difference in the reports before and after the StorageClass change was made
cat report.json | jq --raw-output  '.cluster_wide.security.encryption_secrets."EBS Storage Classes should have encryption parameter.".status'
false
cat report2.json | jq --raw-output  '.cluster_wide.security.encryption_secrets."EBS Storage Classes should have encryption parameter.".status'
true

This could be extended to utilize any number of JSON difference tools, which would pinpoint where drift occurred and based on that drift, alerts could fire to notify operations.
Advanced configuration

Configurable rules

Through a config file in yaml format, users customize default behavior of HardenEKS. The config file is used for ignoring given namespaces and selecting which rules to be run.

We are working towards full coverage of the EBPG. Our goal is to incorporate as many rules into HardenEKS as possible.
Contributions

If you have a desire to contribute to HardenEKS, then please look at the contribution guidelines. Collaborators and contributors who help build and guide future versions of HardenEKS are welcomed.

Roadmap

HardenEKS has a public roadmap that shows planned features for future versions. Users influence the roadmap by creating GitHub issues.
Prerequisites

    Python 3.7 or later (note that you can use pyenv to easily switch between different versions of Python)
    AWS Account
    Amazon EKS Cluster
    AWS Credentials and ClusterRole that has necessary permissions defined in the readme
    ~/.kube/config (Currently we only support default ~/.kube/config as file location)

Cleaning up

There is no cleanup needed. HardenEKS doesn’t create any infrastructure and requires no cleanup after it is done running.
Conclusion

In this post, we showed you how Amazon EKS operators can programmatically validate their Amazon EKS clusters against the EBPG. It’s a treat to create new ways of helping customers with their Day 2 Operations with Amazon EKS. If you’re interested, then please download the tool and test it out on your Amazon EKS clusters and provide feedback through Github issues.

For a great introduction on how to run HardenEKS periodically using Amazon EventBridge, see this blog post.

For more information and contributions: https://github.com/aws-samples/hardeneks
TAGS: Amazon EKS, EKS Clusters, Kubernetes security 
