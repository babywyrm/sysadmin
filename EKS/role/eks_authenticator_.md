From https://aws.amazon.com/blogs/opensource/integrating-ldap-ad-users-kubernetes-rbac-aws-iam-authenticator-project/

**3\. Configure Role Permissions via Kubernetes RBAC**
------------------------------------------------------

At this point, we have set up Microsoft AD to control authentication to the AWS SSO user portal. We have also set up partial authorization by specifying which AD group has been assigned access to Account B (where the EKS cluster resides). However, access control (i.e., the level of permissions granted to the AD users) has not yet been specified. In this section, we will demonstrate how Kubernetes RBAC can be configured to define access control for AD users/groups via federation through an AWS IAM role.

Before proceeding with the steps below, be sure that that:

1.  You have a working Kubernetes cluster with worker nodes.
2.  You have already configured kubeconfig to manage the cluster via the cluster admin (creator).

Note: If you are using Amazon EKS, please see [Getting Started with Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html) for detailed steps to configure your Amazon EKS cluster.

**Create a Demo Namespace**

First, let’s create a demo namespace called demo-service. We will use this namespace to illustrate full and read-only access control via Kubernetes RBAC for the AWS-EKS-Admins and AWS-EKS-Dev AD groups.

```
$ kubectl create namespace demo-service
```

Next, let’s create the associated Kubernetes Roles, one each, for the AWS-EKS-Dev and AWS-EKS-Admins groups.

**Create ClusterRoles**

```
$ cat role.yaml
```

YAML

    # role.yaml
     ---
     apiVersion: rbac.authorization.k8s.io/v1
     kind: Role
     metadata:
       name: demo-service:ad-cluster-admins
       namespace: demo-service
     rules:
     - apiGroups: ["*"]
       resources: ["*"]
       verbs: ["*"]
     ---
     apiVersion: rbac.authorization.k8s.io/v1
     kind: Role
     metadata:
       name: demo-service:ad-cluster-devs
       namespace: demo-service
     rules:
     - apiGroups: [""]
       resources: ["services", "endpoints", "pods", "deployments", "ingress"]
       verbs: ["get", "list", "watch"]

Next, we will apply these Roles to our cluster to enable them.

```
$ kubectl apply -f role.yaml
```

**Modify Authenticator Config Map**

Now, let’s modify our authenticator config to allow EKS access to these groups. You will need to get the role arns for the roles that IAM assumes for the two respective AD groups, AWS-EKS-Dev and AWS-EKS-Admins. You can do that using the following command:

```
$ aws iam list-roles | grep Arn | grep AD-EKS-
```

Next, you will need to edit the aws-auth ConfigMap:

```
$ kubectl edit configmap aws-auth --namespace kube-system
```

This command will open the file in your editor. We can then add the following to the mapRoles section. Make sure to:

1.  For the rolearn be sure to remove the /aws-reserved/sso.amazonaws.com/ from the rolearn url, otherwise the arn will not be able to authorize as a valid user.
2.  Make sure that the groups match the —group parameter you specify in the role bindings below.

YAML

    # ... mapRoles config
     - rolearn: arn:aws:iam::141548511100:role/AWSReservedSSO_AWS-EKS-Admins_b7e6a177cfc720e6
       username: adminuser:{{SessionName}}
       groups:
       - demo-service:ad-cluster-admins
     - rolearn: arn:aws:iam::141548511100:role/AWSReservedSSO_AWS-EKS-Dev-AssumedRole_7f87046f4b89cf97
       username: devuser:{{SessionName}}
       groups:
     - demo-service:ad-cluster-devs

Once you have added that, save and close this file.

**Create Role Bindings**

Finally, we can bind these roles to the relative groups in Kubernetes who should have access to the demo-service namespace. The AWS-EKS-Admin role will have full access and the AWS-EKS-Dev role will have read-only access to the demo-service namespace. In the commands below, we create rolebindings operations-team-binding, and development-team-binding, which assigns the Role `demo-service:ad-cluster-admin` and the Role `demo-service:ad-cluster-devs` to the Kubernetes groups `demo-service:ad-cluster-admins` and `demo-service:ad-cluster-devs` in the `demo-service` namespace.

Role binding for demo-service:ad-cluster-admins:

```
$ kubectl create rolebinding operations-team-binding --role demo-service:ad-cluster-admins --group demo-service:ad-cluster-admins --namespace demo-service
```

Role binding for demo-service:ad-cluster-devs:

```
$ kubectl create rolebinding development-team-binding --role demo-service:ad-cluster-devs --group demo-service:ad-cluster-devs --namespace demo-service
```

**Modifying kubeconfigs**

Now we can create new KUBECONFIG files for each set of role bindings, one for dev users and one for admin users. Copy your kubeconfig file and then modify the user section for your eks cluster to look like this.

~/.kube/config-test-eks-cluster-1-dev

```
- name: test-eks-cluster
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: heptio-authenticator-aws
      args:
      - "token"
      - "-i"
      - "test-eks-cluster"
      - "-r"
      - "&lt;RoleArn of AWS-EKS-Dev AssumedRole&gt;"
```      

~/.kube/config-test-eks-cluster-1-admins

```
- name: test-eks-cluster
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: heptio-authenticator-aws
      args:
      - "token"
      - "-i"
      - "test-eks-cluster"
      - "-r"
      - "&lt;RoleArn of AWS-EKS-Admins AssumedRole&gt;"
```

**Note:** For the -r parameter above, specify the full rolearn in this case, including the path in the rolearn.

Example:

arn:aws:iam::1234567890:role/**aws-reserved/sso.amazonaws.com/**AWSReservedSSO_AWS-EKS-Admins
