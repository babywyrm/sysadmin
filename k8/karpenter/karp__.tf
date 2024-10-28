# Install Karpenter in a specific namespace with required resources and configurations
resource "helm_release" "karpenter" {
  namespace        = "karpenter"
  create_namespace = true
  name             = "karpenter"
  repository       = "oci://public.ecr.aws/karpenter"
  chart            = "karpenter"
  version          = "v0.27.3"

  # Set Karpenter controller resources
  values = [
    <<-EOF
    controller:
      resources:
        requests:
          cpu: 500m
          memory: 512Mi
        limits:
          cpu: 800m
          memory: 1Gi
    EOF
  ]

  # Associate the required IAM Role to the Karpenter service account
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = var.karpenter_irsa_iam_role_arn
  }

  # Cluster-specific settings for Karpenter
  set {
    name  = "settings.aws.clusterName"
    value = var.eks_cluster_name
  }

  set {
    name  = "settings.aws.clusterEndpoint"
    value = data.aws_eks_cluster.cluster.endpoint
  }

  # Specify default IAM instance profile for nodes
  set {
    name  = "settings.aws.defaultInstanceProfile"
    value = var.karpenter_instance_role_name
  }

  # Set log level for debugging
  set {
    name  = "logLevel"
    value = "debug"
    type  = "string"
  }
}

# Define the Provisioner for Karpenter with spot instance specifications and scaling limits
resource "helm_release" "karpenter_provisioner" {
  depends_on = [helm_release.karpenter]
  name       = "karpenter-provisioner"
  repository = "https://nishantn3.github.io/helm-charts"
  chart      = "raw"
  version    = "0.2.5"

  values = [
    <<-EOF
    resources:
      - apiVersion: karpenter.sh/v1alpha5
        kind: Provisioner
        metadata:
          name: default
        spec:
          requirements:
            # Use spot instances
            - key: karpenter.sh/capacity-type
              operator: In
              values: ["spot"]
            # Specify instance families for cost optimization
            - key: karpenter.k8s.aws/instance-family
              operator: In
              values: ${var.karpenter_instance_types}
          # Define resource limits for scaling nodes
          limits:
            resources:
              cpu: 100
          providerRef:
            name: default
          labels:
            node-type: spot
          # TTL (time-to-live) for empty nodes and nodes reaching expiration
          ttlSecondsAfterEmpty: 100
          ttlSecondsUntilExpired: 86400
    EOF
  ]
}

# Configure AWSNodeTemplate to link nodes to specified subnets, security groups, and tags
resource "helm_release" "karpenter_nodetemplate" {
  depends_on = [helm_release.karpenter]
  name       = "karpenter-nodetemplate"
  repository = "https://nishantn3.github.io/helm-charts"
  chart      = "raw"
  version    = "0.2.5"

  values = [
    <<-EOF
    resources:
      - apiVersion: karpenter.k8s.aws/v1alpha1
        kind: AWSNodeTemplate
        metadata:
          name: default
        spec:
          # Subnet selector for Karpenter nodes
          subnetSelector:
            "karpenter.sh/discovery/${var.eks_cluster_name}": "*"
          # Security group selector for Karpenter nodes
          securityGroupSelector:
            karpenter.sh/discovery/${var.eks_cluster_name}: ${var.eks_cluster_name}
          # Tags to organize and manage nodes
          tags:
            karpenter.sh/discovery/${var.eks_cluster_name}: ${var.eks_cluster_name}
    EOF
  ]
}

##
##

helm_release.karpenter:

Installs Karpenter with specific CPU and memory requests/limits.
Associates an IAM role (var.karpenter_irsa_iam_role_arn) for permissions on AWS resources.
Sets up the Karpenter controller to connect to the EKS cluster by specifying the cluster name, endpoint, and an IAM instance profile for node roles.
The logLevel is set to debug for easier troubleshooting.
helm_release.karpenter_provisioner:

Defines the Provisioner to manage and scale spot instances based on demand.
Limits CPU resources to 100 cores and uses instance types specified by var.karpenter_instance_types.
Applies ttlSecondsAfterEmpty and ttlSecondsUntilExpired to terminate empty or expired nodes, enhancing cost efficiency.
helm_release.karpenter_nodetemplate:

Specifies AWSNodeTemplate to link nodes with selected subnets and security groups, configured with subnetSelector and securityGroupSelector using the karpenter.sh/discovery label.
Applies cluster-specific tags to manage Karpenter resources and organize them within AWS.

##
##

