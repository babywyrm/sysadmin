resource "helm_release" "karpenter" {
  namespace        = "karpenter"
  create_namespace = true

  name       = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  chart      = "karpenter"
  version    = "v0.27.3"

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

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = var.karpenter_irsa_iam_role_arn
  }

  set {
    name  = "settings.aws.clusterName"
    value = var.eks_cluster_name
  }

  set {
    name  = "settings.aws.clusterEndpoint"
    value = data.aws_eks_cluster.cluster.endpoint
  }

  set {
    name  = "settings.aws.defaultInstanceProfile"
    value = var.karpenter_instance_role_name
  }

  set {
    name  = "logLevel"
    value = "debug"
    type  = "string"
  }
}

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
            - key: karpenter.sh/capacity-type
              operator: In
              values: ["spot"]
            - key: karpenter.k8s.aws/instance-family
              operator: In
              values: ${var.karpenter_instance_types}
          limits:
            resources:
              cpu: 100
          providerRef:
            name: default
          labels:
            node-type: spot
          ttlSecondsAfterEmpty: 100
          ttlSecondsUntilExpired: 86400
    EOF
  ]
}

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
          subnetSelector:
            "karpenter.sh/discovery/${var.eks_cluster_name}": "*"
          securityGroupSelector:
            karpenter.sh/discovery/${var.eks_cluster_name}: ${var.eks_cluster_name}
          tags:
            karpenter.sh/discovery/${var.eks_cluster_name}: ${var.eks_cluster_name}
    EOF
  ]
}
