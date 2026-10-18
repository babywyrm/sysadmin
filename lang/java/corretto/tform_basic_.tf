provider "aws" {
  region = "us-west-2"
}

resource "aws_ecr_repository" "my_microservice" {
  name = "my-microservice"
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "16.0.0"

  cluster_name = "my-eks-cluster"
  subnets      = ["subnet-12345678", "subnet-23456789"]
  vpc_id       = "vpc-0123456789abcdef"

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

resource "kubernetes_deployment" "my_microservice" {
  metadata {
    name = "my-microservice"
  }

  spec {
    replicas = 2

    selector {
      match_labels = {
        app = "my-microservice"
      }
    }

    template {
      metadata {
        labels = {
          app = "my-microservice"
        }
      }

      spec {
        container {
          image = "${aws_account_id}.dkr.ecr.us-west-2.amazonaws.com/my-microservice:latest"
          name  = "my-microservice"

          ports {
            container_port = 8080
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "my_microservice" {
  metadata {
    name = "my-microservice"
  }

  spec {
    selector = {
      app = "my-microservice"
    }

    port {
      port        = 80
      target_port = 8080
    }

    type = "LoadBalancer"
  }
}
