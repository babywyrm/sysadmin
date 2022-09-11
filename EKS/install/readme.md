# EKS clustercreation using eksctl:

# Step1: Take EC2 Instance with t2.xlarge instance type
# Step2: Create IAM Role with Admin policy for eks-cluster and attach to ec2-instance
# Step3: Install kubectl
	curl -o kubectl https://amazon-eks.s3-us-west-2.amazonaws.com/1.14.6/2019-08-22/bin/linux/amd64/kubectl
	chmod +x ./kubectl
	mkdir -p $HOME/bin
	cp ./kubectl $HOME/bin/kubectl
	export PATH=$HOME/bin:$PATH
	echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc
	source $HOME/.bashrc
	kubectl version --short --client
	
	
	curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.19.6/2021-01-05/bin/linux/amd64/kubectl
	chmod +x ./kubectl
	mkdir -p $HOME/bin
	cp ./kubectl $HOME/bin/kubectl
	export PATH=$HOME/bin:$PATH
	echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc
	source $HOME/.bashrc
	kubectl version --short --client
	
	curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.20.4/2021-04-12/bin/linux/amd64/kubectl
	chmod +x ./kubectl
	mkdir -p $HOME/bin
	cp ./kubectl $HOME/bin/kubectl
	export PATH=$HOME/bin:$PATH
	echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc
	source $HOME/.bashrc
	kubectl version --short --client
	
	curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.22.6/2022-03-09/bin/linux/amd64/kubectl
	chmod +x ./kubectl
	mkdir -p $HOME/bin
	cp ./kubectl $HOME/bin/kubectl
	export PATH=$HOME/bin:$PATH
	echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc
	source $HOME/.bashrc
	kubectl version --short --client

# Step4: Install eksctl:
    curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
    sudo mv /tmp/eksctl /usr/bin
    eksctl version

# Step5: Cluster creation:
    eksctl create cluster --name=eksdemo \
                      --region=us-east-1 \
                      --zones=us-east-1a,us-east-1b \
                      --without-nodegroup 
					  
# Step6: Add Iam-Oidc-Providers:
    eksctl utils associate-iam-oidc-provider \
        --region us-east-1 \
        --cluster eksdemo \
        --approve
					  
# Step7: Create node-group:
    eksctl create nodegroup --cluster=eksdemo \
                       --region=us-east-1 \
                       --name=eksdemo-ng-public \
                       --node-type=t2.medium \
                       --nodes=2 \
                       --nodes-min=2 \
                       --nodes-max=4 \
                       --node-volume-size=10 \
                       --ssh-access \
                       --ssh-public-key=devops-7am-aws \
                       --managed \
                       --asg-access \
                       --external-dns-access \
                       --full-ecr-access \
                       --appmesh-access \
                       --alb-ingress-access	
					   
# CleanUP
Delete node-group:
			   
    eksctl delete nodegroup --cluster=eksdemo \
                       --region=us-east-1 \
		          			   --name=eksdemo-ng-public
Delete Cluster:
				   
    eksctl delete cluster --name=eksdemo \
                      --region=us-east-1	
		      
		      
# EKS-Fargate-Setup

## EKS Fargate Cluster Setup
```bash
eksctl create cluster --name eksdemo --region us-east-1 --fargate
```

## OIDC Provider Creation
```bash
eksctl utils associate-iam-oidc-provider --region=us-east-1 --cluster=eksdemo --approve
```

## Create Role to Access ECR from EKS Fargate Cluster
```bash
eksctl create iamserviceaccount \
    --attach-policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser \
    --cluster eksdemo \
    --name ecr-role \
    --namespace default \
    --override-existing-serviceaccounts \
    --region us-east-1 \
    --approve	
```

## Build and Push Image to ECR
```bash
docker pull nginx
# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 451060642371.dkr.ecr.us-east-1.amazonaws.com
docker tag nginx:latest 451060642371.dkr.ecr.us-east-1.amazonaws.com/nginx:latest
docker push 451060642371.dkr.ecr.us-east-1.amazonaws.com/nginx:latest
```
## Deploy application with below
```bash
cat << EOF > nginx-deployment.yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: 451060642371.dkr.ecr.us-east-1.amazonaws.com/nginx:latest
        ports:
        - containerPort: 80
EOF       
		
kubectl apply -f nginx-deployment.yaml
```
