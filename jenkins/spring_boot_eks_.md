
##
#
https://awstip.com/deploying-a-spring-boot-application-on-aws-eks-using-jenkins-cicd-a-step-by-step-guide-8e684f488ffc
#
##

Deploying a Spring-boot Application on AWS EKS using Jenkins CICD: A Step-by-Step Guide

Elastic Kubernetes Service by AWS
Amazon Elastic Kubernetes Service (EKS) is a managed Kubernetes service offered by Amazon Web Services (AWS) that makes it easy to deploy, manage, and scale containerized applications using Kubernetes.

Jenkins is a popular open-source automation server that can be used to automate various tasks related to building, testing, and deploying software. Jenkins pipelines provide a way to define and automate the steps involved in the continuous integration and delivery (CI/CD) of applications.

In this guide, I’ll show you how to deploy a spring-boot application on Amazon EKS using Jenkins pipelines. This process will involve creating a Jenkins pipeline that builds and pushes the Docker image of the application to an Elastic Container Registry and then deploys the application to Amazon EKS using Kubernetes manifests.

By following this guide, you will gain a better understanding of how to automate the deployment of applications on Amazon EKS using Jenkins pipelines, which can significantly improve the speed and reliability of your CI/CD processes.

AWS Prerequisites
Example Project
Set up a Cluster and Worker Nodes
Install and configure Jenkins in an EC2 instance
Install Docker
Install required Plugins in Jenkins
Integrate Docker with Jenkins
Configure AWS Credentials
Create a repository in ECR
Add Maven to Jenkins
Pipeline creation
Write Jenkinsfile
Trigger the pipeline
Monitor the pipeline
Interact with a cluster from terminal
Expose the service
Get the external IP
Allow the required ports
Test App Access
Conclusion
AWS Prerequisites

Set up an EC2 instance in an Amazon VPC.
Here’s how to create and configure the VPC, as well as launch the EC2 instance within it. Check out the link below.

Create an EC2 instance in an Amazon VPC

Example Project

https://github.com/SrijaAnaparthy/springboot-app-for-aks.git

Set up a Cluster and Worker Nodes

Take the reference below to install AWS CLI and Kubectl, set up a cluster and worker nodes, and configure kubectl to use a cluster.

Creating and Managing EKS Clusters

Install and configure Jenkins in an EC2 instance

Jenkins must be installed in that EC2 instance, as we are deploying our application from the Jenkins pipeline. Check out the link below to learn how to install and configure Jenkins on EC2.

Jenkins on AWS

Install Docker

Docker is a popular open-source platform for building, shipping, and running containers.

To install Docker on an Amazon Linux instance

Install Docker on Amazon Linux Machine

To install Docker on an Ubuntu instance

Install Docker on an Ubuntu machine

Install required Plugins in Jenkins

Amazon EC2 plugin
Amazon ECR plugin
Docker plugin
Docker Pipeline
CloudBees Docker Build and Publish plugin
Kubernetes CLI Plugin
Pipeline: AWS Steps
Integrate Docker with Jenkins

Integration of Docker and Jenkins is required because it enables continuous delivery and deployment of applications.

With every code change made by a developer, it is desirable for Jenkins to automate the process of creating Docker images and pushing them to the Amazon Elastic Container Registry (ECR) for efficient and streamlined deployment.

Add Jenkins user to the Docker group

sudo usermod -a -G docker jenkins
Restart the Jenkins service

sudo systemctl restart jenkins
Reload system daemon files

sudo systemctl daemon-reload
Restart the Docker service as well

sudo service docker stop
sudo service docker start
Configure AWS Credentials

Open the Jenkins Dashboard and click on the “Credentials” link from the left navigation menu.
Select the “System” option, and then click on the “Global credentials (unrestricted)” domain.
Click on the “Add Credentials” button and select the “AWS Credentials” option.
Enter the AWS Access Key ID and the AWS Secret Access Key for your AWS account. The process of obtaining a new access key has been previously discussed in Creating and Managing EKS clusters
Provide a meaningful description for the credentials and select the “ID” field. This ID will be used later in the pipeline to reference the AWS credentials.
Click the “OK” button to save the AWS credentials.
To use the AWS credentials in a Jenkins pipeline, you need to reference them by ID in the credentialsId field of the withAWS step. For example:
withAWS(credentials: 'aws-credentials', region: 'us-west-2')
Create a repository in ECR

Here’s a step-by-step procedure to create a repository in Amazon Elastic Container Registry (ECR):

Log in to the AWS Management Console and navigate to the Amazon ECR service.
Click on the “Create repository” button.
Enter a name for your repository. This name must be unique within your AWS account.
(Optional) Add a description for your repository.
Click on the “Create repository” button.
You will now see your newly created repository in the repository list.
Select the newly created repo and then choose to view push commands.
Use those commands to authenticate and push an image to your repository while writing Jenkinsfile.
Add Maven to Jenkins

Here are the steps to add Maven tool to Jenkins

Log in to Jenkins.
Go to the “Manage Jenkins” page by clicking the “Manage Jenkins” link on the left sidebar.
Click on “Global Tool Configuration.”
Scroll down to the “Maven” section.
Click the “Add Maven” button.
Give the installation a name, for example, “Maven3.”
Select the “Install automatically” option.
Click the “Save” button.
Jenkins will now download and install Maven3, and it will be available for use in your pipeline. You can reference the installation in your pipeline using the “maven” tool definition, for example:

tools {
    maven 'Maven3'
}
Pipeline creation

Create a Jenkins pipeline: From the Jenkins Dashboard, select “New Item” and create a new pipeline.

Write Jenkinsfile

Once the pipeline has been created, give it a description and proceed to the pipeline section on the left-hand side.

2. Write a Jenkinsfile to define the steps in a pipeline for deploying a spring-boot application to an EKS cluster using Jenkins.

The steps should include checking out the git repository, building a Jar, building a Docker image, pushing the image to ECR, integrating Jenkins with the EKS cluster, and deploying an app to EKS. To do this, select “Pipeline script” under the pipeline section and specify the necessary steps.
```
pipeline {
    tools {
        maven 'Maven3'
    }
    agent any
    stages {
        stage('Checkout') {
            steps {
                checkout([$class: 'GitSCM', branches: [[name: '*/main']], extensions: [], userRemoteConfigs: [[url: '<GIT_REPO_URL>']]])
            }
        }
        stage('Build Jar') {
            steps {
                sh 'mvn clean package'
            }
        }
        stage('Docker Image Build') {
            steps {
                sh 'docker build -t <IMAGE_NAME> .'
            }
        }
        stage('Push Docker Image to ECR') {
            steps {
                withAWS(credentials: '<AWS_CREDENTIALS_ID>', region: '<AWS_REGION>') {
                    sh 'aws ecr get-login-password --region <AWS_REGION> | docker login --username AWS --password-stdin <ECR_REGISTRY_ID>'
                    sh 'docker tag <IMAGE_NAME>:latest <ECR_REGISTRY_ID>/<IMAGE_NAME>:latest'
                    sh 'docker push <ECR_REGISTRY_ID>/<IMAGE_NAME>:latest'
                }
            }
        }
        stage('Integrate Jenkins with EKS Cluster and Deploy App') {
            steps {
                withAWS(credentials: '<AWS_CREDENTIALS_ID>', region: '<AWS_REGION>') {
                  script {
                    sh ('aws eks update-kubeconfig --name <EKS_CLUSTER_NAME> --region <AWS_REGION>')
                    sh "kubectl apply -f <K8S_DEPLOY_FILE>.yaml"
                }
                }
        }
    }
    }
}
```
The above pipeline has five stages:

Checkout: The stage “Checkout” retrieves the code from a Git repository. It specifies the Git repository URL and the branch to checkout (in this case, the main branch). The code will be checked out in the Jenkins workspace and available for the rest of the pipeline to use.
Maven Build: This build stage of the pipeline is responsible for creating a jar file of the spring boot application code. This is done using the Apache Maven build tool. The steps in this stage include:
i) Cleaning any previous build artifacts using the command mvn clean.
ii) Building the jar file using the command mvn package.
This stage compiles the source code into a standalone executable jar file, which will be used in later stages of the pipeline.

Building a JAR file is a one-time process, but it may need to be rebuilt if changes are made to the code or if a new version is being released. Additionally, JAR files can also be repackaged if needed.

3. Docker Image Build: This stage is for building a Docker image using a Dockerfile. The stage runs a shell command using the sh step, which runs the docker build command. The -t option is used to specify the name of the image, and the . at the end of the command specifies that the build context is the current directory. The image name is specified using the placeholder <IMAGE_NAME>.

4. Push Docker Image to ECR: This stage pushes the Docker image that was built in the previous stage to Amazon Elastic Container Registry (ECR), which is a fully-managed Docker container registry service provided by AWS. The stage uses AWS CLI to authenticate and push the image to the specified ECR repository.

5. Integrate Jenkins with EKS and deploy: This stage integrates Jenkins with an AWS EKS (Elastic Kubernetes Service) cluster and deploys an application. By using the withAWS block, Jenkins can securely access AWS resources (such as Amazon Elastic Container Registry or Amazon Elastic Kubernetes Service) on behalf of the user.

The first command updates the kubectl configuration to connect to the specified EKS cluster.
Then, the application is deployed to the cluster using the kubectl apply command and the YAML file for deployment and service.
Trigger the pipeline

Start the pipeline by clicking “Build Now” in the Jenkins Dashboard
