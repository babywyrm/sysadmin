##
#
https://sweetcode.io/how-to-deploy-an-application-to-kubernetes-cluster-using-jenkins-ci-cd-pipeline/
#
##

How to Deploy an Application to Kubernetes Cluster using Jenkins CI/CD Pipeline
BY BRAVIN WASIKE4 WEEKS AGO
IN APPLICATION DEVELOPMENT
devops · kubernetes · microservices
This tutorial will teach you how to deploy a simple containerized application to the Kubernetes cluster using Jenkins CI/CD Pipeline. Jenkins is one of the most popular continuous integration/continuous delivery and deployment (CI/CD) automation platforms. It is written in Java and is server based. Jenkins has helped DevOps engineers and developers automate most of the development workflows. 

In an organization, Jenkins automates the building, staging, testing, and deploying of software while implementing continuous integration and continuous delivery. It ensures the software is always up to date and the end user enjoys the new releases. You will use Jenkins CI/CD Pipeline with multiple stages to deploy the simple containerized application.

How Jenkins Works
Jenkins implements the development workflows using CI/CD pipelines. A Jenkins pipeline has multiple stages and steps for implementing the CI/CD workflow. In Jenkins, you use a Jenkinsfile to define and declare all the stages for your Jenkins CI/CD Pipeline. ‘Jenkinsfile’ is popularly known as “pipeline as code” since you write your CI/CD pipeline as executable code. Jenkins will execute the ‘Jenkinsfile’ and implement the pipeline. The pipeline will automate the stages defined in the Jenkinsfile. You can read this Sweet Code Post on Jenkins Pipeline.

In this tutorial, our ‘Jenkinsfile’ will have multiple stages. The stages will be for:

Building a Docker image
Pushing the Docker image to Docker Hub.
Pulling the Docker image from the Docker Hub repository and creating a containerized application.
Deploy the containerized application to the Kubernetes cluster. 
Jenkins also uses plugins that enable developers to integrate different third-party software with Jenkins. Plugins help in implementing continuous integration/delivery and deployment. In this tutorial, you will install the Docker and Kubernetes plugins in the Jenkins platform.

When you are using Jenkins, you have to connect it to your Source Code Management (SCM) Git repository. The repository will host your ‘Jenkinsfile’ and other application files. Jenkins will use the files in the GitHub repository to deploy the applications to the Kubernetes cluster.

Prerequisites
Before you start working on this project, you need to have the following:

Docker Desktop: You will use Docker to build and run Jenkins as a Docker Container. You can read this Sweetcode post on how to install and use Docker.
GitHub account: You will use GitHub as your Source Code Management (SCM) Git repository. You will push your Jenkinsfile, application, and deployment files to your GitHub repository. 
Kubernetes Cluster: Various cloud-based Kubernetes clusters can host your deployed containerized application such as:
Amazon EKS cloud cluster.
DigitalOcean Kubernetes
IBM Cloud Kubernetes service
Microsoft Azure Kubernetes Service
OpenShift Kubernetes
 Linode Kubernetes Engine
 Google Kubernetes Engine
Civo Kubernetes
Kubectl
Docker Hub account
In this tutorial, you will use the Minikube. It is the most popular local Kubernetes cluster. We will use Minikube since it’s free to use and easy to set up on your computer. If you want to understand more about Minikube, read this article on Sweetcode.

It is the command line tool interface for Kubernetes. It allows DevOps practitioners to run commands and deploy Kubernetes objects to the Kubernetes cluster.  You can read this Sweet Code post on how to get started with Kubectl.

The Jenkins CI/CD Pipeline will build the Docker image and push it to your Docker Hub repository. It will also pull the Docker image from the Docker Hub registry and create a containerized application.

How to Deploy to Kubernetes Cluster using CI/CD Jenkins Pipeline
Step 1: Run Jenkins as a Docker Container
To install Jenkins, you will run it as a Docker container using the following Docker run command:

docker run --name myjenkins-container -p 8080:8080 -p 50000:50000 -v /var/jenkins_home jenkins
When you execute the command above:

It will run the ‘jenkins’ official Docker image.
It will start the Jenkins container. It will then expose it on port 8080 and the nodes on port 50000. You will access the Jenkins container on port 8080.  
Open your web browser and type localhost:8080 to access the Jenkins application:



From the image above, the Jenkins container is locked. You will require the administrator password to unlock Jenkins.

Getting the Administrator Password
To get the initial administrator password for unlocking Jenkins, run the following command:

docker logs myjenkins-container
After executing the command, the following initial administrator password will be displayed on your terminal:



Next, copy the initial administrator password and paste it into the password field. After unlocking Jenkins using the initial administrator password, you will be redirected to another page as shown below:



Next, select ‘Install suggested plugins’ to allow the installation of the necessary plugins. These are the basic plugins that Jenkins requires to run. The plugins to be installed are shown in the image below:



Create First Admin User
After installing all the basic plugins shown above, you will be redirected to another page for you to create your first admin user:



You will fill in all the fields and the click ‘Save and Continue’ button. You will then be redirected to another page as shown below:



Next, click the ‘Save and Finish’ and your Jenkins platform will be running and ready to use. You will be redirected to another page as shown below:



Finally, click the ‘Start using Jenkins’. It will open the “Welcome to Jenkins” Dashboard:



You will interact with the Jenkins Dashboard when managing Jenkins, creating CI/CD pipelines, and making configurations. You have completed the first step.

Step 2: Install Docker Pipeline Plugin
To install Docker Pipeline Plugin, click ‘Manage Jenkins’:



Next, click ‘Manage Plugins’:



Next, search for Docker Pipeline. Then click the ‘Download now and install after restart button’:



The Docker pipeline will enable you to add Docker commands in your Jenkins CI/CD pipeline scripts. Without this plugin, Jenkins will not recognize and understand Docker commands.

Step 3: Install Kubernetes Plugin
To install the Kubernetes Plugin, you will search for Kubernetes Pipeline. Then, click the `Download now and install after restart button: 



The Docker pipeline will enable you to integrate Kubernetes with Jenkins. With the Kubernetes plugin, you can deploy the containerized application to the Kubernetes cluster using CI/CD Jenkins Pipeline.

Step 4: Add Credentials to Jenkins Credentials Manager
You will add the GitHub and Docker Hub credentials to the Jenkins Credentials manager. Jenkins will use Git Hub credentials to authenticate to GitHub and Docker Hub credentials to authenticate to Docker Hub.

Adding the Docker Hub Credentials
To add the Docker Hub credentials:

Go back to the Jenkins Dashboard and click “Manage Jenkins”
Click ‘Manage Credentials’
Click ‘Add Credentials’
Add Docker Hub username and password
After adding all the information, click the ‘Create’ button.

Adding the Git Hub Credentials
You will add your GitHub username and password as shown below:



After adding all the information, click the ‘Create’ button. You will have created the two credentials that Jenkins will use for authentication (logging into Git Hub and Docker Hub.)  

Step 5: Start Minikube
To start Minikube, open your terminal as admin and run the following command:

minikube start
It will take a while to start Minikube. After a few minutes, Minikube will start running on your local machine and it is ready for use as shown below:



Both our Jenkins and Kubernetes environments are ready. The next step is to create new a GitHub repository.

Step 6: Create a new GitHub Repository
You will be required to login into your personal GitHub account. Then, you will need to add a new GitHub repository as shown in the image below:



You will push your Jenkinsfile, application files, and deployment files to the new GitHub repository. Let’s start working on the application.

Step 7: Create a Simple React.js Application
In your computer, create a new folder named ‘jenkins-deploy’. In the ‘jenkins-deploy’ folder, run the following command to create a simple React.js application:

npx create-react-app jenkins-kubernetes-deployment
The command will create a simple React.js application. It will also generate a new folder named ‘jenkins-kubernetes-deployment’ inside the ‘jenkins-deploy’ root folder.

Step 8: Create a Dockerfile
The Dockerfile will contain commands that the Jenkins CI/CD pipeline will use to build the Docker image for the simple React.js application. In the ‘jenkins-kubernetes-deployment’ folder, create a Dockerfile and paste the following Docker snippet:

#It will use node:19-alpine3.16 as the parent image for building the Docker image
FROM node:19-alpine3.16
#It will create a working directory for Docker. The Docker image will be created in this working directory.
WORKDIR /react-app
#Copy the React.js application dependencies from the package.json to the react-app working directory.
COPY package.json .
COPY package-lock.json .
#install all the React.js application dependencies
RUN npm i
<!-- Copy the remaining React.js application folders and files from the `jenkins-kubernetes-deployment` local folder to the Docker react-app working directory -->
COPY . .
#Expose the React.js application container on port 3000
EXPOSE 3000
#The command to start the React.js application container
CMD ["npm", "start"]
Step 9: Create a Kubernetes Deployment YAML file
A Kubernetes Deployment YAML file creates the pods for the React.js application container in the Kubernetes cluster. The pods will host the application container, and each pod will have the necessary Kubernetes resources. In the ‘jenkins-kubernetes-deployment’ folder, create a ‘deployment.yaml’ file and paste the following YAML snippet:

apiVersion: apps/v1
kind: Deployment
metadata:
  name: deployment #The name of the Kubernetes Deployment to be created in the Kubernetes cluster
  labels:
    app: react-app
spec:
  replicas: 2 #The number of pods to be created in the Kubernetes cluster for the React.js application container
  selector:
    matchLabels:
      app: react-app
  template:
    metadata:
      labels:
        app: react-app 
    spec:
      containers:
      - name: react-app #The name of the react.js application container
        image: bravinwasike/react-app:latest #The Docker image for building the React.js application container
        ports:
        - containerPort: 3000 #The port for the React.js application   container
The ‘deployment.yaml’ file above will create two pods in the Kubernertes application. It will pull ‘bravinwasike/react-app:latest’ Docker image from the Docker Hub repository and create a containerized application.

Step 10: Create a Kubernetes Service Deployment YAML file
A Kubernetes Service Deployment YAML file will create a Kubernetes Service in the Kubernetes cluster. The Kubernetes Service will expose the pods for the React.js application container outside the Kubernetes cluster. You will use the Kubernetes Service to access the React.js application container from outside the Kubernetes cluster. 

In the ‘jenkins-kubernetes-deployment’ folder, create a ‘service.yaml’ file and paste the following YAML snippet:

apiVersion: v1
kind: Service
metadata:
  name: service #The name of the Kubernetes Service to be created in the Kubernetes cluster
spec:
  selector:
    app: react-app 
  type: LoadBalancer #Type of the Kubernetes Service
  ports:
  - protocol: TCP
    port: 3000 #Service port
    targetPort: 3000 #The port for the React.js application container
Step 11: Create a Jenkinsfile
The ‘Jenkinsfile’ will have multiple stages for defining our CI/CD Jenkins Pipeline. In the ‘jenkins-kubernetes-deployment’ folder, create a ‘Jenkinsfile’ and paste the following Jenkins pipeline snippet:

pipeline {
  environment {
    dockerimagename = "bravinwasike/react-app"
    dockerImage = ""
  }
  agent any
  stages {
    stage('Checkout Source') {
      steps {
        git 'https://github.com/Bravinsimiyu/jenkins-kubernetes-deployment.git'
      }
    }
    stage('Build image') {
      steps{
        script {
          dockerImage = docker.build dockerimagename
        }
      }
    }
    stage('Pushing Image') {
      environment {
               registryCredential = 'dockerhub-credentials'
           }
      steps{
        script {
          docker.withRegistry( 'https://registry.hub.docker.com', registryCredential ) {
            dockerImage.push("latest")
          }
        }
      }
    }
    stage('Deploying React.js container to Kubernetes') {
      steps {
        script {
          kubernetesDeploy(configs: "deployment.yaml", "service.yaml")
        }
      }
    }
  }
}
The Jenkinsfile will create a Jenkins Pipeline with four stages:

Checkout Source
Build image
Pushing Image
Deploying React.js container to Kubernetes
Checkout Source Stage
This Jenkins Pipeline stage will use ‘https://github.com/Bravinsimiyu/jenkins-kubernetes-deployment.git’ as the GitHub repository. It will pull and scan all the files in this GitHub repository.

Build Image Stage
This Jenkins Pipeline stage will use the created Dockerfile to build a Docker image named ‘bravinwasike/react-app’.

Pushing Image Stage
This Jenkins Pipeline stage will push the ‘bravinwasike/react-app’ Docker image to Docker Hub using the ‘dockerhub-credentials’

Deploying React.js container to Kubernetes Stage
It will pull ‘bravinwasike/react-app:latest’ Docker image from the Docker Hub repository and create a containerized application. It will then deploy the React.js container to Kubernetes.

Step 12: Push the Files to your GitHub Repository
The push all the application files to your GitHub repository, run the following Git commands shown below:



After running the Git commands, you will push all the React.js application files, the ‘Dockerfile’, the ‘Jenkinsfile’, the ‘deployment.yaml’ file, and the ‘service.yaml’ file to your GitHub Repository:



All our files are ready, Let’s create a multi-branch pipeline in the Jenkins platform.

Step 13: Create a Multi-branch Pipeline
Open the Jenkins Dashboard and Click ‘New Item’.
Enter an item name
To Create a Multi-branch Pipeline, follow the steps below:

Open the Jenkins Dashboard and Click ‘New Item’.

Enter an item name.

Scroll down and Select the ‘Multibranch Pipeline’ then click ‘OK’.

Step 14: Configure the Multi-branch Pipeline
To configure the Multi-branch Pipeline:

Click ‘Branch Sources’.
Select ‘GitHub’ from the dropdown menu
Add the GitHub credentials ID and the GitHub repository URL
Scan the GitHub Repository
You will click ‘Scan Repository Now’ to scan the GitHub Repository you have added:



It will scan all the files in this GitHub repository and find the ‘Jenkisfile’. Jenkins will use this file to build the Multi-branch pipeline:



Step 15. Build the Muliti-branch Pipeline
To build the Multi-branch Pipeline, click “Build Now”:



Jenkins will use the Jenkinsfile to build the Multi-branch pipeline stages as shown below:



Muliti-branch Pipeline Output
To get the Muliti-branch Pipeline output, click “Console Ouput”:



It will implement all the stages defined in the Jenkinsfile and produce the following outputs:





The Jenkins CI/CD pipeline outputs a ‘SUCCESS’ message. The Jenkins CI/CD pipeline was able to: 

Build the Docker image.
Push the Docker image to Docker Hub.
Pull the Docker image from the Docker Hub repository and create a containerized application.
Deploy the containerized application to the Kubernetes cluster. 
Step 16: Accessing the Deployed Containerized Application
You will use the Kubernetes Service to access the React.js application container from outside the Kubernetes cluster. To get the Kubernetes Service, run this command:

kubectl get service
The command will output the following Kubernetes Service in your terminal:



You will then run the following command to get the URL:

minikube service react-app-service
The command will output the following URL:



Copy the URL and paste it into your browser to access the deployed containerized application (React.js application):



You can now access the React.js application that you have deployed using the CI/CD pipeline.

Conclusion
In this tutorial, you have learned how to deploy an application to a Kubernetes cluster using Jenkins CI/CD Pipeline. This tutorial covers how Jenkins works and how to run Jenkins as a Docker Container. After running the Jenkins container you added credentials to Jenkins Credentials Manager. You then created the React.js application files, the ‘Dockerfile’, the ‘Jenkinsfile’, the ‘deployment.yaml’ file, and the ‘service.yaml’ file.

In the next steps, you pushed the files to the GitHub repository and configured a multi-branch Pipeline. After building the Jenkins CI/CD pipeline using the Jenkisfile, you accessed the deployed containerized application. You used the Kubernetes Service to access the React.js application. The Jenkins CI/CD pipeline deployed the containerized application to the Kubernetes cluster. Jenkins is the best way of accelerating the development workflows. It can be adopted in any organization.


