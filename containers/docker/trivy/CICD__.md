
##
#
https://medium.com/@ougabriel/cicd-project-production-level-blog-app-deployment-using-eks-nexus-sonarqube-trivy-with-40eb648a688a
#
##

CICD PROJECT: Production Level Blog APP Deployment using EKS, Nexus, SonarQube, Trivy with Monitoring Tools
GABRIEL OKOM
·
Sep 18, 2024

Tools Used:
Jenkins: For managing the CI/CD pipeline.
SonarQube: For static code analysis.
Nexus: For managing dependencies and artifacts.
Trivy: For scanning vulnerabilities in files and Docker images.
Docker: To containerize applications.
Prometheus: For monitoring metrics from services.
Blackbox Exporter: For probing application availability.
Grafana: For visualizing metrics.
Kubernetes (AWS EKS): For managing containerized workloads.
Terraform: For EKS deployment.

Prerequisites:
- Basic Understanding of CI/CD: Familiarity with Continuous Integration and Continuous Deployment.
- AWS Account: Access to create and manage EC2 instances and EKS.
- Git Knowledge: Experience using Git and GitHub.
- Linux Commands: Basic experience with terminal commands and SSH access.
- Jenkins, Docker, and Kubernetes knowledge: Understanding of basic setup and usage.

Table of Contents:

Step 1: Set up Git Repository and create Security Token
Step 2: Setup required servers (Jenkins, Sonarqube, Nexus, Monitoring tools)
Step 3: Set up Jenkins, Sonarqube and Nexus
Step 4: Install Jenkins Plugins, and Configure Nexus, Trivy, SonarQube and DockerHub to use Jenkins
Step 5: Create a complete CICD pipeline
Step 6: Create the EKS cluster, Install AWS CLI, Kubectl and Terraform
Step 7: Assign a custom domain to the deployed application
Step 8: Monitor the application
Step 1. Set up Git Repository and create Security Token

a.> Create the Repo: We will need to setup a private git repo, it is assumed you already know how to do one. If not click here to read the official GitHub docs. You can decide to make it public or private for production use, it is best to set it to private this way it is more secured and not exposed to the public.

However; by choice I will be leaving my repo public , this way you can get access to it and the source files used for this project. Repo Link

b.> Create a Security Token: After setting up the git repo, we will have to create a security token ; this will help us authenticate easily. Another major importance is that it ensures secured, managed access to your repositories without exposing your actual password.

c.> Install GitBash in your local system and clone the repo:

Again, it is assumed you already know how to install Git Bash, it is quite easy to do this for Windows and Mac. Download the OS and follow the installation prompts. Click Here to get started and install Git. Having Git on your local system is a advisable because it makes it easier to push and commits code.

After installing Git Bash, we need to clone the repo we will be using, this repo contains the source code needed for this project. Click Here to CLONE it.

git clone https://github.com/ougabriel/full-stack-blogging-app.git

I am running the git clone command in VS Studio

When this is done make sure to cd into the project directory

cd FullStack-Blogging-App/

Step 2: Setup required servers (Jenkins, Sonarqube, Nexus, Monitoring tools)

Here, we are going to deploy 2 EC2 instance for Nexus and Sonarqube

To create two t2.mediumUbuntu EC2 instances on AWS, follow these steps:

a.> Log in to AWS Console: Go to the AWS Management Console and sign in to your account.
b.> Navigate to EC2: In the search bar, type “EC2” and select EC2to go to the EC2 dashboard.
c.> Launch Instance: Click on Launch instances.
d. > Configure Instance Details: -Name: Give a name to your instances. -AMI: Choose an Amazon Machine Image (AMI) by selecting Ubuntu Server 20.04 LTS. -Instance type: Select t2.mediumfrom the dropdown.
e.> Key Pair (SSH login): -Select an existing key pair or create a new one to securely connect via SSH.
f.> Network settings: Create or Choose your preferred VPC and subnet. -Ensure that Auto-assign publi IP is enabled for external access. -Configure Security Group: Allow SSH (port 22) access by specifying your IP range of 2000 –11000.
g.> 7. Configure storage: -The storage size should be 20GB
h.> 8. Set the Number of Instances: -In the Number of instances field, enter 2 to create two instances.
i.> Launch Instances: -Review your settings and click Launch.
j.>10. Connect: -Once the instances are running, you can use the SSH keyto connect via terminal:

ssh -i /path/to/your-key.pem ubuntu@<public-ip>

Next; we are going to create a separate EC2 instance with a large storage size of 25GB and Instance type of t2.largefor Jenkins.

Now, repeate the same process and create an EC2 instance of size 25GB and Instance type of t2.large, use the same security group and dont forget to make sure Auto-assign publi IP is enabled for external access.

Best way to connect to the 3 instances is to use MobaXterm, a third party app that can be used to ssh into any system. Find the guide here.
Step 3: Set up Jenkins, Sonarqube and Nexus

3.1 Jenkins set up: To configure Jenkins for use, we need to install some few things.

a.> SSH into the Jenkins instance

ssh -i <path-to-your-keyp.pem ubuntu@<jenkins-vm-public-ip>

b.> Update and install java

sudo apt update
sudo apt install openjdk-17-jre-headless  -y

c.> Install Jenkins: Using scripts make it easier to install packages, and helps to save time spent on running single commands.

#!/bin/bash

# Update system packages
sudo apt-get update -y

# Install Java (Jenkins requires Java to run)
sudo apt-get install -y openjdk-11-jdk

# Import Jenkins GPG key and add Jenkins apt repository
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io.key | sudo tee \
  /usr/share/keyrings/jenkins-keyring.asc > /dev/null

echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
  https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
  /etc/apt/sources.list.d/jenkins.list > /dev/null

# Update package lists to include Jenkins repository
sudo apt-get update -y

# Install Jenkins
sudo apt-get install -y jenkins

# Start Jenkins
sudo systemctl start jenkins

# Enable Jenkins to start at boot
sudo systemctl enable jenkins

# Print the initial Jenkins admin password
echo "Jenkins installed successfully!"
echo "You can access Jenkins at http://<your-server-ip>:8080"
echo "Use the following command to retrieve your initial Jenkins admin password:"
echo "sudo cat /var/lib/jenkins/secrets/initialAdminPassword"

Run the following command to run the script

vi install_jenkins.sh  #paste the script into the editor. Press Ctrl wq! to save and exit

chmod +x install_jenkins.sh
./install_jenkins.sh

After the installation; you can login to Jenkins by using http://<your-jenkins-public-ip>:8080 . You can get the jenkins initial password here sudo cat /var/lib/jenkins/secrets/InitialAdminPassword

login to Jenkins

After running the sudo cat /var/lib/jenkins/secrets/InitialAdminPassword copy and paste the output to login to Jenkins. When you login click on suggested plugins this will help to download all the neccessary plugins plugins required for Jenkins to function. > Next, type in login details (you can use admin for both username and password and type in your email)

When this is done correctly we can now access the Jenkins page.

d.> Install Docker:
```
#!/bin/bash

# Update existing list of packages
sudo apt-get update

# Install prerequisite packages
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add Docker's official GPG key
sudo mkdir -m 0755 -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Set up the Docker stable repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update the package index again
sudo apt-get update

# Install Docker Engine, CLI, and containerd
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start Docker
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify Docker installation
sudo docker --version

# Add current user to the Docker group to avoid using sudo (optional)
sudo usermod -aG docker $USER

echo "Docker installation completed. Please log out and log back in to apply the group changes."
```


To use the script: i> Copy the script to a file (e.g., install_docker.sh). ii.>Make the script executable: chmod +x install_docker.sh iii.>Run the script: ./install_docker.sh

This will install Docker and add your user to the Docker group to avoid using sudo for Docker commands.

Check docker version by running the command docker --version

NOTE: This docker script will be used on all other VMs or Instances in this project. You can copy, paste and run the script to have docker installed on all the instances

3.2. Nexus set up

For Nexus: SSH into the VM > Run the command sudo apt update > Next, copy and paste the docker script used earlier and install the script.

When this is done. We will be running Nexus as a docker container

sudo docker run -d -p 8081:8081 sonatype/nexus3

Confirm that the Nexus container is running sudo docker ps

We can access Nexus on http://<nexus-ip>:8081 > the page may take sometime to come up, just give it some time.

Sign in: To be able to login, click on the signin button and run this command on the terminal

sudo docker exec -it <sonar-docker-container-name> /bin/bash

cat /nexus-data/admin.password

To login, use admin as username and the generated password. > Click on Accept Anonymous Access

3.3. Sonarqube setup

SSH into the sonarqube VM and update it > Install docker with the same script used earlier > check if docker is installed docker --version > Next, create a sonarqube container by running the command sudo docker run -d -p 9000:9000 sonarqube:lts-community > check the container is running sudo docker ps

Access sonarqube on http://<sonarqube-ip:9000 > login using admin as username and password
Step 4: Install Jenkins Plugins, and Configure Nexus, Trivy, SonarQube and DockerHub to use Jenkins

a.> Install Jenkins Plugin

In the Jenkins page, we need to install some additional plugins we need for this project.

on the left menu, click on ‘manage jenkins’ > click on plugins > available plugins > in the search bar; type and select the following plugins.

sonarqube scanner, eclipse temurin installer, config file provide, maven integration, pipeline maven integration, kubernetes, kubernetes credential, kubernetes CLI, kubernetes client API, docker, docker pipeline

>After selecting them, click on install > Restart Jenkins when the installation is done.

b.> Configure the Plugins:

When you install plugins, it is a good practice to configure based on your needs. To do this; click on ‘manage jenkins’ > click on ‘tools’

For docker: give a name and leave as default

For maven: give it a name and leave as default

For JDK: click on add > install automatically > click on ‘adoptium.net’ > select jdk 17+35 > Save the configuration

for sonarqube scanner

c.> Configure SonarQube Scanner and SonarQube Server

    Generate token for SonarQube Scanner:

To generate a token; at the top menu, click on ‘administration’ > security > in the dropdown menu, click on ‘users’ > then ‘Tokens’ > type in a name and generate the token > copy the token generated

After generating the token we need to add this token to our jenkins credentials, login to your jenkins , click on ‘Manage Jenkins’ > Credentials > Global > click on ‘Add Credentials’ > in the pop page, for ‘kind’ select Secret text > paste the SonarQube token into the secret box > Create

    Add SonarQube Server Credentials to Jenkins

In ‘Managed Jenkins’ > Click on System > under SonarQube Servers click on Add SonarQube

> for URL type in http://<your-sonarqube-ip:9000 >

d.> Configure Jenkins to use Trivy

In the jenkins, click on ‘New Items’ > Select ‘pipeline’ > give a name for the pipeline > and create it. > when it is created, select the pipeline to start building. > click on ‘configure’

In the jenkins VM terminal, run the following commands to install trivy plugins . This is important if not our trivy pipeline commands will not run.

wget https://github.com/aquasecurity/trivy/releases/download/v0.43.0/trivy_0.43.0_Linux-64bit.deb
sudo dpkg -i trivy_0.43.0_Linux-64bit.deb

e.> Configure Jenkins to use Nexus

> copy th maven-releases and maven-snapshotsURL

Depending on where you have your source code open, edit the pom.xml file and paste it there. (if you have the source code on vscode like I did, make sure to push the changes to github)

To complete the setup, Jenkins needs authentication to the Nexus Server.

go to Managed Jenkins > Managed Files > Add ‘A new config file’ > Select ‘Global Maven settings.xml’ > scroll down, for IDchange it to ‘maven-settings’ or any name you can remember > In the pop page, edit the server section > Change username and password with your Nexus login credentials . (In the server section make sure by removing the comments and making sure it looks like this.)

 <servers>
 
    <server>
      <id>maven-releases</id>
      <username>admin</username>
      <password>admin</password>
    </server>
   
    <server>
      <id>maven-snapshots</id>
      <username>admin</username>
      <password>admin</password>
    </server>
    
  </servers>

in the Nexus login page, edit the deployment policy for both maven-releases and maven-snapshots > change it to allow redeploy

This will ensure there is no re-build error when the jenkins pipeline attempts to re-send the artifacts

Add credentials to jenkins, in managed jenkins > credentials > global > type in the username and password of the Nexus credentials and create it

rf.> Configure Jenkins to Dockerhub authentication

Before building the artifact, we need a registry to store the image. We will doing this with dockerhub

> Log into your dockerhub and create a private repo, you can give it any name .

We will be adding this newly created dockerhub repo into the Docker Build & Tagstage of the pipeline

After creating the dockerhub repo, we need to create a jenkins credential for it.

Go to ‘managed jenkins’ > click on ‘credentials’ > > global > then ‘Add credentials’ > for kind, select ‘username and password’ > type in your dockerhub username and password in their respective fields > for ID give it a name so you can can identify it.

We will need to add the credentials to system settings, go to managed jenkins > systems > edit the docker section and select the newly docker credentials you just created.
Step 5: Create a complete CICD pipeline

This pipeline should be changed to fit your docker image and dockerhub details. This is not the end of the pipeline, because we still going to integrate Email Push Notification within the pipeline that tells us when the pipeline fails or succeeds.

pipeline {
    agent any
    tools {
        jdk "jdk"
        maven "maven"
    }
    environment {
        SCANNER_HOME = tool 'sonar-scanner'
    }
    
    stages {
        stage('Git Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/ougabriel/full-stack-blogging-app.git'
            }
        }
        stage('Compile') {
            steps {
                sh "mvn compile"
            }
        }
        stage('Trivy FS') {
            steps {
                sh "trivy fs . --format table -o fs.html"
            }
        }
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('sonarqubeServer') {
                    sh '''$SCANNER_HOME/bin/sonar-scanner -Dsonar.projectName=Blogging-app -Dsonar.projectKey=Blogging-app \
                          -Dsonar.java.binaries=target'''
                }
            }
        }
        stage('Build') {
            steps {
                sh "mvn package"
            }
        }
        stage('Publish Artifacts') {
            steps {
                withMaven(globalMavenSettingsConfig: 'maven-settings', jdk: 'jdk', maven: 'maven', mavenSettingsConfig: '', traceability: true) {
                        sh "mvn deploy"
                }
            }
        }
        stage('Docker Build & Tag') {
            steps {
                script{
                withDockerRegistry(credentialsId: 'dockerhub-cred', url: 'https://index.docker.io/v1/') {
                sh "docker build -t ugogabriel/gab-blogging-app ."
                }
                }
            }
        }
        stage('Trivy Image Scan') {
            steps {
                sh "trivy image --format table -o image.html ugogabriel/gab-blogging-app:latest"
            }
        }
        stage('Docker Push Image') {
            steps {
                script{
                withDockerRegistry(credentialsId: 'dockerhub-cred', url: 'https://index.docker.io/v1/') {
                    sh "docker push ugogabriel/gab-blogging-app"
                }
                }
            }
        }
    }  // Closing stages
}  // Closing pipeline

Run the build, and click on stages to see the pipeline stages
Step 6: Create the EKS cluster, Install AWS CLI, Kubectl and Terraform

We will need to create a VM, install and useterraform to deploy the EKS service into the machine and install and usekubectl to interact with this EKS cluster.

a.> Create the VM: Login to the AWS console and create a new EC2 instance (t2 medium, 15GB) as we did before > use the same keypair and security group as the other instances and make sure the public IP is enabled. > Create the instance.

b.> Install AWS CLI: The AWS CLI (Command Line Interface) allows you to interact with AWS services directly from your terminal.

# Update the package list
sudo apt update

# Install curl if not already installed
sudo apt install curl -y

# Download the AWS CLI v2 installation file
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"

# Install unzip and extract the downloaded zip file
sudo apt install unzip -y
unzip awscliv2.zip

# Run the AWS CLI installer
sudo ./aws/install

# Verify the installation
aws --version

After the installation we need to connect the cluster to our AWS; to do this we need to create a access key that will be to authenticate to AWS services.

> In your AWS console > click on your profile > security credentials > and Create access key

Run the following command aws configurein your AWS console > copy and paste the access key and security access keys in the prompts.

Follow the prompts as shown below

c.> Install Terraform: Install terraform in this instance by running this command

sudo apt install terraform --classic

We need 3 tf files for our terraform script. Which is the main.tf , output.tf and variable.tf . (find the files in the given github repo for this project)

vi output.tf
vi main.tf
vi variable.tf

Run this command individually, copy and paste the terraform scripts into the editor > save and exit.

To deploy the resources, we need to first run the following commands

(optional: make sure to change the main.tf region and the availabilty zone to suite your region)

(important: in the variable.tfscript you MUST change the default = "gabkeypair to the name of your AWS instance keypairif the name is different from this.

    terraform init : to initialize the project, It downloads the necessary provider plugins and sets up the backend where Terraform will store state data.
    terraform plan : Prepares an execution plan, showing what actions Terraform will take to deploy the infrastructure. It lists the resources that will be created, modified, or destroyed. In this case, you would see a plan indicating that 17 resources are going to be deployed.

    terraform apply: Executes the plan and actually deploys the infrastructure. Terraform will create, modify, or delete resources as outlined in the execution plan.

preferrably; run this command

terraform apply --auto-approve

Make sure to run the commands in the order given above

When you run the command, it will take sometime for all the changes or all the services to be fully deployed.

After the installation when you run kubectl get nodes you will notice the error Command kubectl not found this is because the kubectl command is not yet installed.

sudo snap install kubectl --classic

After installing kubectl we need to confirm if our nodes are ready; run the command kubectl get nodes . You should get another error as shown below.

This is because you are yet to connect the EKS cluster to AWS services, do that using this command;

aws eks --region eu-west-2 update-kubeconfig --name <cluster-name>

Run the command again this time to the nodes ready

d.> Setup Service Account and RBAC

RBAC is one of the most important concepts of Kubernetes. In order to be able to perform deployments and authentication with this cluster we need to create a service account and give it necessary permissions. RBAC (Role Based Access Control) we will create roles, rolebinding, a token for the secret which we will be used for authentication. Copy and paste the following commands into the vi editor

Create a namespace

kubectl create namespace webapps

Service Account > vi serviceaccount.yaml

apiVersion: v1
kind: ServiceAccount
metadata:
  name: jenkins
  namespace: webapps

Role > vi role.yaml

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: webapps
  name: role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["get", "list", "create", "delete", "patch", "watch"]

Rolebinding > vi rolebinding.yaml

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rolebinding
  namespace: webapps
subjects:
- kind: ServiceAccount
  name: jenkins # The service account created earlier
  namespace: webapps
roleRef:
  kind: Role
  name: role  # The role created earlier
  apiGroup: rbac.authorization.k8s.io

Token for Service Account Secret > vi sa-secret.yaml

apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  name: mysecretname
  namespace: webapps  # Make sure to specify the correct namespace
  annotations:
    kubernetes.io/service-account.name: jenkins  # The service account name

Apply all the yaml files,

kubectl apply -f serviceaccount.yaml
kubectl apply -f role.yaml
kubectl apply -f rolebinding.yaml
kubectl apply -f sa-secret.yaml

If you check the git repo for this project, you will see the deployment-service.yml which will be deployed to this EKS cluster. We will need to create an imagePullSecretfor it to pull our docker image from the dockerhub private registry . When working with private registry, you will need to provide an authentication secret that helps it get access to the private registry. Run the following command. (change username and password to that of your dockerhub credentials).

kubectl create secret docker—registry regcred \
--docker—server=https://index.docker.io/v1/ \
--docker—username=<your—username> \
--docker—password=<your—password>
--namespace=webapps

regcred is the name of the imagePullSecret . This is already added to the deployment.yaml file in the git repo.

e.> Authenticate Jenkins with EKS using secret

If you run the command, kubectl get secrets -n webapps you will notice we have two secrets.

One for pulling the image from the dockehub private registry and the other for the service account authentication. Run the command kubectl describe secret mysecretname -n webapps to get the authentication token for our service account secret.

Go to jenkins, click on ‘manage jenkins’ > Credentials > Global > Add credentials > for kind select ‘secret text’ > paste the token within the ‘secret’ box > give it a name > Create

f.> Install Kubectl on Jenkins, Modify the Pipeline and Setup Email Notification

We will be inserting kubectl command in the pipeline, we will need to install it on the Jenkins machine so that kubectl command syntax can be able to work.

sudo snap install kubectl --classic

Now, we will be modifying the pipeline to deploy our kubernetes resources. we will be adding 3 more stages to the pipeline script for this purpose.

g.> Setup Email Notifications

Copy and paste the following into the browser to generate an email authentication password. (GMAIL only)

https://myaccount.google.com/apppasswords

for other email accounts, you can do this.

For Hotmail/OutlookGo to your Microsoft Account Security page.
Click on Advanced security options.
Under App passwords, click on Create a new app password.
Use the generated app password in your application (e.g., Jenkins) instead of your regular password.For Yahoo:Go to your Yahoo Account Security page.
Enable Two-step verification if not already enabled.
After enabling 2FA, select Generate app passwords.
Use the app password in your application (e.g., Jenkins) instead of your regular password.

Click on ‘manage jenkins’ > systems > scroll down till you find Email Notification > fill in the boxes as shown > test the connection

Make sure port 465 is open in your AWS NSG (Network Security Group).

Within the same page, configure the same thing for Extended Email notification , this time you will add a credential named email cred containing the username and generated password of the email you used earlier.

To see the 2 new stages (k8s-deploy and k8s verify) added to the pipeline please check the jenkinsfile in the git repo. Trigger the pipeline to deploy the application
Step 7: Assign a custom domain to the deployed application

Add the URL link into an existing Domain from any domain name provider for example (godaddy) using the CNAME type. Perform an nslookup to verify it is up. Then try it on the browser to view the app.

Note: this is optional. I dont need this app to have any special domain url but you can try it for practice
Step 8: Monitor the application

Create another EC2 instance of t2large and 25GB > install grafana, prometheus and blackbox on the instance using the following command.

a.> Set Up Blackbox Exporter: Blackbox Exporter is used for probing endpoints and checking their availability.

Install Blackbox Exporter

Download and run Blackbox Exporter:

wget https://github.com/prometheus/blackbox_exporter/releases/download/v0.21.0/blackbox_exporter-0.21.0.linux-amd64.tar.gz
 tar xvfz blackbox_exporter-0.21.0.linux-amd64.tar.gz
 cd blackbox_exporter-0.21.0.linux-amd64
 ./blackbox_exporter

Configure Blackbox Exporter > vi blackbox.yaml

modules:
  http_2xx:
    prober: http
    timeout: 5s
    http:
      method: GET
      valid_http_versions: [ "1" ]
      valid_http_mimes: [ "application/json" ]
      valid_http_status_codes: []  # Defaults to 2xx

b.> Set Up Prometheus: Prometheus will be used to collect metrics from various sources, including the Blackbox Exporter.

Install Prometheus > sudo apt install prometheus -y

Create the Prometheus config file > vi prometheus.yaml

global:
  scrape_interval: 15s
  evaluation_interval: 15s

crape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'blackbox'
    metrics_path: /probe
    params:
      module: [http_2xx]  # Look for an HTTP 200 response
    static_configs:
      - targets:
          - http://prometheus.io
          - https://prometheus.io
######blog app url link
          - aeac8ab098ec448ca94c681962c91277-1539973516.eu-west-2.elb.amazonaws.com  #the blogging app url link to probe
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 18.175.135.0:9115  # Blackbox Exporter address

Make sure to change the blackbox exporter address and blog app url linkto that which points to your VM IP. and change the blog app url link

Run Prometheus > prometheus --config.file=prometheus.yaml

c.> Set Up Grafana: Grafana will be used for visualizing metrics collected by Prometheus.



# Update package list and install necessary dependencies
sudo apt-get update
sudo apt-get install -y software-properties-common curl

# Add Grafana GPG key
curl https://packages.grafana.com/gpg.key | sudo apt-key add -

# Add Grafana APT repository
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"

# Update package list again and install Grafana
sudo apt-get update
sudo apt-get install -y grafana

# Start Grafana service
sudo systemctl start grafana-server

# Enable Grafana to start on boot
sudo systemctl enable grafana-server

# Print the status of Grafana service
sudo systemctl status grafana-server

d.> Verify Installations: Do this on the termline

#for blackbox
curl http://localhost:9115

#for blackbox exporter metrics
curl http://localhost:9115/metrics

#for prometheus
curl http://localhost:9090/metrics

#for grafana
sudo systemctl status grafana-server

Open grafana and prometheus using your VM IP and their port

#for grafana
http://<monitoring-vm-ip>:3000

#for prometheus
http://<monitoring-vm-ip>:9090

#for blackbox
http://<monitoring-vm-ip>:9115

e.> Add data source and create dashboard:

    Open Grafana in your web browser: > Log in with the default credentials (`admin/admin`) > click on Administration > Add Prometheus as a data source > Set the URL to your Prometheus instance > Click `Save & Test`.
    On the left pane click on ‘import dashboard’ > for ID type in 7587
    and click Load > select a data source (prometheus) > click import

-Prometheus: collects and stores metrics.
- Blackbox Exporter: probes your application endpoints and provides metrics to Prometheus.
-Grafana: visualizes the metrics collected by Prometheus.

By setting up these components, you’ll be able to monitor your application’s health and performance effectively.


##
#
https://harsh05.medium.com/building-a-robust-ci-cd-pipeline-with-gitlab-aws-eks-and-terraform-44de6e937558
#
##

Deploying Secure Java Applications on AWS EKS Using GitLab CI/CD, Maven, Trivy and SonarQube
@Harsh

@Harsh
·

Follow
14 min read
·
Aug 13, 2024

In modern DevOps, automation is crucial for efficient, reliable, and consistent software deployment. GitLab CI/CD is a powerful tool that helps streamline the entire software delivery process. In this project, we’ll explore how to use GitLab CI/CD to deploy a Java application on a aws-managed Kubernetes multi-cluster set up using eksctl. We'll cover the process from creating the Kubernetes cluster to deploying a containerized Java application, integrating essential DevOps tools like Trivy and SonarQube along the way.
Step-by-Step Workflow:
Project Overview

    Registering an AWS Instance as a GitLab Runner
    Creating a GitLab CI/CD Pipeline
    Unit Testing with Maven
    Scanning Dependencies with Trivy
    Analyzing Code Quality with SonarQube
    Building and Containerizing the Application
    Scanning the Container Image with Trivy.
    Pushing the Container Image to GitLab Container Registry.
    Deploying the Application to Kubernetes
    Setting up AWS EKS Cluster using eksctl.
    Connecting EKS Cluster with GitLab
    Running the Pipeline

Step 1: Create New Project in Gitlab:
Step 2: Setting Up AWS Instance as a Gitlab Agent

    Log in to AWS Management Console.
    Launch an EC2 instance with the following specifications:

    Amazon Machine Image (AMI): Choose an Ubuntu or Amazon Linux AMI.
    Instance Type: Select an instance type that suits your job requirements (e.g., t2.micro for testing).
    Security Group: Ensure the instance allows SSH access.

Install GitLab Runner on the EC2 Instance

    SSH into your EC2 instance:

2. Install GitLab Runner:

    Run the below commands to install gitlab runner.

sudo curl -L --output /usr/local/bin/gitlab-runner https://gitlab-runner-downloads.s3.amazonaws.com/latest/binaries/gitlab-runner-linux-amd64
sudo chmod +x /usr/local/bin/gitlab-runner
sudo useradd --comment 'GitLab Runner' --create-home gitlab-runner --shell /bin/bash
sudo gitlab-runner install --user=gitlab-runner --working-directory=/home/gitlab-runner
sudo gitlab-runner start

Register the Runner with Your GitLab Project

    Now we need authentication token for registering this instance as a runner for my project.
    Go to your Project > settings > CI/CD > Runners.
    We need to run below command in the AWS instance to get it registered.

    Give the appropriate tag name.

    We need to run below command in the AWS instance to get it registered.

sudo gitlab-runner run

Follow the prompts:

    Enter the GitLab instance URL: https://gitlab.com/
    Enter the executor: Choose shell for simplicity, but you can use Docker or other executors.
    Verify by reading the file /home/ubuntu/.gitlab-runner/config.toml file.

Step 3: Creating a GitLab CI/CD Pipeline

Now that our infrastructure is ready, we can start defining the GitLab CI/CD pipeline in a .gitlab-ci.yml file. The pipeline will consist of several stages, including testing, scanning, building, and deploying the Java application.

    Clone the repository in your local environment.

2. Add the code and push it to the github repository..
Step 4: Pipeline Configuration: .gitlab-ci.yml
1. STAGES:

    First, we will set the stages in the file:

2. Installing Pre-requisites Tools:

    Some tools are need to be installed before going ahead with the project.

- sudo apt install -y openjdk-17-jre-headless  
- sudo apt install -y maven
- sudo apt-get install -y wget apt-transport-https gnupg lsb-release
- wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
- echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
- sudo apt -y install docker.io && chmod 666 /var/run/docker.sock
- sudo apt-get update && sudo apt-get install -y trivy
- sudo snap install kubectl --classic

    But for this, we need to give sudo powers to the user gitlab-runner otherwise these commands will not work.
    Go to the /etc/sudoers.d folder and edit the below file.

3. Unit Testing with Maven:

    Unit testing is the first step in ensuring the reliability of your application. Maven is used here to run unit tests.

 mvn test

    This command compiles the code and runs the tests defined in the project. The output will provide insights into any failures or issues that need to be addressed.

4. Scanning Dependencies with Trivy

    Trivy is a vulnerability scanner for container images, file systems, and Git repositories. We use it here to scan the dependencies of our Java application.

trivy fs --format table -o fs.html .

    This command scans the current directory for any vulnerabilities in the dependencies used by the application and store the output in fs.html file.
    It’s a crucial step to ensure the security of your project. We will then artifacts the fs.html file to get the output.

    When we run it, it shows the output something like this :

5. Analyzing Code Quality with SonarQube

    SonarQube is a tool that analyzes source code to detect bugs, vulnerabilities, and code smells.
    Integrating SonarQube into your CI pipeline helps maintain high code quality.
    Sonarqube consist of two parts, one is scanner part and other is server part. We will setup the server first manually with the help of docker.

    Access the sonarqube portal at https://public-ip:9000

    Default username and password is admin

    For personal token, Go to Project > Settings > Access Tokens.
    Click on Add Token

    Copy the code and paste it in the sonarqube.

    Save Configuration.

    Enter your personal token here also and save it.

    Click on Set up .

    Choose other from below option and copy the code.

    Go to your gitlab repository and create the file sonar-project.properties and paste this code in there.

    Save the file and click on continue on sonarqube portal.

    Then we will follow the next step Add environment variables .

    So as per the 2nd step, we will create 2 variables.

    Click on continue on the sonarqube 2nd step after completing this.
    It will provide us the entire job that we need to copy and paste in our .gitlab-ci.yml file.

    Append the pipeline and save it:

    When we run the pipeline, sonarqube will show the result something like this on the server.

6. Building and Containerizing and Scanning the Application

    Once testing and scanning are completed, the next step is to build the application package and create a Docker image.
    Before pushing the image, we scan it with Trivy to ensure it doesn’t contain any vulnerabilities.
    This step is vital for security, as it identifies any issues within the built Docker image.

    When you successfully run the pipeline, you will show the output something like this.

7. Pushing the Container Image to GitLab Container Registry

After creating the Docker image, we push it to the GitLab Container Registry, where it will be stored and accessible for deployment.

    When you run this job and if the job succeed, you will find that your image is being pushed in your Container Registry.
    In Deploy > Container Registry.

8. Deploying the Application to Kubernetes

Finally, deploy the containerized application to your Kubernetes cluster:

    In this job, we will decode the config details that we earlier encoded for security purpose.

    Here we create a variable KUBE_CONTEXT project-path:k8s-agent and use the bitnami image for kubectl.
    Since our manifest include several gitlab variables, therefore we use envsubst keyword that will substitute the original values in place of them.

deployment-service.yaml.template :

apiVersion: apps/v1
kind: Deployment # Kubernetes resource kind we are creating
metadata:
  name: java-app
spec:
  selector:
    matchLabels:
      app: java-app
  replicas: 2 # Number of replicas that will be created for this deployment
  template:
    metadata:
      labels:
        app: java-app
    spec:
      imagePullSecrets:
        - name: registry-credentials # To authenticate to our container registry
      containers:
        - name: java-app-container
          image: $CI_REGISTRY/harsh005/java-app/java-app:$CI_PIPELINE_ID # Image that will be used to containers in the cluster
          imagePullPolicy: Always
          ports:
            - containerPort: 8080 # The port that the container is running on in the cluster


---

apiVersion: v1 # Kubernetes API version
kind: Service # Kubernetes resource kind we are creating
metadata: # Metadata of the resource kind we are creating
  name: java-app-svc
spec:
  selector:
    app: java-app
  ports:
    - protocol: "TCP"
      port: 80
      targetPort: 8080
  type: LoadBalancer # type of the service.

Step 5: Setting up AWS EKS Cluster using eksctl

eksctl is a simple CLI tool for creating and managing clusters on EKS. It's a preferred option because of its simplicity and ease of use. Here’s how to create an EKS cluster using eksctl:
1. Install eksctl:

    Click on Below Link :

Release eksctl 0.176.0 · eksctl-io/eksctl
Release v0.176.0 🚀 Features Add support for AMIs based on AmazonLinux2023 (#7684) 🎯 Improvements Display full draft…

github.com

    Install the eksclt windows release.

    Extract the folder in your local computer.

2. Configuring AWS CLI:

    Download the AWS CLI tool in your local computer.

Install or update to the latest version of the AWS CLI
Instructions to install or update the AWS CLI on your system.

docs.aws.amazon.com

    Download the AWS CLI from here and configure it for your account.
    For this you need to create IAM User in your account.
    In Security credentials, click on Create access key option and create the access and secret key and copy both.

    Now go to your local command line, and write command aws configure and paste these credentials there

    Paste your access key in Access Key ID and Secret Key in Secret Access Key ID. And also give the default region that you want to set.

After successfully set up aws cli, we also need to install client tool for kubernetes that is Kubectl, that will deploy our applications inside cluster.
3. Creating an EKS Cluster:

    Create a EKS cluster setup file in yaml.

apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: my-test-cluster
  region: us-east-1

nodeGroups:
  - name: small-nodegroup
    instanceType: t2.micro
    desiredCapacity: 2

  - name: medium-nodegroup
    instanceType: t2.small
    desiredCapacity: 2

    Now with a single command, eks will launch the entire cluster.

eksctl create cluster -f cluster-setup.yml

Step 6: Connecting EKS Cluster with GitLab

After creating the EKS cluster, the next step is to connect it to GitLab to manage deployments directly from your CI/CD pipeline.

    Create a agent configuration file .gitlab/agents/eks-k8s/config.yaml in your repository:

user_access:
  access_as:
      agent: {} 
  projects:
      - id: <your-project-id>

    Navigate to Operate > Kubernetes Cluster > Connect a cluster.

    Select your agent from dropdown and Register it.

    Copy the token and agent configuration commands after this step.
    Run the those commands in your cluster to deploy gitlab agent.

helm repo add gitlab https://charts.gitlab.io
helm repo update
 helm upgrade --install eks-k8s gitlab/gitlab-agent \
    --namespace gitlab-agent-eks-k8s \
    --create-namespace \
    --set image.tag=v17.3.0-rc7 \
    --set config.token= <your-token> \
    --set config.kasAddress= <your-kasAddress>

    Once the agent is deployed, you will see that the Connection Status on gitlab is showing Connected .

    Now we need to add the registry credentials in kubernetes manifest so that it can pull the image while creating deployment.
    For this we will create secret named registry-credentials
    So we need Token for this step to authenticate to our registry.
    Go to Settings > Repository > Display tokens > Add Token.

    Create deploy token and copy them. They will be used as our container registry’s username and password.

    Go to your cluster and create a docker-registry secret named registry-credentials.

 kubectl create secret docker-registry registry-credentials --docker-server=registry.gitlab.com --docker-username=<1st-token> --docker-password=<2nd-token> --dry-run=client -o yaml > registry-credentials.yml

Step 7: Running the Pipeline

With everything set up, it’s time to run the pipeline.

    Commit and Push Code:

    Ensure that your .gitlab-ci.yml file, Java source code, and Kubernetes deployment manifests, Dockerfile are committed to your GitLab repository.

.gitlab-ci.yml :

stages:
  - pre-requisite
  - unit_test
  - trivy_scan
  - sonar_test
  - build_and_scan
  - image_push
  - deploy_to_eks

install_tools:
  stage: pre-requisite
  script:
    - sudo apt install -y openjdk-17-jre-headless  
    - sudo apt install -y maven
    - sudo apt-get install -y wget apt-transport-https gnupg lsb-release
    - wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
    - echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
    - sudo apt-get update && sudo apt-get install -y trivy
    - sudo apt -y install docker.io && sudo chmod 666 /var/run/docker.sock
    - sudo snap install kubectl --classic
  tags:
    - dedicated-runner
  only:
    - main

unit_testing:
  stage: unit_test
  script:
    - mvn test
  tags:
    - dedicated-runner
  only:
    - main

trivy_fs_scan:
  stage: trivy_scan
  script:
    - trivy fs --format table -o fs.html .
  tags:
    - dedicated-runner
  artifacts:
    paths:
      - fs.html
  only:
    - main

sonarqube-check:
  stage: sonar_test
  image: 
    name: sonarsource/sonar-scanner-cli:latest
  variables:
    SONAR_USER_HOME: "${CI_PROJECT_DIR}/.sonar"  # Defines the location of the analysis task cache
    GIT_DEPTH: "0"  # Tells git to fetch all the branches of the project, required by the analysis task
  cache:
    key: "${CI_JOB_NAME}"
    paths:
      - .sonar/cache
  script: 
    - sonar-scanner
  allow_failure: true
  only:
    - main


image_build_&_scan:
  stage: build_and_scan
  variables:
    Image_tag: $CI_REGISTRY/harsh005/java-app/java-app:$CI_PIPELINE_ID
  script:
    - mvn clean package
    - docker build -t $Image_tag .
    - trivy image $Image_tag --format table -o image.html
  tags:
    - dedicated-runner
  artifacts:
    paths:
      - image.html
  only:
    - main

image_push:
  stage: image_push
  variables:
    Image_tag: $CI_REGISTRY/harsh005/java-app/java-app:$CI_PIPELINE_ID
  before_script:
    - docker login $CI_REGISTRY -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD
  script:
    - docker push $Image_tag 
  tags:
    - dedicated-runner
  only:
    - main

k8s-deploy:
  stage: deploy_to_eks
  variables:
    KUBE_CONTEXT: harsh005/java-app:eks-k8s
  image: 
    name: bitnami/kubectl:latest
    entrypoint: ['']
  before_script:
    - kubectl config use-context "$KUBE_CONTEXT"
  script:
    - envsubst < deployment-service.yaml.template > deployment-service.yaml
    - kubectl apply -f deployment-service.yaml
  only:
    - main
  when: manual

    Here we also put some job controls that all the jobs will run in main branch. And if all the jobs prior to deploy_to_eks stage are successful, then we manually trigger the k8s-deploy job, that will deploy our code on our self-managed Kubernetes.

2. Trigger the Pipeline:

    Once the code is pushed, GitLab will automatically detect the .gitlab-ci.yml file and trigger the pipeline.

3. Monitor the Pipeline:

    Navigate to the CI/CD > Pipelines section in your GitLab project to monitor the progress.
    You’ll see each stage — installation, testing, scanning, building and deploying— execute in sequence in test branch.

    You can see the results of trivy scan or sonarqube testing as we told earlier.
    Now since all the testing and building is done, we can manually trigger k8s-deploy job for final deploy.

4. Review Pipeline Results:

    Review the output logs for each job. If everything is set up correctly, the pipeline should complete successfully, and your Java application will be deployed to your Kubernetes cluster.

5. Output:

    Copy the external ip (load balancer URL) and paste it on your browser.

Conclusion

In this project, we’ve covered the setup and deployment of a Java application on a self-managed Kubernetes multi-cluster using GitLab CI/CD. The process included unit testing, security scanning, code quality analysis, building, containerization, and finally, deploying the application using Kubernetes. This pipeline automates the software delivery process, ensuring high-quality code is consistently deployed in a secure and efficient manner. By running the pipeline, we’ve seen how GitLab CI/CD can streamline complex deployments, integrating multiple tools and processes into a single automated workflow.
