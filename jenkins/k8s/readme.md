##
#
https://gist.githubusercontent.com/vishnuhd/4f6b007ff47794be84bd979d3e1be1df/raw/36b218cbba24cc8ac3bec14ea89561378d4e7c04/jenkinsk8shelm.md
#
##

# Deploy Jenkins to K8s using Helm in Jenkins namespace

- Setup tiller in your k8s cluster as here - https://gist.github.com/vishnuhd/08a5b830a4dbf2476ee40ace18e36a31

- Create jenkins namespace
```
kubectl create ns jenkins
```

- Install helm chart for Jenkins with `jenkins` namespace
```
helm install --name my-jenkins stable/jenkins --set namespaceOverride=jenkins
```

- NOTES:
1. Get your 'admin' user password by running:
```
  printf $(kubectl get secret --namespace jenkins my-jenkins -o jsonpath="{.data.jenkins-admin-password}" | base64 --decode);echo
```
2. Get the Jenkins URL to visit by running these commands in the same shell:
  NOTE: It may take a few minutes for the LoadBalancer IP to be available.
        You can watch the status of by running 
        ```
        kubectl get svc --namespace jenkins -w my-jenkins
        ```
```
  export SERVICE_IP=$(kubectl get svc --namespace jenkins my-jenkins --template "{{ range (index .status.loadBalancer.ingress 0) }}{{ . }}{{ end }}")
  echo http://$SERVICE_IP:8080/login
```
3. Login with the password from step 1 and the username: admin

## Setup for docker in docker

- Create a container tamplate with name and image as `docker` in Manage Jenkins -> Configure System.
- Add a host path volume with `host path` and `mount path` as `/var/run/docker.sock`
- Find below some useful Jenkinsfiles :

```
pipeline {
    agent {
        kubernetes {
            label "my-jenkins-jenkins-slave"
            defaultContainer 'docker'
        }
    }
    stages{
        stage("Build and Push to ACR") {
            steps {
                 sh "docker ps"
            }
        }
    }
}
```

AND

```
def label = "worker-${UUID.randomUUID().toString()}"

podTemplate(label: label, containers: [
  containerTemplate(name: 'docker', image: 'docker', command: 'cat', ttyEnabled: true),
  containerTemplate(name: 'kubectl', image: 'lachlanevenson/k8s-kubectl:v1.8.8', command: 'cat', ttyEnabled: true),
  containerTemplate(name: 'helm', image: 'lachlanevenson/k8s-helm:latest', command: 'cat', ttyEnabled: true)
],
volumes: [
  hostPathVolume(mountPath: '/var/run/docker.sock', hostPath: '/var/run/docker.sock')
]) {
  node(label) {
    def myRepo = "test"
 
    stage('Test') {
      script{
          echo "Test"
      }
    }
    stage('Build') {
      script{
          echo "Build"
      }
    }
    stage('Create Docker images') {
      container('docker') {
          sh "docker ps"
      }
    }
    stage('Run kubectl') {
      container('kubectl') {
        sh "kubectl get pods"
      }
    }
    stage('Run helm') {
      container('helm') {
        sh "helm list"
      }
    }
  }
}
```

## Issues

- If slaves are failing instantaneously, verify the value at - Manage Jenkins -> Configure System -> Kubernetes URL = https://kubernetes.default:443 (Issue : https://github.com/helm/charts/issues/16928)






1. Set Up Jenkins Namespace
Create a namespace for Jenkins..

```
kubectl create namespace jenkins
```


2. Install Jenkins Helm Chart
Since Helm 3 no longer requires Tiller, installation is simpler. The Jenkins Helm chart has moved from stable/jenkins to jenkinsci/jenkins, which is the updated repository.

Add the Jenkins Helm chart repository:

```
helm repo add jenkinsci https://charts.jenkins.io
helm repo update
```

Install Jenkins with the following command, specifying the jenkins namespace and custom values for configuration:

```
helm install my-jenkins jenkinsci/jenkins --namespace jenkins --set controller.serviceType=LoadBalancer
```

This command deploys Jenkins with a LoadBalancer service for external access. Update serviceType based on your infrastructure (e.g., NodePort for on-prem clusters).

3. Access Jenkins
Retrieve the admin password:

```
kubectl get secret --namespace jenkins my-jenkins -o jsonpath="{.data.jenkins-admin-password}" | base64 --decode
```


Get the Jenkins URL:

Wait for the LoadBalancer IP to be assigned, then:

```
kubectl get svc --namespace jenkins my-jenkins -w
```

When the IP is ready, access Jenkins at http://<LoadBalancerIP>:8080.

4. Docker-in-Docker Setup
To set up DinD, configure a Jenkins agent pod template that can handle Docker commands. Here’s how:

Jenkins Agent with Docker:

In the Kubernetes plugin settings (Manage Jenkins > Configure System), add a new container template with the following specifications:

Name: docker
Image: docker:20.10-dind (or latest)
Mount Host Path: /var/run/docker.sock at /var/run/docker.sock
This will allow the Jenkins container to use the host’s Docker daemon.

5. Jenkins Pipeline for Docker and Kubernetes Commands
Update your Jenkinsfiles to align with Kubernetes and Helm’s latest versions. Here’s a streamlined example:

```
pipeline {
    agent {
        kubernetes {
            label "jenkins-slave"
            defaultContainer 'docker'
        }
    }
    stages {
        stage("Build and Push to Registry") {
            steps {
                container('docker') {
                    sh "docker build -t myrepo/myimage:latest ."
                    sh "docker push myrepo/myimage:latest"
                }
            }
        }
    }
}
```


For a more complex setup using multiple containers (Docker, kubectl, and Helm), here’s an updated template:

```
def label = "worker-${UUID.randomUUID().toString()}"

podTemplate(label: label, containers: [
  containerTemplate(name: 'docker', image: 'docker:20.10-dind', command: 'cat', ttyEnabled: true),
  containerTemplate(name: 'kubectl', image: 'bitnami/kubectl:latest', command: 'cat', ttyEnabled: true),
  containerTemplate(name: 'helm', image: 'alpine/helm:3.8.0', command: 'cat', ttyEnabled: true)
],
volumes: [
  hostPathVolume(mountPath: '/var/run/docker.sock', hostPath: '/var/run/docker.sock')
]) {
  node(label) {
    stage('Test') {
      echo "Running tests..."
    }
    stage('Build') {
      echo "Building..."
    }
    stage('Docker Build & Push') {
      container('docker') {
          sh "docker build -t myrepo/myimage:latest ."
          sh "docker push myrepo/myimage:latest"
      }
    }
    stage('Deploy with kubectl') {
      container('kubectl') {
        sh "kubectl get pods -n jenkins"
      }
    }
    stage('Deploy with Helm') {
      container('helm') {
        sh "helm list -n jenkins"
      }
    }
  }
}
```
6. Persistent Volume for Jenkins
To persist Jenkins data across pod restarts, configure a persistent volume:

Create a PersistentVolumeClaim (PVC):


```
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: jenkins-pvc
  namespace: jenkins
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

Apply this YAML with kubectl apply -f <filename>.yaml.

Configure the Helm Chart to Use the PVC:

Pass the PVC name to the Helm chart to persist Jenkins data:
```
helm upgrade my-jenkins jenkinsci/jenkins --namespace jenkins --set persistence.existingClaim=jenkins-pvc
```

This setup ensures Jenkins retains data and can access Docker, kubectl, and Helm for CI/CD tasks on Kubernetes.
