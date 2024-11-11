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
