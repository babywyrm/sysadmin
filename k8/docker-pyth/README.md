

###################
###################

kubectl is a command-line interface for executing commands against a Kubernetes cluster. Run the shell script below to install kubectl:

curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl

Deploying to Kubernetes requires a containerized application. Let's review containerizing Python applications.

We can now use kubectl to add the persistent volume and claim to the Kubernetes cluster:

$ kubectl create -f persistent-volume.yml
$ kubectl create -f persistent-volume-claim.yml

We are now ready to deploy to Kubernetes.

###################
###################


Finally, use kubectl to deploy the application to Kubernetes:

$ kubectl create -f k8s_python_sample_code.deployment.yml
$ kubectl create -f k8s_python_sample_code.service.yml

Your application was successfully deployed to Kubernetes.

You can verify whether your application is running by inspecting the running services:

kubectl get services

May Kubernetes free you from future deployment hassles!

Want to learn more about Python? Nanjekye's book, Python 2 and 3 Compatibility offers clean ways to write code that will run on both Python 2 and 3, including detailed examples of how to convert existing Python 2-compatible code to code that will run reliably on both Python 2 and 3.
