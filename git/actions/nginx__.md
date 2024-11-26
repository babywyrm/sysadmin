GitOps way with Github Actions and self-hosted runner on Kubernetes
Igor Zhivilo
Israeli Tech Radar
Igor Zhivilo

##
#
https://medium.com/everything-full-stack/gitops-way-with-github-actions-and-self-hosted-runner-on-kubernetes-bb15d3f2f147
#
##




Hi, I’m DevOps Engineer at Tikal Knowledge.

In this tutorial, I will show how to:

Deploy self-hosted-runner to Kubernetes and connect it with your GitHub repo.
Redeploy Nginx server on your k8s cluster with every change in nginx/deployment.yaml, which pushed to Github repo.
Every change in configuration of deployment.yaml on Github will be propagated to Nginx server.

On YouTube you can watch also: https://youtu.be/cV1LhQT1bK4

Github Actions Published guides:

Use GitHub Actions and Terraform to provision EC2 instance
GitOps way with Github Actions and self-hosted runner on Kubernetes
Automatic scaling with Github Actions and self-hosted runners
Github Actions with k8s and Karpenter to dynamically provision your runners on spot instances
Github Actions with ChatOps to write beautiful python code
Use OpenID Connect with Github Actions to authenticate with Amazon Web Services
So, why self-hosted runner?
The reason for self-hosted runner is coming from security limitation ( in my case), I have an internal k8s cluster which is not externally reachable and can be accessed only via VPN.

So how it works if the cluster can’t be reached externally?

Communication between self-hosted runners and GitHub

The self-hosted runner connects to GitHub to receive job assignments and to download new versions of the runner application. The self-hosted runner uses an HTTPS long poll that opens a connection to GitHub for 50 seconds, and if no response is received, it then times out and creates a new long poll. The application must be running on the machine to accept and run GitHub Actions jobs.

Since the self-hosted runner opens a connection to GitHub.com, you do not need to allow GitHub to make inbound connections to your self-hosted runner.

meaning self-hosted runner using https polling to talk with Github, but Github not talking directly with self-hosted runners.

What is GitHub actions?
GitHub Actions is a continuous integration and continuous delivery (CI/CD) platform that allows you to automate your build, test, and deployment pipeline. You can create workflows that build and test every pull request to your repository, or deploy merged pull requests to production.

GitHub Actions goes beyond just DevOps and lets you run workflows when other events happen in your repository. For example, you can run a workflow to automatically add the appropriate labels whenever someone creates a new issue in your repository.

GitHub provides Linux, Windows, and macOS virtual machines to run your workflows, or you can host your own self-hosted runners in your own data center or cloud infrastructure.

Why use it?
GitHub Actions makes it easy to automate all your software workflows, now with world-class CI/CD. Build, test, and deploy your code right from GitHub. Make code reviews, branch management, and issue triaging work the way you want.

Let’s do it
Need to generate Github’s Personal access token (PAT) first
Go to your Github account -> https://github.com/settings/profile, then to

Developer settings -> Generate new token


Provision of self-hosted runner to k8s
I will use Dockerfile for self-hosted runner from this repo: Github self-hosted

by Sander Knape, https://sanderknape.com/2020/03/self-hosted-github-actions-runner-kubernetes/

Validation of PAT by running self-hosted runner as docker container
docker run --name github-runner \
     -e GITHUB_OWNER=warolv \
     -e GITHUB_REPOSITORY=github-actions-series \
     -e GITHUB_PAT=YOUR_GITHUB_PAT \
     sanderknape/github-runner
I am using my Github account for testing: warolv, repo is ‘github-actions-series’ and PAT we generated previously


Go to your Github repo -> settings -> Actions -> runners, you will see new self-hosted runner:


self-hosted runner is connected to Github and ready to do the job, looks good:-)

Next step will be to deploy it to k8s.

I will use my ‘kind’ k8s cluster for demo:

https://kind.sigs.k8s.io/

kind create cluster
Now let’s actually provision self-hosted runner to k8s

First clone my repo: git clone git@github.com:warolv/github-actions-series.git

Creating of k8s secret with PAT in namespace: ‘github-runner’

# create github-runner namespace
kubectl create ns github-runner

# create secret from PAT we got previously
kubectl create secret generic gh-pat \
    -n github-runner \
    --from-literal=pat=YOUR_GITHUB_PAT
Overview of manifests for deployment
gr-deployment.yaml (self-hosted-runner/gr-deployment.yaml in cloned repo)

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: github-runner
  namespace: github-runner
  labels:
    app: github-runner
spec:
  replicas: 1
  selector:
    matchLabels:
      app: github-runner
  template:
    metadata:
      labels:
        app: github-runner
    spec:
      serviceAccountName: gr-sa
      containers:
      - name: github-runner
        image: sanderknape/github-runner:latest
        env:
        - name: GITHUB_OWNER
          value: warolv
        - name: GITHUB_REPOSITORY
          value: github-actions-series
        - name: RUNNER_LABELS
          value: self-hosted-runner
        - name: GITHUB_PAT
          valueFrom:
            secretKeyRef:
              name: gh-pat
              key: pat
        lifecycle:
          postStart:
            exec:
              command: ["sh", "-c", "install kubectl..."]

```

For deployment of self-hosted runner to k8s, you need to set proper values for:

GITHUB_OWNER: warolv in my case
GITHUB_REPOSITORY: [ github-actions-series], for my demo
RUNNER_LABELS: [ self-hosted-runner ], used in workflow
GITHUB_PAT: taken from k8s secret we created previously
Also we installing ‘kubectl’ to existing runner using ‘lifecycle poststart’ hook, we need kubectl to redeploy Nginx on configuration change.

PostStart

The PostStart hook is called immediately after a container is created. This occurs as it transitions into the Running phase after its Waiting period.

gr_sa.yaml is a service account which will be attached to runner, in order to have permissions for redeploying Nginx.

```
apiVersion: v1
kind: ServiceAccount
metadata:
  name: gr-sa
  namespace: github-runner
gr-cluster-role.yaml and gr-cluster-role-binding.yaml is a binding of needed permissions to ‘gr-sa’ service account.

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-handler
rules:
- apiGroups: ["apps"]
  resources: ["pods", "deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pod-handler-binding
  namespace: github-runner
roleRef: 
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pod-handler 
subjects:
- kind: ServiceAccount
  name: gr-sa
  namespace: github-runner
```

Let’s deploy all needed manifests in self-hosted-runner folder
```
kubectl apply -f self-hosted-runner

```


Validate self-hosted-runner is running and connected
kubectl get pods
github-runner-58855b59b6-l87sv   1/1     Running   0          165m

kubectl logs github-runner-58855b59b6-l87sv


Add Github Workflow to redeploy Nginx on configuration change
Last step actually would be to create workflow with Github Actions to redeploy Nginx server on configuration change, when nginx/deployment.yaml is changed, committed and pushed to repo.

.github/workflows/nginx_redeploy.yaml

name: Redeploy nginx after changes in deployment.yaml
on:
  push:
    paths:
      - nginx/**

jobs:
  redeploy-nginx:
    runs-on: self-hosted-runner
    steps:
      - uses: actions/checkout@v3
      - name: Redeploy nginx
        run: |
          kubectl apply -f nginx/deployment.yaml
I use ‘paths:’ to make sure Nginx will be redeployed only if nginx/deployment.yaml is changed.

To actually apply changes I use ‘kubectl apply -f nginx/deployment.yaml’, kubectl was installed into runner as I explained previously.

Now each commit with a change of nginx/deployment.yaml which pushed, will redeploy Nginx (In this example I changed number of replicas to 2 replicas) :



You can get all tutorials for Github Actions from my Github repo by cloning it: ‘git clone https://github.com/warolv/github-actions-series.git‘

I also will create Youtube video for this tutorial on my YT channel: https://www.youtube.com/@igorzhivilo, please subscribe!

Conclusion
In this tutorial, I explained how to deploy self-hosted-runner to Kubernetes and connect it with your GitHub repo, and how to redeploy Nginx server on configuration change with Git, the GitOps way.

Thank you for reading, I hope you enjoyed it, see you in the next post.

If you want to be notified when the next post of this tutorial is published, please follow me here on medium, Twitter (@warolv) and my YT channel.
