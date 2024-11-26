

Github Self-Hosted Runners on Kubernetes with Actions Runner Controller
Karan Thakur
mossfinance
Karan Thakur

##
#
https://medium.com/mossfinance/github-self-hosted-runners-on-kubernetes-with-actions-runner-controller-41e30c4cb76e
#
##




In the software delivery process, CI/CD plays an important role in achieving pace. One of the most adopted CI/CD platforms is Github actions which helps us to create workflows to build & deploy the applications.

At Moss, we use Github for hosting our code so using github actions for CI/CD is a natural choice. Before diving deep into self-hosted runners let’s briefly introduce GitHub Actions. GitHub Actions is a CI/CD platform that works on a “choose-your-own-adventure” approach meaning the flexibility to use community-shared actions or write your own actions using any supported language.

Writing a workflow is quite easy:
```
on:
  pull_request:

jobs:
  build: 
    runs-on: ubuntu-latest
    steps:
      - run: echo "Hello build!"
```


It looks simple enough but where are these steps executed? On entities known as runners.

By definition — “The runner is the application that runs a job from a GitHub Actions workflow. It is used by GitHub Actions in the hosted virtual environments, or you can self-host the runner in your own environment”

In the above example workflow runs-on: ubuntu-latest flag states to run the job on GitHub hosted Ubuntu machine with the newest stable OS version available.

There are two types of Runners
GitHub-hosted: These are virtual machines hosted by GitHub. They’re convenient because they are fully managed by GitHub, saving developers the hassle of setup and maintenance. They come with a broad range of developer tools pre-installed.
Self-hosted: These are user-provisioned machines that are set up by the users themselves. They offer more flexibility and control over the environment, including specific hardware, software, and network configurations.
You might be having a thought that while GitHub-hosted runners are convenient, why might one opt for self-hosted runners? Moss is a regulated payment institution so data confidentiality & security play an important role for us. There are other reasons as well like full control over the build environment, Internal network access, specific OS versions or pre-installed applications, etc.

For these requirements, we had to set up a few VMs when it was necessary for a particular workflow. It fulfilled our requirements but there were some drawbacks.

We have to bake and maintain our runner image
Update installed tools regularly
Take care of caching and cleanup of job data
Auto-scaling of VM instances is a challenge because either we need to keep the VMs overprovisioned, which leads to a waste of resources or we keep them underprovisioned, which leads to slow builds and poor developer experience
To address these concerns, we considered running GitHub Actions within our own Kubernetes cluster rather than on a VM. Running workloads on a Kubernetes cluster brings its own perks like scalability, resource efficiency, and more control over security, network policies, and other configurations.

So how do we deploy Github Actions on the Kubernetes cluster? Here comes the Actions Runner Controller(ARC). ARC makes it simpler to run self-hosted environments on Kubernetes clusters. With ARC we can:

Deploy self-hosted runners on the Kubernetes cluster.
Auto-scale runners based on demand.
Setup across repository or organization
How to setup ARC

Actions Runner Controller
We will use Helm to install the ARC operator and configure it. One of the prerequisites of ARC is to use cert-manager. ARC uses cert-manager for certificate management of Admission Webhook.

Install cert-manager
```
  helm repo add jetstack https://charts.jetstack.io

helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.12.4 \
   --set installCRDs=true
GitHub Authentication
There are two ways to authenticate with Github via the GitHub App & using PAT (Personal Access Token). We will use Github App. Follow the steps given in Github doc and create a k8s secret with the generated app-id, installation-id, and private-key.

kubectl create secret generic controller-manager -n actions-runner-system 
--from-literal=app-id=<APP_ID>
--from-literal=installation-id=<INSTALLATION_ID>
--from-literal=private-key=<PRIVATE_KEY>

```

Install ARC
Next, install the helm chart for the actions-runner-controller. We have to update default values from the helm chart and also have to add env variables referenced from the created secret that will be used for GitHub authentication.

```
helm repo add actions-runner-controller https://actions-runner-controller.github.io/actions-runner-controller


helm upgrade --install --namespace actions-runner-system --create-namespace -f values.yaml \
             --wait actions-runner-controller actions-runner-controller/actions-runner-controller
# values.yaml

certManagerEnabled: true

scope:
  singleNamespace: false

# disabling authSecret as we already created
authSecret:
  enabled: false

githubWebhookServer:
  enabled: false

env:
  - name: GITHUB_APP_ID
    valueFrom:
      secretKeyRef:
        key: APP_ID
        name: controller-manager
  - name: GITHUB_APP_INSTALLATION_ID
    valueFrom:
      secretKeyRef:
        key: INSTALLATION_ID
        name: controller-manager
  - name: GITHUB_APP_PRIVATE_KEY
    valueFrom:
      secretKeyRef:
        key: PRIVATE_KEY
        name: controller-manager

```
after helm chart installation below resources will be created


We can also verify controller logs

# Log for the controller manager

2023-09-14T21:12:12Z INFO starting manager
2023-09-14T21:12:12Z INFO controller-runtime.webhook.webhooks Starting webhook server
2023-09-14T21:12:12Z INFO controller-runtime.certwatcher Updated current TLS certificate
2023-09-14T21:12:12Z INFO controller-runtime.webhook Serving webhook server {"host": "", "port": 9443}
2023-09-14T21:12:12Z INFO Starting server {"path": "/metrics", "kind": "metrics", "addr": "127.0.0.1:8080"}
2023-09-14T21:12:12Z INFO controller-runtime.certwatcher Starting certificate watcher
I0914 21:12:12.457459       1 leaderelection.go:248] attempting to acquire leader lease actions-runner-system/actions-runner-controller...
I0914 21:12:12.466213       1 leaderelection.go:258] successfully acquired lease actions-runner-system/actions-runner-controller
With the controller successfully set up, we can now proceed to establish the runners. There are two CRDs for this purpose: RunnerDeployment and RunnerSet. A key feature distinction between them is that RunnerSet allows for the use of persistent volumes for caching. Internally, RunnerSet is based on Kubernetes’ StatefulSet and supports all features of a stateful workload. Since we do not plan to use persistent volumes for our runners, we will opt for RunnerDeployment. We have the option to install the runner at either the repository level or the organization level, or both.

Install Runner at the repository level

```
# runnerdeployment.yaml
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: arc-runner
  namespace: actions-runner-system
spec:
  replicas: 2 # This will deploy 2 runners
  template:
    spec:
      repository: getmoss/demo-repo # specify name of the repository
      labels:
        - arc-runner-repo # runner label
Install Runner at the org level
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: arc-runner
  namespace: actions-runner-system
spec:
  template:
    spec:
      ephemeral: true # runner will be destroyed after completion of the job
      dockerEnabled: false
      organization: getmoss  # specify name of the organization
      labels:
        - arc-runner-org # runner label

```


-- log for started runner

2023-09-13 11:27:45.84  NOTICE --- Runner init started with pid 7
2023-09-13 11:27:45.90  DEBUG --- Github endpoint URL https://github.com/
2023-09-13 11:27:47.249  DEBUG --- Passing --ephemeral to config.sh to enable the ephemeral runner.
2023-09-13 11:27:47.279  DEBUG --- Configuring the runner.
# Authentication
√ Connected to GitHub
# Runner Registration
√ Runner successfully added
√ Runner connection is good
2023-09-13 11:27:54.84  DEBUG --- Runner successfully configured.
√ Connected to GitHub
Current runner version: '2.309.0'
2023-09-13 11:27:56Z: Listening for Jobs
Using in a workflow
we have seen an example workflow at first which runs on GitHub hosted runner. We just have to update the label to run it on the self-hosted runner

on:
  pull_request:

jobs:
  build: 
    runs-on: arc-runner-org # label of org runner
    steps: 
      - run: echo "Hello build!"
when this job is executed we can verify runner details on the GitHub actions console

Current runner version: '2.309.0'
Runner name: 'arc-runner-klwl7-lzskj'
Runner group name: 'Default'
Machine name: 'arc-runner-klwl7-lzskj'

A job started hook has been configured by the self-hosted runner administrator
Run '/etc/arc/hooks/job-started.sh'
2023-09-14 14:23:51.363  DEBUG --- Running ARC Job Started Hooks
2023-09-14 14:23:51.366  DEBUG --- Running hook: /etc/arc/hooks/job-started.d/update-status
Autoscaling Runners
Rather than using a fixed number of replicas, we can implement autoscaling based on either pull-based scaling metrics or webhook events. The pull-based strategy might lead to API rate limit concerns due to its frequent API requests. Autoscaling through webhook events is preferred since the Autoscaling Resource Controller (ARC) is instantly notified of the scaling need.

Webhooks are processed by a separate webhook server. The webhook server receives workflow_job webhook events and scales RunnerDeployments / RunnerSets by updating HRAs configured for the webhook trigger.

To configure autoscaling first we need to enable the webhook server and define HorizontalRunnerAutoscaler CR that will do all the heavy lifting.

update values.yaml file and run helm upgrade command for actions-runner-controller release

githubWebhookServer:
  enabled: true
The helm upgrade command will create a new deployment and a service for receiving Github Webhooks. Now we need to expose this service so that GitHub can send these webhooks over the network with TLS protection. The preferred way to do it is via configuring an Ingress.

Ingress for GitHub Webhooks
# arc-webhook-server.yaml
# kubectl apply -n actions-runner-system -f arc-webhook-server.yaml
```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: actions-runner-controller-github-webhook-server
  namespace: actions-runner-system
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - your.domain.com # name of your domain
      secretName: {{ .Values.secretCertificate }}
  rules:
    - host: your-tls-secret-name # certificate for the domain
      http:
        paths:
          - pathType: Prefix
            path: /actions-runner-controller-github-webhook-server
            backend:
              service:
                name: actions-runner-controller-github-webhook-server
                port:
                  number: 80

```

add HorizontalRunnerAutoscaler targeting the runner
# arc-runner-hra.yaml
# kubectl apply -n actions-runner-system -f arc-runner-hra.yaml

apiVersion: actions.summerwind.dev/v1alpha1
kind: HorizontalRunnerAutoscaler
metadata:
  name: arc-runner-hra
  namespace: actions-runner-system
spec:
  minReplicas: 1
  maxReplicas: 10
  scaleTargetRef:
    kind: RunnerDeployment
    name: arc-runner
  scaleUpTriggers:
    - githubEvent:
        workflowJob: {}
      duration: "30m" # maximum amount of time to wait for a scale-down event
After applying, verify the configured HorizontalRunnerAutoscaler

❯ kubectl get HorizontalRunnerAutoscaler -n actions-runner-system                                                                                                                              ⎈ tf-gke-cluster-staging
NAME             MIN   MAX   DESIRED   SCHEDULE
arc-runner-hra   1     10    1
when the webhook server receives workflow_job webhook events it scales up the runner count and upon receiving completion scales down.

# logs from webhook server

2023-09-14T13:31:01Z DEBUG controllers.webhookbasedautoscaler Found 1 HRAs by key {"key": "getmoss"}
2023-09-14T13:31:01Z DEBUG controllers.webhookbasedautoscaler job scale up target found {"event": "workflow_job", "hookID": "431019267", "delivery": "f1911040-5302-11ee-9d09-0be13b8df476", "workflowJob.status": "queued", "workflowJob.labels": ["arc-runner-org"], ...}
2023-09-14T13:31:01Z INFO controllers.webhookbasedautoscaler scaled arc-runner-hra by 1 {"event": "workflow_job", "hookID": "431019267", "delivery": "f1911040-5302-11ee-9d09-0be13b8df476", "workflowJob.status": "queued", "workflowJob.labels": ["arc-runner-org"], ...}
Conclusion
The Actions Runner Controller is a powerful tool that can help you improve your GitHub Actions workflows. It simplifies the management of runners by automating tasks such as the creation, scaling, and deletion of runners. It also provides an easy way to create and manage runners in a Kubernetes cluster. By using Actions Runner Controller for Self-Hosted Runner, you can take full advantage of the power of GitHub Actions while having full control over your infrastructure. Keep in mind that self-hosted runners save costs on GitHub Action minutes but consume cloud resources. An overview of the cost-benefit analysis would be valuable.

