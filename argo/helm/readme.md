
##
#
https://spacelift.io/blog/argocd-helm-chart
#
##

General
How to Deploy Helm Charts with Argo CD [Tutorial]

How to Deploy Helm Charts with Argo CD [Tutorial]
James Walker
12 Feb 2024
·
14 min read
Reviewed by: 
Flavius Dinu
argocd helm chart
Argo CD is a continuous delivery (CD) tool for Kubernetes. It automates the process of deploying apps into your cluster by offering a declarative, GitOps-driven configuration process.

Using Argo helps you deploy your workloads more quickly and reliably. However, you still need to prepare your apps before Argo can install them.

Helm charts are a popular way to package, share, and configure software in Kubernetes. Creating a Helm chart allows users to deploy your project to their clusters without being exposed to the details of your Kubernetes manifest files.

In this article, we’ll explain how to use Argo CD to automatically deploy Helm charts using GitOps, providing maximum simplicity and automation for your Kubernetes operations.

We will cover:

What is ArgoCD?
What are Helm charts?
How to use Argo CD with Helm charts
Example – Using ArgoCD to deploy Helm charts
What is the difference between Helm and Argo CD?
What is Argo CD?
Argo CD is a pull-based GitOps tool for continual delivery to Kubernetes clusters. Argo runs inside your cluster and connects to your source repositories. It automatically detects changes you make to your Kubernetes resource definitions (such as manifest files and Helm charts) and syncs them to your cluster.

Argo uses declarative configuration to understand the desired state of your deployments. The resources in your Git repository declare this state; Argo then automates the process of adding, altering, and removing Kubernetes cluster objects to achieve it. Argo can prevent configuration drift by continually resyncing your cluster objects to the configuration declared in your repository, ensuring unintentional changes are quickly reversed.

What are Helm charts?
Helm charts package Kubernetes configurations. At their simplest, they’re a collection of Kubernetes manifest files that define the cluster objects required by a particular app. Helm automates the process of creating all the objects when you deploy the chart to your cluster, then manages the deployment through its life.

Charts provide Kubernetes package management, versioning, and dependency resolution capabilities. Helm charts can reference each other, are easy to upgrade, and are frequently published to centralized repositories—similar to operating system packages and programming language dependencies.

Helm also provides important customization options, including chart variables that users can override during deployments. You could configure your chart to use variables for the image tag, replica count, and CPU/memory constraints, for example, allowing users to set those values for their installation without having to manually edit the manifests that form the chart.

How to use Argo CD with Helm charts
Argo CD has built-in support for deploying Helm charts to your cluster. They’re fully compatible with Argo’s GitOps workflows, CLI, UI, and API.

Installing a Helm chart with Argo
Installing a Helm chart with Argo has slightly different effects compared to when Helm is used directly. Argo only uses the Helm chart to determine which objects should be created in the cluster; it then creates and manages the objects itself without using Helm. This ensures the app’s lifecycle can be fully administered within Argo CD.

The installation process therefore works as follows:

Argo inflates the Helm chart using the standard Helm templating system (helm template command). — This produces the final Kubernetes manifest to install, with all variable values, function calls, and file includes resolved.
Argo installs the generated manifest as a regular Argo deployment. — This creates the Kubernetes objects in your cluster and makes the app visible in Argo, ready for you to administer and sync new changes to.
The model means Helm chart deployments behave identically to other types of Argo app, but it also prevents you from using the regular Helm CLI to interact with your workloads. Because Helm isn’t used to make the deployments, apps installed through Argo won’t show up in commands such as helm list. Argo CD’s own declarative approach to configuration, using Argo app manifests, also overlaps with some of the functionality available in Helm charts.

Using Helm values with Argo CD
Argo lets you pass values through to your Helm chart using either the Argo CLI or the source.helm field in your Argo app manifest, which supports values, valueFiles, and valueObjects keys:
```
source:
  helm:
    valuesObject:
      replicaCount: 2
The example above is equivalent to using the Helm CLI with a values.yml file that has the following content:

replicaCount: 2
Argo also supports Helm parameters that are equivalent to the --set Helm CLI flag:

source:
  helm:
    parameters:
      - name: replicaCount
        value: 2
  ```
  
This results in Argo running helm template . --set replicaCount=2 to generate your deployment’s final manifest file from the Helm chart. Parameters can also be set via the CLI using --parameter key=value syntax.

Converting Helm hooks to Argo CD
Hooks are an advanced Helm mechanism for performing operations in response to certain events occurring in your chart. Pre-install, post-install, and post-upgrade hooks, for example, can be used to set up default configurations or migrate old resources after a new release is deployed.

Argo has its own hook system with similar effects to Helm hooks. If you use Helm hooks in your charts, then Argo will automatically map them to their Argo counterparts. However, not all Helm hooks are supported; those that are may exhibit behavioral differences due to how Argo implements GitOps and manages your deployments, so you should review the documentation to check your hook will function correctly.

💡 You might also like:

16 DevOps Best Practices to Follow
Why Generic CI/CD Tools Will Not Deliver Successful IaC
Common Infrastructure Challenges and How to Solve Them
Example - Using ArgoCD to deploy Helm charts
Let’s run through a simple example of how to deploy a Helm chart to Kubernetes using Argo CD. To follow along, you’ll need access to an existing Kubernetes cluster with Argo CD already installed and connected to the Argo CLI. You can find detailed setup steps in our ArgoCD getting started guide.

There are two main techniques for deploying a Helm chart with Argo:

Deploy a chart stored in a Git repository. This is typically the approach used when you’re authoring a Helm chart for your projects and you want to deploy it using Argo.
Directly deploy a chart from a Helm repository. This is ideal to quickly launch a deployment of a third-party service that’s provided a Helm chart for you to use.
We’re going to focus on deploying your own charts from Git repositories, but we’ll briefly show how to deploy from a Helm repo later in this section.
```
1. Create your Helm chart
Begin by heading to GitHub and creating a new repository to contain your Helm chart. Afterward, clone the repository to your machine:

$ git clone https://github.com/<username>/<repo>.git
$ cd <repo>
Next, use the helm create command to scaffold your Helm chart. We’re calling our chart demo-app:

$ helm create demo-app
Creating demo-app
Your repository will now have a new demo-app subdirectory that contains a basic Helm chart structure:

$ tree
.
└── demo-app
    ├── Chart.yaml
    ├── charts
    ├── templates
    │   ├── NOTES.txt
    │   ├── _helpers.tpl
    │   ├── deployment.yaml
    │   ├── hpa.yaml
    │   ├── ingress.yaml
    │   ├── service.yaml
    │   ├── serviceaccount.yaml
    │   └── tests
    │       └── test-connection.yaml
    └── values.yaml
```
4 directories, 10 files
This basic chart is adequate for our demonstration purposes. In its default configuration, it’ll create an NGINX Deployment in your cluster, along with an accompanying Service. However, a few minor changes are required to correctly configure the namespace for the created resources.

Open up the templates/deployment.yaml, templates/service.yaml, and templates/serviceaccount.yaml files and add the namespace field within the metadata section of each resource. The result should look similar to the following in each case:
```
metadata:
  name: {{ include "demo-app.fullName" . }}
  namespace: {{ .Values.namespace }}
    labels:
      # ...
```
Next, commit and push your chart to GitHub, ready to deploy using Argo:
```
$ git add .
$ git commit -m "Add initial Helm chart"
$ git push
2. Deploy your chart with Argo
Now you can use the Argo CLI to deploy your chart into your Kubernetes cluster:

$ argocd app create demo-app \
	--repo https://github.com/<username>/<repo>.git \
	--path demo-app \
	--dest-server https://kubernetes.default.svc \
	--dest-namespace demo-app \
	--sync-option CreateNamespace=true \
	--parameter namespace=demo-app \
application 'demo-app' created
Here’s what each of the flags is for:

--repo — Specifies the path to the Git repository that contains your chart.
--path — Specifies the chart’s directory path within the Git repository.
--dest-server — The URL of the Kubernetes cluster to deploy to, which is https://kubernetes.default.svc if you’re deploying to same the cluster that Argo is installed in.
--dest-namespace — The name of the Kubernetes namespace for the app.
--sync-option CreateNamespace=true — Opt-in to Argo automatically creating the Kubernetes namespace for you.
--parameter namespace=demo-app — The --parameter flag passes values down to the Helm templating process. This populates the namespace fields that we added to the chart’s manifests in the previous step.
```


Your app should now appear when running argocd app list:
```
$ argocd app list
NAME             CLUSTER                         NAMESPACE  PROJECT  STATUS     HEALTH   SYNCPOLICY  CONDITIONS  REPO                                                   PATH      TARGET
argocd/demo-app  https://kubernetes.default.svc  demo-app   default  OutOfSync  Missing  <none>      <none>      https://github.com/ilmiont/spacelift-argocd-helm-demo  demo-app
```


It’ll also be presented in the Argo web UI:

argocd helm chart example
The app shows as Missing and Out of Sync. So far, we’ve only registered the app with Argo; a separate sync operation is required to actually create the resources in your Kubernetes cluster. Press the Sync or Sync Apps button in the UI, or use the argocd app sync command, to start your initial sync.

$ argocd app sync demo-app
...
GROUP  KIND            NAMESPACE  NAME      STATUS  HEALTH       HOOK  MESSAGE
       ServiceAccount  demo-app   demo-app  Synced                     serviceaccount/demo-app created
       Service         demo-app   demo-app  Synced  Healthy            service/demo-app created
apps   Deployment      demo-app   demo-app  Synced  Progressing        deployment.apps/demo-app created
The objects defined by the Helm chart will be added to your cluster. The app’s status should transition to Healthy and Synced in Argo:

argocd helm chart github
Clicking the app’s card in the web UI allows you to easily inspect the components in the chart. You can also see the relationships between them and take action to force a resync or rollback. These operations can also be achieved using the CLI.

argocd install helm chart
You can now update your deployment by modifying your Helm chart, pushing the changes to GitHub, and initiating a resync within Argo.

3. Use the web UI to deploy a Helm chart
Helm chart applications can also be created using the Argo web UI, without any CLI interactions. Click the New App button on the home screen and fill out the app’s basic details:

argocd deploy helm chart
Next, scroll down to the Source section. Enter the URL of your GitHub repository and then the path to your Helm chart.

argocd helm chart application
Finally, scroll down the page and finish configuring your app by setting the destination Kubernetes cluster and the directory options to apply. Then you can create your app by pressing the Create button at the top of the flyout.

4. Deploy charts from Helm repositories
As we mentioned earlier, Argo can also deploy charts directly from Helm repositories. To achieve this, change the Repository type dropdown value to “Helm,” then enter the URL to the repository the chart resides in.

Afterward, enter the target chart’s name and version into the inputs at the bottom of the panel:

argocd local helm chart
Helm chart URLs can also be deployed using the Argo CLI:
```
$ argocd app create cert-manager \
	--repo https://charts.jetstack.io \
	--helm-chart cert-manager \
	--revision 1.13 \
	--dest-server https://kubernetes.default.svc
application 'cert-manager' created
```
The --repo, --helm-chart, and --revision flags are used to specify the Helm repository, chart name, and chart version respectively.

Once your app’s been created, you can sync it in the same way as Git repositories. Argo will fetch any chart updates directly from the Helm repo, then apply them to your Kubernetes cluster.

5. Deploy apps with multiple Helm charts
In practice, many applications are deployed using multiple Helm charts. For example, a microservices architecture could be formed from hundreds or thousands of distinct components defined across several independent charts. Yet a successful deployment will require every chart to be installed in your cluster in the correct order.

Argo CD makes it easy to orchestrate this process. Your apps can reference multiple sources, allowing you to install several Helm charts from different Git and Helm repositories. You can then define their installation order using Argo’s sync waves, a mechanism for running operations sequentially during a sync.

By default, all cluster objects are created in a single wave—wave 0—but you can assign operations and hooks to a different wave using the argocd.argoproj.io/sync-wave annotation in your Argo app’s config manifest:

metadata:
  annotations:
    argocd.argoproj.io/sync-wave: “3”
This example means the annotated object won’t be synced until the operations in the earlier waves have completed. Waves don’t begin until every object from the previous wave has synced and is healthy, so it’s possible your sync will get stuck if an earlier wave can’t finish due to an error.

Sync waves allow you to implement complex dependency-driven workflows for apps with multiple charts and components. You can learn more about using them in the Argo documentation, in addition to other sync features, such as selective sync, which lets you deploy a subset of resources from a multi-component app.

What is the difference between Helm and Argo CD?
There’s no either/or for Argo CD and Helm Charts: these tools complement each other and are often used together. If you’re working with Kubernetes, then combining Argo and Helm is a valuable strategy to both simplify resource configuration and automate deployment.

Writing Helm charts for your apps makes it easier to handle multiple deployments and share your configuration with others. Installing apps using Helm lets you benefit from its automatic lifecycle management while providing opportunities to customize your deployment via chart variables and templates.

Argo offers additional convenience by automating chart deployments using GitOps. This prevents configuration drift, aids versioning of environments, and improves deployment safety.

Key points
We’ve explored the features of Argo CD and Helm charts, then shown how to combine them to automate your Kubernetes app deployments. Creating a Helm chart makes it easier to share and install Kubernetes workloads, while Argo CD provides declarative GitOps-powered syncs that automatically update your cluster’s state so it matches the contents of your charts.

Although Argo CD is easy to use, it’s a powerful tool with plenty of options and tool integrations available. If you’re not using Helm yet, then you can also deploy plain Kubernetes manifests or Kustomize apps instead. Check out the docs to learn what’s possible, or try reading our guide to best practices for CI/CD and Kubernetes.

We encourage you also to try Spacelift’s CI/CD platform to collaborate on infrastructure using multiple IaC providers, including Kubernetes, Ansible, and Terraform. Spacelift lets you visualize your resources, prevent drift, and help developers ship fast within precise policy-driven guardrails. You can check it for free, by creating a trial account or booking a demo.
