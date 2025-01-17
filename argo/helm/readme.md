
##
#
https://spacelift.io/blog/argocd-helm-chart
#
https://akuity.io/blog/argo-cd-helm-values-files
#
https://medium.com/yotpoengineering/argo-cd-applicationset-and-helm-custom-plugin-challenges-and-solutions-2e23fd495c67
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


##
##


Supplying Custom Values Files to Helm Charts in Argo CD
In this blog post, we will dive into a common challenge developers face when using Argo CD — an innovative Kubernetes application deployment and management tool. We'll explore how to supply custom values files to a Helm chart sourced from a Helm chart repository within an Argo CD application. This situation arises when you want to use a Helm chart that you don't maintain but need to override some default values with your own custom ones managed in a Git repository, following GitOps practices.

Before we dive into the solutions, we invite you to check out our free course on GitOps and Continuous Delivery. Developed by the founders of the Argo Project, this course offers hands-on experience in implementing these practices with Argo CD.

Check out our Youtube video for an in-depth look with demos of the solutions presented in this blog post.



Understanding the Challenge
The challenge we face is sourcing a Helm chart from a Helm chart repository and custom values from a Git repository simultaneously. We'll look at three common solutions to tackle this problem, each with pros and cons. Let's explore each approach in detail:

Solution 1: Helm Umbrella Chart
The first solution involves creating a Helm umbrella chart that includes the Helm chart from the repository as a dependency. The custom values are then maintained in the same Git repository as this umbrella chart. This approach allows you to source the Helm chart and values files from Git within an Argo CD Application.

Helm Umbrella chart.yaml.

It's important to note that any values you want to supply to a chart dependency must be under a top-level key in the values files with the same name as the Helm chart dependency. In our example chart YAML, we've got a dependency named hello-world; in the values files, it's got hello-world as the top-level key.

Helm Values for an Umbrella Chart.

However, the downside with this approach is that if all three of my applications are tracking the same revision of my Git repository and then, therefore, the same revision of the Helm umbrella chart, when I update the dependency in the chart, YAML, it will affect all three applications.

Argo CD Apps with sync status unknown due to broken umbrella chart.

Solution 2: App of Apps Pattern with Values in Application Manifest
The second solution is to place the custom values directly in the Application manifest instead of separate values files. This approach works well when adopting the App of Apps pattern for managing your Application manifests in Git. It allows you to pass the Helm values directly to the chart hosted in the Helm chart repository while keeping the values in Git. This provides GitOps for the entire application and allows each Application variation to have a different target revision of the Helm chart.

An Argo CD Application manifest with Helm Values.

Solution 3: Multiple Sources for Applications (Beta Feature)
The final solution utilizes the Multiple Sources for Applications beta feature introduced in Argo CD version 2.6. This allows you to specify multiple sources for the Application manifest, including Helm chart repositories and Git repositories for values files. This approach combines the benefits of using the Helm chart repository and Git for custom values, enabling easier management of applications with distinct target revisions for different environments.

An Argo CD Application manifest using the multiple sources feature.

Conclusion
Choosing the right approach depends on your specific requirements and preferences. While the Helm umbrella chart solution might be the most elegant currently, the Multiple Sources for Applications feature shows promise for the future. It's vital to consider factors like application complexity, versioning, and ease of management when making your decision.

Thank you for reading our blog post! We invite you to check the Akuity YouTube channel for more Argo CD-related content and insights. Happy syncing!

##
##


Argo CD: ApplicationSet and Helm custom plugin — challenges and solutions
Yakir Levi
Yotpo Engineering
Yakir Levi

·






3 months ago at Yotpo, we decided to go all in on Argo CD as our deployment tool for our hundreds of microservices. The goal was to eventually replace our Jenkins server.

Along the way, we found that Argo CD and ApplicationSet are generic and flexible tools, which can be easily adopted without making big changes.

In our case, we ended up migrating from Jenkins to Argo CD with zero changes to the way the engineers work.

In this post you’ll learn:
How to write a Helm plugin to fit your use case— in our case, this was solving a limitation where the Helm chart and the Helm values files needed to be in the same repository
How to deploy multiple Argo CD applications using a single ApplicationSet YAML file
You can find the full YAMLs example in the following Git Repo.

As we move forward, I’ll assume that if you’re reading this blog you’re already familiar with the Argo CD Application CRD and Helm.

Migration challenges
Right from the start we had to address a number of challenges:

In the current Argo CD version (2.3), the Helm chart and Helm values files needed to be in the same repository, and at Yotpo we store our Helm charts on ChartMuseum and our Helm values on GitHub.
During the deployment, when we call the Argo CD Helm plugin we need to pass additional variables (namespace, chart version, etc.), to build the Helm CLI command. The problem is that the current Argo CD Helm plugin doesn’t support it.
When a new values file is pushed to the developer’s Git repository, we need Argo CD to detect it and deploy it automatically.
Helm plugin
Before we begin, I will explain how we deployed the Helm values files before Argo CD.

Yotpo helm values files structure
In the very beginning, when we started using Helm as the deployment tool for Kubernetes, we had to think of where to store all the necessary information to build the Helm CLI install command for every Helm values file.

The solution we chose was to add one more section to every values file, which included all the necessary information to build the Helm CLI install command. The motivation was that the developer can control all aspects of the deployment using a single file.

yotpo:
 chartName: bitnami/wordpress
 chartPath: https://charts.bitnami.com/bitnami
 deploymentName:  my-release
 chartVersion: 14.2.6
 namespace: infra
Before Argo CD, we used Jenkins to parse this section and then run the relevant Helm install command.

helm upgrade --version 14.2.6 --namespace infra --install --values values.yaml my-release bitnami/wordpress
When we migrated to Argo CD, we wanted to preserve this behavior.

Helm plugin to support charts and values files from different repositories
In order to be able to use Argo CD with Helm charts and values files in different locations (basic usage in our opinion), we had to write a very simple Helm plugin named “helm-yotpo” and add it to the relevant section in the ArgoCD Helm value file.

```
server:
 name: server
 config:
   configManagementPlugins: |
       - name: helm-yotpo
         generate:
           command: ["sh", "-c"]
           args: ["helm template --version ${HELM_CHART_VERSION} --repo ${HELM_REPO_URL} --namespace ${NAMESPACE}  $HELM_CHART_NAME --name-template=${HELM_RELEASE_NAME} -f $(pwd)/${HELM_VALUES_FILE} "]
Once we’d added the Helm custom plugin to the Argo CD server configuration, we created the following the Argo CD Application CRD:

---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
 name: application-test
 namespace: infra
spec:
 destination:
   namespace: infra
   server: https://kubernetes.default.svc
 project: infra
 source:
   path: "helm-values-files/telegraf"
   repoURL: https://github.com/YotpoLtd/argocd-example.git
   targetRevision: HEAD
   plugin:
     name: helm-yotpo
     env:
       - name: HELM_RELEASE_NAME
         value: "telegraf-test"
       - name: HELM_CHART_VERSION
         value: "1.8.18"
       - name: NAMESPACE
         value: "infra"
       - name: HELM_REPO_URL
         value: "https://helm.influxdata.com/"
       - name: HELM_CHART_NAME
         value: "telegraf"
       - name: HELM_VALUES_FILE
         value: "telegraf.yaml"

```

The interesting part of the YAML is the “plugin” section. In that section we call our “helm-yotpo” plugin and pass it our environment variables, in order to build the Helm CLI command.

Once we deploy this Application CRD, the Helm plugin will run the following Helm template command:

helm template --version 1.8.18 --repo https://helm.influxdata.com/
 telegraf --namespace infra --name-template=telegraf-test
 -f $(pwd)/telegraf.yaml
After deploying the ArgoCD Application CRD, you can see it in the Argo CD UI:


Argo CD UI: Application tile with the custom plugin

Argo CD UI: Application resources
So finally we’ve achieved the Helm chart and Helm value on different repositories, and we can customize the Helm template command using additional variables.

ArgoCD: one ApplicationSet to rule them all
At Yotpo, a single repository can include dozens and sometimes hundreds of value files (Java applications, Kafka consumers, Prometheus exporters, etc. ) that need to be deployed. Once we’d achieved our core goal, we realized that the Argo CD Application CRD was not enough.

It’s not scalable enough to create hundreds of Application CRDs for every repository. In fact it will create a lot of work to migrate one repository, and every time a developer adds a new values file to their repository they’ll need us to create one more Application CRD to deploy in using Argo CD.

At this point we started looking at Argo CD ApplicationSet…

What is Argo CD ApplicationSet?
ApplicationSet is a sub-project of Argo CD. The ApplicationSet CRD describes the Applications that create/manage, and Argo CD is responsible for deploying them.

The main feature is that you can manage a large number of Argo CD Applications (in our case all Helm values files in a single Git repository) as a single unit.

All you need to do is specify, with your ApplicationSet, a template and generator that is used to customize that template. Then the ApplicationSet goes and creates an Applications CRD, based on the template and generator combination you’ve specified. You can think of ApplicationSets as a factory for Argo CD Applications.

ApplicationSet configuration
Let’s dive into the ApplicationSet example configuration, and explain it section by section:

```
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
 name: applicationset-test
 namespace: infra
spec:
 generators:
 - git:
     repoURL: https://github.com/YotpoLtd/argocd-example.git
     revision: HEAD
     files:
     - path: "helm-values-files/**/*.yaml"
 template:
   metadata:
     name: '{{ yotpo.deploymentName }}'
   spec:
     destination:
       namespace: "{{ yotpo.namespace }}"
       server: https://kubernetes.default.svc
     project: "{{ yotpo.namespace }}"
     source:
       path: "./"
       repoURL: https://github.com/YotpoLtd/argocd-example.git
       targetRevision: HEAD
       plugin:
         name: helm-yotpo
         env:
           - name: HELM_RELEASE_NAME
             value: "{{ yotpo.deploymentName }}"
           - name: HELM_CHART_VERSION
             value: "{{ yotpo.chartVersion }}"
           - name: NAMESPACE
             value: "{{yotpo.namespace}}"
           - name: HELM_REPO_URL
             value: "{{ yotpo.chartPath }}"
           - name: HELM_CHART_NAME
             value: "{{ yotpo.chartName }}"
           - name: HELM_VALUES_FILE
             value: "{{ filepath }}"
     syncPolicy:
       automated:
         prune: true
         selfHeal: true
```
       
ApplicationSet generator section
generators:
- git:
   repoURL: https://github.com/YotpoLtd/argocd-example.git
   revision: HEAD
   files:
   - path: "helm-values-files/**/*.yaml"
Generators are responsible for generating parameters, which are then rendered into the template fields of the ApplicationSet resource.

I invite you to read more on ApplicationSet generators here. We are using one specific generator (for now).

Git files generator
The Git file generator generates parameters using the contents of YAML files found in the Git repository (repoURL), the file will be substituted into the template.

In our case the ApplicationSet will scan the Git repository https://github.com/YotpoLtd/argocd-example.git for all the files found by this path “helm-values-files/**/*.yaml”, and automatically render one application for one file found. Basically each file found will be an Argo CD Application tile.

ApplicationSet template section
The template fields of the ApplicationSet spec are used to generate Argo CD application resources.

The template parameters are key-value pairs that will be substituted into the corresponding {{parameters-name}} fields of the template.

In our case, all the parameters will be read from the Yotpo section for every Helm file, and will be rendered into the template except for one parameter {{ filepath }}

We use the ApplicationSet with Git generator, to discover multiple Helm values files (*.yaml), and run the custom Helm plugin for each file found.

In order to run the plugin, we need to pass it the file path (helm template -f {filePath} )

The Git generator doesn’t include this parameter, so we had to contribute some code and build our own docker image to support our use case.

Once we deploy the ApplicationSet CRD, an Argo CD Application tile will be created for every YAML file found.
