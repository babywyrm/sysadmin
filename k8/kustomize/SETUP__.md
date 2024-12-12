[base]: https://kubectl.docs.kubernetes.io/references/kustomize/glossary/#base
[config]: https://github.com/kubernetes-sigs/kustomize/tree/master/examples/helloWorld
[gitops]: https://kubectl.docs.kubernetes.io/references/kustomize/glossary/#gitops
[hello]: https://github.com/monopole/hello
[kustomization]: https://kubectl.docs.kubernetes.io/references/kustomize/glossary/#kustomization
[original]: https://github.com/kubernetes-sigs/kustomize/tree/master/examples/helloWorld
[overlay]: https://kubectl.docs.kubernetes.io/references/kustomize/glossary/#overlay
[overlays]: https://kubectl.docs.kubernetes.io/references/kustomize/glossary/#overlay
[patch]: https://kubectl.docs.kubernetes.io/references/kustomize/glossary/#patch
[variant]: https://kubectl.docs.kubernetes.io/references/kustomize/glossary/#variant
[variants]: https://kubectl.docs.kubernetes.io/references/kustomize/glossary/#variant

# Demo: hello world with variants

##
#
https://gap.gjensidige.io/docs/guides/ci-automation-with-kustomize
#
##

Steps:

 1. Clone an existing configuration as a [base].
 1. Customize it.
 1. Create two different [overlays] (_staging_ and _production_)
    from the customized base.
 1. Run kustomize and kubectl to deploy staging and production.

First define a place to work:

<!-- @makeWorkplace @testAgainstLatestRelease -->
```
DEMO_HOME=$(mktemp -d)
```

Alternatively, use

> ```
> DEMO_HOME=~/hello
> ```

## Establish the base

Let's run the [hello] service.

To use [overlays] to create [variants], we must
first establish a common [base].

To keep this document shorter, the base resources are
off in a supplemental data directory rather than
declared here as HERE documents.  Download them:

<!-- @downloadBase @testAgainstLatestRelease -->
```
BASE=$DEMO_HOME/base
mkdir -p $BASE

curl -s -o "$BASE/#1.yaml" "https://raw.githubusercontent.com\
/kubernetes-sigs/kustomize\
/master/examples/helloWorld\
/{configMap,deployment,kustomization,service}.yaml"
```

Look at the directory:

<!-- @runTree -->
```
tree $DEMO_HOME
```

Expect something like:

> ```
> /tmp/tmp.IyYQQlHaJP
> └── base
>     ├── configMap.yaml
>     ├── deployment.yaml
>     ├── kustomization.yaml
>     └── service.yaml
> ```


One could immediately apply these resources to a
cluster:

> ```
> kubectl apply -k $DEMO_HOME/base
> ```

to instantiate the _hello_ service.  `kubectl`
would only recognize the resource files.

### The Base Kustomization

The `base` directory has a [kustomization] file:

<!-- @showKustomization @testAgainstLatestRelease -->
```
more $BASE/kustomization.yaml
```

Optionally, run `kustomize` on the base to emit
customized resources to `stdout`:

<!-- @buildBase @testAgainstLatestRelease -->
```
kustomize build $BASE
```

### Customize the base

A first customization step could be to change the _app
label_ applied to all resources:

<!-- @addLabel @testAgainstLatestRelease -->
```
sed -i.bak 's/app: hello/app: my-hello/' \
    $BASE/kustomization.yaml
```

See the effect:
<!-- @checkLabel @testAgainstLatestRelease -->
```
kustomize build $BASE | grep -C 3 app:
```

## Create Overlays

Create a _staging_ and _production_ [overlay]:

 * _Staging_ enables a risky feature not enabled in production.
 * _Production_ has a higher replica count.
 * Web server greetings from these cluster
   [variants] will differ from each other.

<!-- @overlayDirectories @testAgainstLatestRelease -->
```
OVERLAYS=$DEMO_HOME/overlays
mkdir -p $OVERLAYS/staging
mkdir -p $OVERLAYS/production
```

#### Staging Kustomization

In the `staging` directory, make a kustomization
defining a new name prefix, and some different labels.

<!-- @makeStagingKustomization @testAgainstLatestRelease -->
```
cat <<'EOF' >$OVERLAYS/staging/kustomization.yaml
namePrefix: staging-
commonLabels:
  variant: staging
  org: acmeCorporation
commonAnnotations:
  note: Hello, I am staging!
resources:
- ../../base
patches:
- path: map.yaml
EOF
```

#### Staging Patch

Add a configMap customization to change the server
greeting from _Good Morning!_ to _Have a pineapple!_

Also, enable the _risky_ flag.

<!-- @stagingMap @testAgainstLatestRelease -->
```
cat <<EOF >$OVERLAYS/staging/map.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: the-map
data:
  altGreeting: "Have a pineapple!"
  enableRisky: "true"
EOF
```

#### Production Kustomization

In the production directory, make a kustomization
with a different name prefix and labels.

<!-- @makeProductionKustomization @testAgainstLatestRelease -->
```
cat <<EOF >$OVERLAYS/production/kustomization.yaml
namePrefix: production-
commonLabels:
  variant: production
  org: acmeCorporation
commonAnnotations:
  note: Hello, I am production!
resources:
- ../../base
patches:
- path: deployment.yaml
EOF
```


#### Production Patch

Make a production patch that increases the replica
count (because production takes more traffic).

<!-- @productionDeployment @testAgainstLatestRelease -->
```
cat <<EOF >$OVERLAYS/production/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: the-deployment
spec:
  replicas: 10
EOF
```

## Compare overlays


`DEMO_HOME` now contains:

 - a _base_ directory - a slightly customized clone
   of the original configuration, and

 - an _overlays_ directory, containing the kustomizations
   and patches required to create distinct _staging_
   and _production_ [variants] in a cluster.

Review the directory structure and differences:

<!-- @listFiles -->
```
tree $DEMO_HOME
```

Expecting something like:

> ```
> /tmp/tmp.IyYQQlHaJP1
> ├── base
> │   ├── configMap.yaml
> │   ├── deployment.yaml
> │   ├── kustomization.yaml
> │   └── service.yaml
> └── overlays
>     ├── production
>     │   ├── deployment.yaml
>     │   └── kustomization.yaml
>     └── staging
>         ├── kustomization.yaml
>         └── map.yaml
> ```

Compare the output directly
to see how _staging_ and _production_ differ:

<!-- @compareOutput -->
```
diff \
  <(kustomize build $OVERLAYS/staging) \
  <(kustomize build $OVERLAYS/production) |\
  more
```

The first part of the difference output should look
something like

> ```diff
> <   altGreeting: Have a pineapple!
> <   enableRisky: "true"
> ---
> >   altGreeting: Good Morning!
> >   enableRisky: "false"
> 8c8
> <     note: Hello, I am staging!
> ---
> >     note: Hello, I am production!
> 11c11
> <     variant: staging
> ---
> >     variant: production
> 13c13
> (...truncated)
> ```


## Deploy

The individual resource sets are:

<!-- @buildStaging @testAgainstLatestRelease -->
```
kustomize build $OVERLAYS/staging
```

<!-- @buildProduction @testAgainstLatestRelease -->
```
kustomize build $OVERLAYS/production
```

To deploy, pipe the above commands to kubectl apply:

> ```
> kustomize build $OVERLAYS/staging |\
>     kubectl apply -f -
> ```

> ```
> kustomize build $OVERLAYS/production |\
>    kubectl apply -f -
> ```



utomation with GitHub Actions and Kustomize

At Gjensidige, we encourage following the GitOps model of deployment, where desired configuration changes are first pushed to GitHub, and the cluster state then syncs to the desired state stored in your GitHub repo.

This guide will teach you how to automatically update your Kubernetes manifests after a new version of your container image has been pushed to Azure Container Registry.
Using Jsonnet as an alternative to plain YAML

See Getting Started with Jsonnet.
Prerequisites

    Familiar with the guide Pushing a Container Image
    Secret SYSTEM_ACTION_USER in your repo. This can be added by typing /platform-github repo add-secret in the Slack Channel #github-at-gjensidige
    A repo containing a /manifests-folder with a Kubernetes Deployment manifest

Kustomize

    Kustomize introduces a template-free way to customize application configuration that simplifies the use of off-the-shelf applications

There are multiple good resources to learn about Kustomize. To get started, check out their website for documentation and their GitHub repo for code examples.
Creating kustomization.yaml

In your /manifests-folder, create a new file named kustomization.yaml:
kustomization.yaml

apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- "deployment.yaml"
images:
- name: "app-image"
  newName: "gjensidige.azurecr.io/your-team-name/your-app-name"
  newTag: "initial"
namespace: "your-team-namespace"

Declaring images enables us to use the command kustomize edit set image app-image=... in our automation later. For your first commit, it's OK to use a placeholder value like initial in newTag.
Kustomization File Reference :bulb:

There are multiple other use-cases for kustomization of Kubernetes manifests. Learn all about it in the reference documentation
Update deployment.yaml

Update your Deployment manifest to tell Kustomize where to put the value of app-image:
deployment.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: "your-team-namespace"
  name: "test-app"
spec:
  selector:
    matchLabels:
      app: "test-app"
  template:
    metadata:
      name: "test-app"
    spec:
      containers:
        - name: "test-app"
          image: "app-image" # The value "app-image" references "app-image" in kustomize.yaml

When applying this Deployment to Kubernetes with Kustomize, app-image will be replaced by the values in kustomize.yaml. Next, we'll automate updating new image tags with GitHub Actions 🚀
GitHub Actions workflow

Let's start automating! Consider the workflow below:
.github/workflows/build_and_deploy.yaml

name: Build and Deploy

on:
  push:
    branches:
      - "main"

env:
  TEAM_NAME: "your-team-name" # Change this
  REGISTRY: "gjensidige.azurecr.io"

jobs:
  build-and-push: # [1]
    runs-on: "ubuntu-latest"
    steps:
      # Copy steps from guide "Pushing a Container Image"

  update-manifest:
    name: "Update Manifests"
    needs: "build-and-push"
    runs-on: "ubuntu-latest"
    steps:
      - name: "Git checkout"
        uses: "actions/checkout@v2"
        with:
          token: ${{ secrets.ACTIONS_SYSTEM_USER }} # [2]

      - name: "Update Deployment Image Tag" # [3]
        working-directory: "manifests"
        run: |
          kustomize edit set image app-image=${{ env.REGISTRY }}/${{ env.TEAM_NAME }}/${{ github.event.repository.name }}:${{ github.sha }}

      - name: "Push Updated Image Tag" # [4]
        run: |
          git config --global user.name "@gjensidige-bot"
          git config --global user.email "gjensidige-bot@users.noreply.github.com"
          git commit -am "feat: Update deployment image tag to ${{ github.sha }} [skip ci]"
          git push

    Build and push your container image using steps from Pushing a Container Image
    ACTIONS_SYSTEM_USER is used to checking out our code. This enables us to push commits (in Step 4)
    We are running kustomize edit to update the image app-image in our kustomize.yaml with the latest version of our container image
    We are pushing the changes to kustomize.yaml back to our code base so that our Infrastructure as Code repository is up to date in accordance with GitOps practices. Note that we add [skip ci] to the commit message to avoid re-running the workflow for this commit.

Multiple environments

Kustomize is great to reduce duplication and increase robustness of code when you are deploying to multiple environments. This Multibase example shows how you can extend a "base" of Kubernetes manifests for each of your environments. Then your folder structure would look something like this:

manifests/
  base/
    deployment.yaml
    kustomization.yaml
  test/
    kustomization.yaml
  prod/
    kustomization.yaml

Next steps
