This is mostly for my own notes, because I had to put this together this week, but hopefully this step by step helps others as well.

##
#
https://medium.com/@hans.knechtions/helm-charts-argocd-and-ecr-beceec0accc1
#
##

Background
I had a client that needed to configure a private helm chart to be installed via ArgoCD into an EKS cluster. This helm chart exists in a separate repo from the values.yaml and is pushed to ECR. This post will walk you through how to configure the pushing of a helm chart to ECR via Github Actions, installing and configuring External Secrets, and finally connecting ArgoCD to deploy the helm chart with a separate values.yaml. An example GitHub repository with all the code/configuration will be available at the end.

This assumes you have a running ArgoCD instance in a k8s cluster. It technically doesn’t have to be in EKS though that’s most likely where this is running and is most helpful to you.

Push a Helm Chart to ECR
This isn’t terribly complicated, but there is a quirk to not needing to manually update the version in the helm chart every time, but rather having GitHub Actions figure out the version based on the tag.

Here is the workflow file:

```
name: Helm Chart Releaser

on:
  push:
    # Pattern matched against refs/tags
    tags:
      - "charts/**"

env:
  YQ_VERSION: v4.33.2
  YQ_BINARY: yq_linux_amd64
  HELM_DOCS_VERSION: 1.13.1

jobs:
  release:
    permissions:
      contents: "read"
      id-token: "write"
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Configure Git
        run: |
          git config user.name "$GITHUB_ACTOR"
          git config user.email "$GITHUB_ACTOR@users.noreply.github.com"

      # Need to add a job to auth to ECR so we can push the chart
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      # Authenticate to Amazon ECR
      - name: Login to Amazon ECR
        uses: aws-actions/amazon-ecr-login@v1

      - name: Install Helm
        uses: azure/setup-helm@v3.5
        with:
          version: v3.12.3

      - name: Install Helm Plugins
        run: |
          wget https://github.com/norwoodj/helm-docs/releases/download/v${HELM_DOCS_VERSION}/helm-docs_${HELM_DOCS_VERSION}_Linux_x86_64.tar.gz
          tar -xvf helm-docs_${HELM_DOCS_VERSION}_Linux_x86_64.tar.gz
          sudo mv helm-docs /usr/local/sbin

      # Uncomment when charts are ready for publishing

      - name: Publish Charts
        run: |
          export CHART_LOCATION="charts"
          export CHART_NAME=$(echo ${GITHUB_REF_NAME} | awk -F/ '{print $2}')
          export CHART_VERSION=$(echo ${GITHUB_REF_NAME} | awk -F/ '{print $3}')

          yq -i e '.version = env(CHART_VERSION)' $CHART_LOCATION/$CHART_NAME/Chart.yaml
          helm-docs -g ${CHART_LOCATION}/${CHART_NAME}

          helm package "${CHART_LOCATION}/${CHART_NAME}"
          helm push /home/runner/work/<github_repo_name>/<github_repo_name>/${CHART_NAME}-${CHART_VERSION}.tgz oci://<aws_account_number>.dkr.ecr.us-east-1.amazonaws.com/
```

Let’s step through the chart.

We tell GitHub actions when to run this. We want to run it only on certain tags. Especially helpful in mono-repos or non-dedicated repos
```
on:
  push:
    # Pattern matched against refs/tags
    tags:
      - "charts/**"
We configure the version of some useful tools:
env:
  YQ_VERSION: v4.33.2
  YQ_BINARY: yq_linux_amd64
  HELM_DOCS_VERSION: 1.13.1
We assign permissions to the task (required because of GitHubs permission model to access the OIDC token for the repo):
jobs:
  release:
    permissions:
      contents: "read"
      id-token: "write"
```

We checkout and configure our tools:
```
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Configure Git
        run: |
          git config user.name "$GITHUB_ACTOR"
          git config user.email "$GITHUB_ACTOR@users.noreply.github.com"

      # Need to add a job to auth to ECR so we can push the chart
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
```

Login to ECR
```
# Authenticate to Amazon ECR
      - name: Login to Amazon ECR
        uses: aws-actions/amazon-ecr-login@v1
Install helm and helm-docs (Helm docs is a very useful helm tool that qill auto generate the readme for your chart).
      - name: Install Helm
        uses: azure/setup-helm@v3.5
        with:
          version: v3.12.3

      - name: Install Helm Plugins
        run: |
          wget https://github.com/norwoodj/helm-docs/releases/download/v${HELM_DOCS_VERSION}/helm-docs_${HELM_DOCS_VERSION}_Linux_x86_64.tar.gz
          tar -xvf helm-docs_${HELM_DOCS_VERSION}_Linux_x86_64.tar.gz
          sudo mv helm-docs /usr/local/sbin
Now we do some magic. We first get the chart location, chart name, and chart version from the tag. This assumes we have a tag formatted like: charts/cool-chart/v1.0.0. We then put the version into the Chart.yaml. Generate the Readme and other documentation. And then push it up to OCR.
      - name: Publish Charts
        run: |
          export CHART_LOCATION="charts"
          export CHART_NAME=$(echo ${GITHUB_REF_NAME} | awk -F/ '{print $2}')
          export CHART_VERSION=$(echo ${GITHUB_REF_NAME} | awk -F/ '{print $3}')

          yq -i e '.version = env(CHART_VERSION)' $CHART_LOCATION/$CHART_NAME/Chart.yaml
          helm-docs -g ${CHART_LOCATION}/${CHART_NAME}

          helm package "${CHART_LOCATION}/${CHART_NAME}"
          helm push /home/runner/work/<github_repo_name>/<github_repo_name>/${CHART_NAME}-${CHART_VERSION}.tgz oci://<aws_account_number>.dkr.ecr.us-east-1.amazonaws.com/
```

Install and Configure External Secrets
Install documentation is reasonably complete for external-secrets. There’s only a few things to add.

First, create an IAM Policy and grant it access to ECR. I didn’t make this policy particularly locked down, but you can limit it to only read actions if you’d like. 
You may also want to add SecretsManager permissions to the policy because External Secrets is a very useful tool in general.
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ecr:*"
            ],
            "Resource": "*"
        }
    ]
}
```
Second, create an IAM role that trusts the external-secrets Kubernetes service account and attach the policy you just created. 
Here is an example of the trust relationship.json. AWS has more documentation if needed.
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<AWS-Account-Number>:oidc-provider/<OIDC-Provider>"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "<OIDC-Provider>:aud": "sts.amazonaws.com",
          "<OIDC-Provider>:sub": "system:serviceaccount:external-secrets:external-secrets"
        }
      }
    }
  ]
}
```
Third, create a values.yaml for external secrets with a reference to the IAM role ARN you just created:
```
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<account-number>:role/<role-name>
```
Fourth, install external-secrets:
```
helm repo add external-secrets https://charts.external-secrets.io

helm install external-secrets \
   external-secrets/external-secrets \
    -n external-secrets \
    --create-namespace \
    -f values.yaml
```
Fifth, configure a secret for ArgoCD to use:
```
apiVersion: generators.external-secrets.io/v1alpha1
kind: ECRAuthorizationToken
metadata:
  name: ecr
  namespace: argocd
spec:
  region: <aws_region>
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: ecr-oci
  namespace: argocd
spec:
  refreshInterval: 30m
  target:
    name: ecr-oci
    template:
      metadata:
        labels:
          argocd.argoproj.io/secret-type: repository
      data:
        name: ecr-oci
        type: helm
        enableOCI: "true"
        url: <account-number>.dkr.ecr.<aws_region>.amazonaws.com
        password: "{{ .password }}"
        username: "{{ .username }}"
  dataFrom:
    - sourceRef:
        generatorRef:
          apiVersion: generators.external-secrets.io/v1alpha1
          kind: ECRAuthorizationToken
          name: ecr
```

This yaml uses the ECR Authorization Token Generator to rotate and create tokens that ArgoCD can use and then puts it in a format that ArgoCD can understand to use for the helm login command.

Configure ArgoCD Application to use Helm Chart
Now you can configure your ArgoCD application to use the Helm Chart properly:
```
project: default
destination:
  server: '<server>'
  namespace: <namespace>
syncPolicy:
  automated:
    prune: true
    selfHeal: true
sources:
- repoURL: '<account_number>.dkr.ecr.<aws_region>.amazonaws.com'
  path: '<chart_name>'
  targetRevision: <version>
  chart: <chart_name>
  helm:
    valueFiles:
      - $values/path/to/values.yaml
- repoURL: 'git@github.com:<GithubOrg>/<Repo>.git'
  targetRevision: HEAD
  ref: values
```
This file creates two sources and allows you to substitute in the the $values for the second source allowing for the values.yaml and the helm chart to exist in different locations.

DevOps
Argo Cd
Kubernetes
