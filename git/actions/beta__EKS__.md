1. Deploy GitHub Actions Runners in EKS
First, you need to deploy GitHub Actions Runners into your EKS cluster to run workflows from your GitHub repositories. The steps are:

Deploy the actions-runner-controller: This Kubernetes controller manages self-hosted runners in EKS and connects them to GitHub.

Use Helm to install the actions-runner-controller in your EKS cluster:

```
helm repo add actions-runner-controller https://actions-runner-controller.github.io/actions-runner-controller
helm install actions-runner-controller actions-runner-controller/actions-runner-controller --namespace actions-runner-system --create-namespace
```

Configure GitHub Repository Access: You’ll need a GitHub App or a Personal Access Token (PAT) to authenticate the runners and allow them to access your GitHub repositories. Create a GitHub App or PAT with the necessary permissions (read/write access to the repository and workflow permissions), then configure the controller.

Create Runner Deployments: Create Kubernetes resources for the GitHub Actions runners that will handle the workflows from your specific repositories. For example:

```
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: example-runner-deployment
spec:
  replicas: 3
  template:
    spec:
      repository: your-org/your-repo
      githubToken: <your-token-or-github-app-secret>
```

This will create 3 runners for your specific repository in the cluster.

2. Integrating Security Checks into GitHub Actions
You can prevent the deployment of insecure code by integrating security checks within your GitHub Actions workflow. This can include:

SAST (Static Application Security Testing): Tools like SonarQube or CodeQL can be integrated into your pipeline to check for code vulnerabilities before merging or deploying.

Example GitHub Actions step:

```
name: Security Check
run: |
  codeql-cli analyze --format=sarif --output=results.sarif
```

Dependency Scanning: Use tools like Trivy or Snyk to scan for vulnerabilities in dependencies or Docker images.

```
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@v0.2.0
  with:
    image-ref: your-image:tag
```

Prevent Deployments on Failure: Configure the workflow so that deployments to EKS only occur if all security checks pass. Example:

```
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v2
      - name: Run Security Scans
        run: |
          # Run security checks here (e.g., SAST, Trivy, etc.)
          ./run-security-checks.sh

  deploy:
    needs: build
    runs-on: self-hosted
    if: success()  # Only deploy if previous steps were successful
    steps:
      - name: Deploy to EKS
        run: |
          kubectl apply -f deployment.yaml
```


3. Control Deployments from GitHub Actions
To control deployments to your EKS cluster directly from GitHub Actions:

Configure Access to EKS: Use GitHub Secrets to store AWS credentials that allow access to your EKS cluster. You can also use the AWS IAM Role for Service Accounts (IRSA) to avoid long-lived secrets.

Set up the aws-actions/configure-aws-credentials action:

```
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v1
  with:
    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    aws-region: us-west-2
```
Use Kubectl to Deploy: Use the kubectl command-line tool within your GitHub Actions to manage and apply Kubernetes manifests to your EKS cluster.

```
- name: Deploy to EKS
  run: |
    kubectl apply -f deployment.yaml
```
This way, you can tightly control which code gets deployed based on security scan results and other checks.

4. Link GitHub Repositories to the Runner
When you create RunnerDeployment Kubernetes resources in your EKS cluster, you specify which GitHub repositories or organizations they should be linked to. Example configuration:

```
spec:
  template:
    spec:
      organization: your-organization-name
      githubToken: ${{ secrets.GITHUB_PAT }}
```

If using the GitHub App, you’ll need to link the app to the repositories it should manage.

5. Secure Git Operations (Push/Merge Control)
To ensure secure code merges and deployments:

Enforce Branch Protection: Use GitHub branch protection rules to require checks (such as security scans) to pass before allowing merges or direct pushes. You can also require approval from security teams.

Automate Merge on Success: Use GitHub Actions to automatically merge pull requests that have passed security checks. Example workflow for automating a merge after checks:

```
name: Auto-merge on success
on:
  pull_request:
    types: [closed]

jobs:
  auto-merge:
    if: github.event.pull_request.merged == true
    runs-on: self-hosted
    steps:
      - name: Merge Pull Request
        run: gh pr merge ${{ github.event.pull_request.number }} --merge
```


