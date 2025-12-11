# Building a GitOps CI/CD Pipeline with GitHub Actions (SOC 2) - 2025 Edition

Here's an updated, modernized version with 2025 best practices:

## Key Improvements for 2025

- ✅ **OIDC Authentication** - No more long-lived tokens
- ✅ **Artifact Attestations** - Supply chain security (SLSA)
- ✅ **GitHub Environments** - Built-in approval gates
- ✅ **Renovate Bot** - Automated dependency updates
- ✅ **Container Signing** - Sigstore/Cosign integration
- ✅ **Enhanced Security** - SARIF scanning, secret scanning
- ✅ **Reusable Workflows 2.0** - Better composability

## Architecture Overview (Updated)

```
┌─────────────────────────────────────────────────────────────┐
│                     App Repository                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐             │
│  │   Source   │→ │   Build    │→ │  Attest &  │             │
│  │    Code    │  │  & Test    │  │   Sign     │             │
│  └────────────┘  └────────────┘  └────────────┘             │
└──────────────────────────┬──────────────────────────────────┘
                           │ Auto PR (via OIDC)
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                   Infra Repository                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐             │
│  │  GitOps    │→ │  Validate  │→ │   Deploy   │             │
│  │  Config    │  │  & Review  │  │ (Approved) │             │
│  └────────────┘  └────────────┘  └────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

## Updated Publish Flow (App Repo)

### Modern Workflow with OIDC and Attestations

`.github/workflows/publish.yml`:

```yaml
name: Publish

on:
  pull_request:
    branches: [main, hotfixes/*]
  push:
    branches: [main, hotfixes/*]

# OIDC permissions
permissions:
  id-token: write
  contents: read
  packages: write
  attestations: write

jobs:
  setup:
    runs-on: ubuntu-24.04  # Updated to latest LTS
    outputs:
      open_infra_pr: ${{ steps.setup.outputs.open_infra_pr }}
      publish: ${{ steps.setup.outputs.publish }}
      version: ${{ steps.setup.outputs.version }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup
        id: setup
        run: |
          VERSION="${GITHUB_SHA:0:8}"
          echo "version=$VERSION" >> "$GITHUB_OUTPUT"
          
          if [[ "${{ github.event_name }}" == "push" ]]; then
            echo "publish=true" >> "$GITHUB_OUTPUT"
            
            if [[ ${{ github.ref }} == refs/heads/main ]]; then
              echo "open_infra_pr=true" >> "$GITHUB_OUTPUT"
            fi
          fi

  security-scan:
    runs-on: ubuntu-24.04
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'

  api:
    needs: [setup, security-scan]
    uses: ./.github/workflows/api.yml
    with:
      publish: ${{ needs.setup.outputs.publish }}
      version: ${{ needs.setup.outputs.version }}
    secrets: inherit

  infra:
    needs: [api, setup]
    if: needs.setup.outputs.open_infra_pr == 'true'
    uses: ./.github/workflows/infra.yml
    with:
      version: ${{ needs.setup.outputs.version }}
    secrets: inherit
```

### API Workflow with Attestations

`.github/workflows/api.yml`:

```yaml
name: API

on:
  workflow_call:
    inputs:
      publish:
        required: true
        type: string
      version:
        required: true
        type: string

permissions:
  id-token: write
  contents: read
  packages: write
  attestations: write

jobs:
  api:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Install dependencies
        run: |
          cd projects/api
          make install

      - name: Run tests with coverage
        run: |
          cd projects/api
          make test-coverage

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v4
        with:
          files: ./projects/api/coverage.xml

      - name: Login to GitHub Container Registry (OIDC)
        if: inputs.publish == 'true'
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push
        if: inputs.publish == 'true'
        id: push
        uses: docker/build-push-action@v6
        with:
          context: projects/api
          push: true
          tags: |
            ghcr.io/${{ github.repository }}/api:${{ inputs.version }}
            ghcr.io/${{ github.repository }}/api:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max
          provenance: true
          sbom: true

      - name: Generate artifact attestation
        if: inputs.publish == 'true'
        uses: actions/attest-build-provenance@v1
        with:
          subject-name: ghcr.io/${{ github.repository }}/api
          subject-digest: ${{ steps.push.outputs.digest }}
          push-to-registry: true

      - name: Sign container image
        if: inputs.publish == 'true'
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}/api@${{ steps.push.outputs.digest }}
```

### Infra Workflow with OIDC

`.github/workflows/infra.yml`:

```yaml
name: Infra

on:
  workflow_call:
    inputs:
      version:
        required: true
        type: string

permissions:
  id-token: write
  contents: write
  pull-requests: write

jobs:
  infra:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          repository: cicd-excellence/infra
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Create GitHub App Token
        uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.BOT_APP_ID }}
          private-key: ${{ secrets.BOT_PRIVATE_KEY }}
          repositories: infra

      - name: Open and merge Infra PR
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
          VERSION: ${{ inputs.version }}
        run: |
          BRANCH_NAME="auto-update-dev-$VERSION"
          
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          
          git checkout -b $BRANCH_NAME
          
          # Update version
          jq '.api.tag = env.VERSION' envs/dev.json > envs/dev.json.tmp
          mv envs/dev.json.tmp envs/dev.json
          
          git add envs/dev.json
          git commit -m "🤖 Auto-update dev to $VERSION"
          git push origin $BRANCH_NAME
          
          # Create and auto-merge PR
          gh pr create \
            --title "🤖 Update dev to $VERSION" \
            --body "Auto-generated PR to deploy \`$VERSION\` to dev environment.
          
          **Changes:**
          - API version: \`$VERSION\`
          
          **Verification:**
          - ✅ Tests passed in app repo
          - ✅ Security scans completed
          - ✅ Artifacts attested and signed" \
            --head "$BRANCH_NAME" \
            --base "main" \
            --label "auto-merge,dev"
          
          # Wait for checks and auto-merge
          gh pr merge --auto --rebase --delete-branch
```

## Updated Deploy Flow (Infra Repo)

`.github/workflows/deploy.yml`:

```yaml
name: Deploy

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read
  deployments: write

jobs:
  setup:
    runs-on: ubuntu-24.04
    outputs:
      deploy: ${{ steps.setup.outputs.deploy }}
      environments: ${{ steps.setup.outputs.environments }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2

      - name: Detect changed environments
        id: setup
        run: |
          if [[ "${{ github.event_name }}" == "push" ]]; then
            echo "deploy=true" >> "$GITHUB_OUTPUT"
            
            # Detect which environments changed
            CHANGED_ENVS=$(git diff --name-only HEAD^ HEAD | \
              grep '^envs/' | \
              sed 's|envs/||' | \
              sed 's|\.json||' | \
              jq -R -s -c 'split("\n") | map(select(length > 0))')
            
            echo "environments=$CHANGED_ENVS" >> "$GITHUB_OUTPUT"
          fi

  validate:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Validate JSON configs
        run: |
          for file in envs/*.json; do
            jq empty "$file" || exit 1
          done

      - name: Run infrastructure tests
        run: make test

      - name: Terraform validate
        run: |
          cd terraform
          terraform init -backend=false
          terraform validate

  deploy:
    needs: [setup, validate]
    if: needs.setup.outputs.deploy == 'true'
    strategy:
      matrix:
        env: ${{ fromJson(needs.setup.outputs.environments) }}
    runs-on: ubuntu-24.04
    environment:
      name: ${{ matrix.env }}
      url: https://${{ matrix.env }}.example.com
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActions-${{ matrix.env }}
          aws-region: us-east-1

      - name: Get deployment config
        id: config
        run: |
          API_VERSION=$(jq -r '.api.tag' envs/${{ matrix.env }}.json)
          echo "api_version=$API_VERSION" >> "$GITHUB_OUTPUT"

      - name: Verify artifact attestation
        run: |
          gh attestation verify \
            oci://ghcr.io/cicd-excellence/app/api:${{ steps.config.outputs.api_version }} \
            --owner cicd-excellence

      - name: Deploy to ${{ matrix.env }}
        run: |
          echo "Deploying API version ${{ steps.config.outputs.api_version }} to ${{ matrix.env }}"
          
          # Example: Update ECS service
          aws ecs update-service \
            --cluster ${{ matrix.env }}-cluster \
            --service api \
            --force-new-deployment \
            --task-definition api:${{ steps.config.outputs.api_version }}

      - name: Run smoke tests
        run: |
          make smoke-test ENV=${{ matrix.env }}

      - name: Notify deployment
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.repos.createDeploymentStatus({
              owner: context.repo.owner,
              repo: context.repo.repo,
              deployment_id: context.payload.deployment.id,
              state: '${{ job.status }}',
              environment_url: 'https://${{ matrix.env }}.example.com',
              description: 'Deployment ${{ job.status }}'
            });
```

## Modern Branch Protection (Rulesets 2025)

`.github/rulesets/main-branch.json`:

```json
{
  "name": "Main Branch Protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/main"],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "required_linear_history"
    },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          {
            "context": "security-scan",
            "integration_id": 15368
          },
          {
            "context": "api / api",
            "integration_id": 15368
          },
          {
            "context": "validate",
            "integration_id": 15368
          }
        ]
      }
    },
    {
      "type": "required_deployments",
      "parameters": {
        "required_deployment_environments": ["dev"]
      }
    }
  ],
  "bypass_actors": [
    {
      "actor_id": 5,
      "actor_type": "RepositoryRole",
      "bypass_mode": "pull_request"
    }
  ]
}
```

## GitHub Environments Configuration

Create environments with protection rules:

**Dev Environment:**
```yaml
# .github/environments/dev.yml
name: dev
deployment_branch_policy:
  protected_branches: true
  custom_branch_policies: false
reviewers: []
wait_timer: 0
prevent_self_review: false
```

**Staging Environment:**
```yaml
# .github/environments/staging.yml
name: staging
deployment_branch_policy:
  protected_branches: true
reviewers:
  - type: Team
    id: engineering-leads
wait_timer: 5  # 5 minute wait
prevent_self_review: true
```

**Production Environment:**
```yaml
# .github/environments/prod.yml
name: prod
deployment_branch_policy:
  protected_branches: true
reviewers:
  - type: Team
    id: sre-team
  - type: Team
    id: security-team
wait_timer: 60  # 1 hour wait
prevent_self_review: true
```

## Automated Dependency Updates

`.github/renovate.json`:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "schedule": ["before 6am on monday"],
  "labels": ["dependencies"],
  "packageRules": [
    {
      "matchUpdateTypes": ["minor", "patch"],
      "matchCurrentVersion": "!/^0/",
      "automerge": true,
      "automergeType": "pr",
      "automergeStrategy": "rebase"
    },
    {
      "matchManagers": ["github-actions"],
      "pinDigests": true,
      "automerge": true
    }
  ],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": ["security"],
    "automerge": true
  }
}
```

## Hotfix Flow (Updated)

`.github/workflows/hotfix.yml`:

```yaml
name: Hotfix

on:
  workflow_dispatch:
    inputs:
      base_commit_sha:
        description: 'Base commit SHA for hotfix'
        required: true
        type: string
      branch_name:
        description: 'Hotfix branch name (e.g., critical-bug-fix)'
        required: true
        type: string
      severity:
        description: 'Severity level'
        required: true
        type: choice
        options:
          - critical
          - high
          - medium

permissions:
  contents: write
  pull-requests: write
  issues: write

jobs:
  create-hotfix:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.inputs.base_commit_sha }}
          fetch-depth: 0

      - name: Create GitHub App Token
        uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.BOT_APP_ID }}
          private-key: ${{ secrets.BOT_PRIVATE_KEY }}

      - name: Create hotfix branch
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
        run: |
          BRANCH="hotfixes/${{ github.event.inputs.branch_name }}"
          
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          
          git switch -c "$BRANCH"
          git push origin "$BRANCH"
          
          # Create tracking issue
          gh issue create \
            --title "🚨 Hotfix: ${{ github.event.inputs.branch_name }}" \
            --body "**Severity:** ${{ github.event.inputs.severity }}
          **Base commit:** ${{ github.event.inputs.base_commit_sha }}
          **Branch:** \`$BRANCH\`
          
          ## Checklist
          - [ ] Root cause identified
          - [ ] Fix implemented and tested
          - [ ] PR reviewed and approved
          - [ ] Deployed to production
          - [ ] Post-mortem scheduled
          
          ## Timeline
          - Created: $(date -u +"%Y-%m-%d %H:%M:%S UTC")" \
            --label "hotfix,${{ github.event.inputs.severity }}"

      - name: Notify team
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "🚨 Hotfix branch created: ${{ github.event.inputs.branch_name }}",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Hotfix Created*\n*Severity:* ${{ github.event.inputs.severity }}\n*Branch:* `hotfixes/${{ github.event.inputs.branch_name }}`"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

## SOC 2 Compliance Checklist (2025)

```yaml
# .github/compliance/soc2-checklist.yml
access_control:
  - ✅ MFA enforced for all organization members
  - ✅ GitHub App with minimal permissions (no long-lived PATs)
  - ✅ OIDC for cloud provider authentication
  - ✅ Branch protection rules enforced
  - ✅ Required reviews from code owners
  - ✅ No direct commits to main branch

change_management:
  - ✅ All changes via pull requests
  - ✅ Automated tests required
  - ✅ Security scans integrated
  - ✅ Deployment approvals for prod
  - ✅ Audit log of all deployments
  - ✅ Rollback procedure documented

security:
  - ✅ Vulnerability scanning (Trivy/Snyk)
  - ✅ Secret scanning enabled
  - ✅ Dependabot security updates
  - ✅ Container signing (Sigstore)
  - ✅ Artifact attestations (SLSA)
  - ✅ SARIF results uploaded
  - ✅ Private vulnerability reporting enabled

monitoring:
  - ✅ Deployment tracking
  - ✅ Audit logs exported
  - ✅ Failed deployment alerts
  - ✅ Security scan failures notified
  - ✅ Metrics collected and monitored

documentation:
  - ✅ Architecture documented
  - ✅ Runbooks for incidents
  - ✅ Access control procedures
  - ✅ Disaster recovery plan
  - ✅ Security incident response plan
```

## Key Differences from 2024

| Feature | 2024 | 2025 |
|---------|------|------|
| **Authentication** | Personal Access Tokens | OIDC + GitHub Apps |
| **Security** | Basic scanning | SLSA attestations + Sigstore |
| **Deployments** | Custom scripts | GitHub Environments |
| **Reviews** | Manual only | AI-assisted (Copilot) |
| **Deps** | Manual updates | Renovate auto-merge |
| **Monitoring** | External only | Built-in insights |
| **Runners** | ubuntu-22.04 | ubuntu-24.04 |
| **Actions** | v3 | v4-v6 |

## Quick Start Script

```bash
#!/usr/bin/env bash
set -euo pipefail

# Setup modern GitOps pipeline
gh repo clone cicd-excellence/app
cd app

# Enable security features
gh repo edit --enable-vulnerability-alerts
gh repo edit --enable-automated-security-fixes
gh secret-scanning enable

# Create GitHub App for automation
echo "Create a GitHub App at: https://github.com/settings/apps/new"
echo "Required permissions:"
echo "  - contents: write"
echo "  - pull_requests: write"
echo "  - issues: write"

# Setup environments
gh api repos/:owner/:repo/environments/dev -X PUT
gh api repos/:owner/:repo/environments/staging -X PUT
gh api repos/:owner/:repo/environments/prod -X PUT

echo "✅ Repository configured for GitOps 2025!"
```
