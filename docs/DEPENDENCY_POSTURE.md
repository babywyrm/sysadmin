# Dependency Posture

This repository is a research archive. Nothing is built or deployed directly
from the repository root.

Dependency manifests are kept for different reasons, so vulnerability alerts
must be triaged by intent instead of blindly upgraded.

## Categories

- `maintained-example`: Example or helper that should stay reasonably current.
- `intentional-vulnerable-lab`: Vulnerable by design for CVE research or exploit
  reproduction. Keep the vulnerable dependency, but document the risk clearly.
- `legacy-archive`: Historical sample preserved for research. It may use old
  SDKs or runtimes and should not be deployed without modernization.
- `review-needed`: Ambiguous material that needs a human decision before update
  or removal.

## Current Manifest Triage

| Path | Category | Notes |
|---|---|---|
| `cve/react-next/lab/package.json` | `intentional-vulnerable-lab` | React/Next CVE lab. Preserve vulnerable versions for research. |
| `cve/react-next/tester/package.json` | `intentional-vulnerable-lab` | React/Next CVE tester. Preserve vulnerable versions for research. |
| `log4j/docker/requirements.txt` | `intentional-vulnerable-lab` | Log4Shell-era lab tooling. Keep isolated and documented. |
| `ai/providers/openai/legacy-demos/pet-name-flask-templates/requirements.txt` | `legacy-archive` | Historical OpenAI quickstart-style demo pins. Not a maintained app. |
| `containers/alpine/vm/package.json` | `legacy-archive` | Node/vm2 sandbox research. Do not treat as a deployable sandbox. |
| `flask/base/requirements.txt` | `maintained-example` | Generic Flask example; safe to modernize. |
| `node/beta/package.json` | `maintained-example` | Node playpen example; safe to modernize or de-noise. |
| `cloud/aws/iam/go.mod` | `maintained-example` | AWS IAM audit helper; keep dependencies current. |
| `ebpf/cilium/exec-trace/go.mod` | `maintained-example` | eBPF tracing helper; keep dependencies current when buildable. |
| `invest/seccheck/go.mod` | `maintained-example` | Small Go helper; keep dependencies current when buildable. |
| `modeling/k8s/spring/core/pom.xml` | `legacy-archive` | Architecture/modeling sample; update only if promoted to maintained example. |

## Alert Handling

1. Fix `maintained-example` manifests where updates are straightforward.
2. Add clear local warnings for `intentional-vulnerable-lab` manifests.
3. Keep `legacy-archive` manifests documented as historical samples, and update
   only when doing a modernization pass for that area.
4. Do not remove intentional vulnerable dependencies solely to clear a GitHub
   alert.

## Dockerfiles

Many Dockerfiles in this archive are copied tutorials, exploit labs, or old
container research. Standard `Dockerfile` names should be reserved for examples
we are willing to keep reasonably current.

Use these suffixes for preserved non-maintained images:

- `Dockerfile.lab`: intentionally vulnerable or exploit-oriented lab image.
- `Dockerfile.legacy`: historical tutorial, copied reference, old platform, or
  architecture sample that should not be treated as maintained.

If a preserved Dockerfile needs to be reproduced, copy it back to `Dockerfile`
inside an isolated lab directory and review the base image first.

Current active Dockerfiles are limited to maintained or low-risk examples:

- `containers/alpine/chromebb/Dockerfile`
- `containers/alpine/chromebb/dev/Dockerfile`
- `containers/alpine/docker/Dockerfile`
- `containers/alpine/wasm/Dockerfile`
- `containers/busybox/Dockerfile`
- `containers/docker/trivy/container/Dockerfile`
- `containers/docker/wolfi/Dockerfile`
- `cors/death/Dockerfile`
- `flask/base/Dockerfile`
- `go/go-kube/Dockerfile`
- `node/beta/Dockerfile`
- `owasp/Dockerfile`
