# Sysadmin Repository Map

This repository is a research archive for systems administration, security,
cloud infrastructure, offensive testing, and defensive operations. It is not a
single product tree.

## Largest Areas

| Area | Purpose |
|---|---|
| `pyth3/` | Python administration, security tooling, tests, exploit notes, and experiments. |
| `containers/` | Container operations, Docker/Podman/Alpine/BusyBox/Firecracker notes, Compose examples, CVE notes, and hardening references. |
| `java/` | Java, Spring, JVM, code review, XSS, deserialization, and related appsec notes. |
| `k3/` | k3s, local Kubernetes labs, bootstrap scripts, Cilium, WordPress, and Gatekeeper notes. |
| `EKS/` | AWS EKS, IAM, IRSA, secrets management, Istio, and cluster operations research. |
| `modeling/` | Architecture sketches, zero trust notes, Kubernetes modeling, and policy experiments. |
| `AD/` | Active Directory tradecraft, defensive notes, payload references, and lab tooling. |
| `k8/` | Kubernetes operations, Helm, probes, dashboards, EKS notes, and cluster hardening. |
| `cloud/` | AWS, ECR, Azure, GCP, DigitalOcean, LocalStack, and Terraform notes. |
| `ai/` | MCP, LLM, OpenAI/provider, agent gateway, and agent security research. |
| `burp/` | Burp/WebGoat/web testing notes and captured learning material. |

## Sensitive Areas

These directories often contain examples that look like secrets or exploit
material. Review carefully before sharing, copying, or publishing snippets:

- `AD/`
- `EKS/`
- `cloud/aws/`
- `cloud/azure/`
- `jwt/`
- `oauth/`
- `ssrf/`
- `secrets/`
- `vault/`
- `sso/`
- `ai/mcp/`
- `ai/providers/openai/`

## Cleanup Notes

- Scanner reports live in `docs/cleanup/`.
- Real credential values should be replaced with explicit placeholders.
- Public references and copied writeups may still trigger scanners because they
  contain long URL slugs or example tokens.
- Downloaded binaries should generally be replaced with source links unless the
  binary itself is the research artifact.

## Active Cleanup State

The first cleanup pass added repo guardrails, redacted current-tree credential
material, and removed a small set of scanner-hotspot binary artifacts.

The first reorganization pass created `cloud/` and `containers/`, then moved the
low-risk cloud and container runtime material into those domains. The repo still
needs historical leak review before any history rewrite decision.

The AI reorganization pass created `ai/`, moved MCP and LLM material under it,
and grouped OpenAI/provider experiments under `ai/providers/openai/`.
