# 01 — Attacker Mindset

Kubernetes security is about **control of the API server**.  
If you can talk to it, you can escalate.

Key principles:

1. **Every pod contains a credential** → a ServiceAccount token.
2. **RBAC is usually misconfigured** → least privilege is rare.
3. **Privileged pods = node compromise** with almost no exceptions.
4. **HostPath volumes bypass all boundaries.**
5. **Operators (ArgoCD, Istio, cert-manager)** often enable RCE.
6. **Cloud metadata services** = IAM privilege escalation.
7. **The API server logs everything.**  
   → Stealth requires kubectl-like traffic, delays, and narrow queries.

This diary teaches you how to move from *pod → namespace → cluster → cloud*.
