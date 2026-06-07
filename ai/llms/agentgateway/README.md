# Agentgateway Notes

This directory contains agent gateway deployment and security material for
LLM/MCP-style traffic.

## Files

- `helm___.md`: Hardened reference architecture and operational notes for a
  DPoP-authenticated Agentgateway MCP/API proxy on Kubernetes.
- `chart.yaml`, `values.yaml`, `templates/`, `files/`: Helm chart material and
  supporting configuration captured with the architecture notes.

## Handling Notes

Treat this as a reference deployment sketch. Review secrets, JWKS material,
runtime identity assumptions, and Kubernetes policy before adapting it.
