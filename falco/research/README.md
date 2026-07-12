# Falco research — field notes & reusable examples

Original, generic notes distilled from hands-on Falco rule engineering. Focused on
the things the docs don't emphasize: which fields to trust, how to prove a rule
fires, and how to keep signal above noise.

## Notes

| Doc | What it covers |
|-----|----------------|
| [`custom-rules-field-reliability.md`](custom-rules-field-reliability.md) | Choosing `proc.name` vs `proc.cmdline` vs `proc.exepath`; evasion trade-offs; a real field-behavior caveat we hit and how to work around it. |
| [`detecting-docker-socket-abuse.md`](detecting-docker-socket-abuse.md) | Three detection layers for `docker.sock` abuse (client tripwire → socket-connect → behavioral effect) and the evasion gaps of each. |
| [`rule-testing-methodology.md`](rule-testing-methodology.md) | How to *prove* a rule fires (loading ≠ firing); unique-token probes; diagnostics; K8s rollout gotchas. |
| [`container-plugin-and-k8s-fields.md`](container-plugin-and-k8s-fields.md) | Falco 0.41+ moved container metadata to a plugin; `k8s.*`/`container.*` fields silently break if it's missing/misconfigured. |
| [`baseline-noise-and-tuning.md`](baseline-noise-and-tuning.md) | Known ambient noise; tuning via scoped exceptions on strong identity; anti-patterns. |

## Examples (`examples/`)

Copy-pasteable, generic rule snippets referenced by the notes above:

- `container-mgmt-cli-watch.yaml` — client-CLI tripwire (cmdline-based) for container-mgmt tools.
- `docker-socket-connect.yaml` — name-independent detection of runtime-socket access.
- `unexpected-shell-in-container.yaml` — shell-in-container with identity-anchored exceptions.

All examples are generic and safe to adapt; validate them against your own baseline
before enforcing (see the testing + tuning notes).
