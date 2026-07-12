# Field selection in Falco rules: reliability & evasion

> TL;DR — the process field you match on decides **two** things at once: whether
> your rule fires at all, and how trivially an attacker sidesteps it. Pick the
> field for your threat model, and **test that it actually fires** (see
> `rule-testing-methodology.md`).

## The process-identity fields

| Field | Source | Spoofable by attacker? | Notes |
|-------|--------|------------------------|-------|
| `proc.name` | kernel `comm` | **Yes, trivially** | `comm` is capped at 16 bytes (15 chars + NUL); set from the exec'd binary's basename but changeable via `prctl(PR_SET_NAME)`, a rename, or a wrapper. Truncated for long names. |
| `proc.exe` | `argv[0]` as presented | Yes | Whatever the caller put in `argv[0]`; an attacker controls it. |
| `proc.exepath` | resolved `/proc/<pid>/exe` | Harder | The real on-disk executable path. Best "what binary is this actually" signal; still not identity of *behavior*. |
| `proc.cmdline` | full argv (name + args) | Partly | What operators usually "see in the logs." Great for catching tool invocations, but bypassable with interpreters/wrappers, and `contains` matching is FP-prone. |
| `proc.pname` / `proc.aname[N]` | ancestry | — | Parent / N-th ancestor name; useful to anchor context (e.g., "shell spawned by nginx"). |

## Field-behavior caveat we hit (worth knowing)

On **Falco 0.44.x with the `modern_ebpf` driver and the `container` plugin loaded**,
a rule of the form:

```yaml
condition: spawned_process and container and proc.name in (container_mgmt_binaries)
```

did **not** reliably fire for a **short-lived, freshly-`exec`'d, renamed** binary
in a container, while the equivalent `proc.cmdline contains "..."` matched every
time. We did not fully root-cause it (candidate explanations: `comm` / container
enrichment not yet populated at the exact event that matched, event-direction
subtleties, or the process exiting before enrichment completed). We are **not**
claiming `proc.name` is broken in general — the upstream stable ruleset uses it
heavily and it works for long-lived/known processes.

**Practical takeaways:**

1. **Never assume a field matched — prove it.** Schema-validation `ok` at load time
   says nothing about runtime firing. Drive the exact event and confirm an alert
   (see `rule-testing-methodology.md`).
2. **Match the field to the goal:**
   - *"What binary is really running?"* → `proc.exepath` (resolved path), not `proc.name`.
   - *"Did someone invoke tool X?"* → `proc.cmdline contains "X"` is a high-signal
     tripwire (and also catches `curl --unix-socket .../docker.sock`, etc.).
   - *"Is this the expected process for this workload?"* → anchor with ancestry
     (`proc.pname` / `proc.aname[N]`) and image (`container.image.repository`).
3. **Assume single-field name checks are evadable.** `proc.name`/`proc.cmdline`
   are defeated by renaming or by driving the same syscall from an interpreter
   (e.g., speaking a unix socket's API directly from code instead of a CLI). For
   anything that matters, add a **behavioral** layer — see
   `detecting-docker-socket-abuse.md`.

## Robustness ranking (rough, for detection engineering)

```
weakest → strongest signal of INTENT
proc.name  <  proc.cmdline  <  proc.exepath  <  behavioral effect
(argv0/comm)  (full argv)     (on-disk path)   (privileged container created,
                                                 sensitive mount, socket connect)
```

Use the cheap fields as tripwires; use behavioral/effect detection as the real
control. Layer them so evading one still trips another.

## List idioms

Reusable lists keep rules readable and match the stock style:

```yaml
- list: container_mgmt_binaries
  items: [docker, dockerd, nerdctl, podman, ctr, crictl, runc]

- macro: spawned_process
  condition: (evt.type in (execve, execveat) and evt.dir = <)
```

Quote items if they could be parsed as non-strings, and prefer referencing a
`- list:` over inlining long `in (...)` sets.
