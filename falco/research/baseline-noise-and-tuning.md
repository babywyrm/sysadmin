# Baseline noise & tuning: separating expected events from real signal

A fresh Falco install on a real node is **noisy**. Before you can trust an alert,
you have to know what "normal" looks like on that host, or you'll drown real
detections in ambient events (or, worse, tune so aggressively you blind yourself).

## Common ambient noise (usually benign)

These frequently fire on healthy nodes; understand them before silencing:

- **`Sensitive file opened for reading by non-trusted program`** — host
  `systemd`/`systemd-executor`, PAM stack, and login flows read `/etc/shadow`,
  `/etc/pam.d/*` during normal operation (service starts, logins). Very common at
  `container_id=host`.
- **`Contact K8s API Server From Container`** — any legitimate in-cluster client
  using its ServiceAccount token (operators, agents, sidecars) trips this. Expected
  for workloads that are *supposed* to talk to the API.
- **`Redirect STDOUT/STDIN to Network Connection in Container`** and
  **shell-in-container** rules — fire for legitimate `kubectl exec`, init
  containers, image build steps, and entrypoint shells.
- **Package-manager / "not part of base image" executions** — CI images, debug
  sidecars, and anything doing `apt/pip/npm` at runtime.

## Tuning approach (in order of preference)

1. **Prevent, don't just mute.** If a workload legitimately reads `/etc/shadow` or
   mounts a socket, that's often a design smell worth fixing.
2. **Scope with exceptions, not deletion.** Prefer the `exceptions:` field or a
   narrow `and not <macro>` over disabling a whole rule. Anchor exceptions to
   *stable* identity (image repository, namespace, service account) — not to a
   spoofable `proc.name`.
   ```yaml
   - macro: known_api_clients
     condition: (k8s.ns.name in (kube-system, monitoring) )

   # append, don't rewrite, the stock rule:
   - rule: Contact K8s API Server From Container
     condition: and not known_api_clients
     override:
       condition: append
   ```
3. **Allowlist by strong identity.** Image digest/repository is far better than a
   process name for "this workload is allowed to do X."
4. **Use the maturity feeds deliberately.** `stable` is quiet and
   production-oriented; `incubating`/`sandbox` add coverage but more noise. Enable
   them knowingly.
5. **Right-size priority + outputs.** Running at `priority: debug` surfaces
   everything (great for a lab, loud in prod). Ship a sensible floor and route by
   severity.

## Build a baseline first

1. Run Falco on a representative node for a while with everything on.
2. Bucket alerts by rule name; label each as *expected-ambient* vs *investigate*.
3. Write scoped exceptions for the expected-ambient set, tied to strong identity.
4. Re-run; confirm the *investigate* set is now clearly visible.
5. Document the baseline so on-call can tell noise from signal at a glance.

## Anti-patterns

- Disabling a whole rule to kill one false positive (you lose the true positives too).
- Exceptions keyed on `proc.name` / `proc.cmdline` (attacker-controllable → becomes
  an evasion primitive).
- Tuning in the rules file the vendor overwrites on upgrade — keep custom rules and
  exceptions in your own `customRules` / `rules.d` file.
