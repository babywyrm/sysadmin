# Proving a Falco rule actually fires

The most common Falco mistake: writing a rule, seeing `schema validation: ok` at
startup, and assuming it works. **Loading is not firing.** A rule can load cleanly
and still never match — wrong field, wrong event direction, an exception that
swallows it, or a field that isn't populated for your event.

## The loop

1. **Confirm it loaded.** Startup log shows each rules file with
   `schema validation: ok`. You can also list loaded rules:
   ```
   falco -L                     # list loaded rules
   falco --list                 # list supported fields/sources
   ```
2. **Emit a known-good event** that should match. Prefer something unambiguous and
   easy to grep in the output.
3. **Confirm the alert appears** (stdout / JSON / your sink) with the expected rule
   name and fields — not just *an* alert, *your* alert.
4. **Confirm the negative** — the benign variant does **not** fire (guards against a
   rule that's too broad).

## Practical tips

- **Use a unique token in the triggering command** so you can grep unambiguously,
  e.g. run `... ZPROBE_$RANDOM ...` and `grep ZPROBE_` the output. This isolates
  *your* event from ambient noise.
- **Short-lived processes can be missed.** A binary that exits in microseconds may
  not be enriched (container/k8s metadata) by the time the rule evaluates. When
  debugging, make the test process live briefly (`sleep 2`) to rule out timing.
- **Add a temporary diagnostic rule** that prints the fields you're keying on, so
  you can see what Falco *actually* assigned:
  ```yaml
  - rule: ZZ Diag Exec Probe
    desc: temporary — prints identity fields for a tagged exec
    condition: spawned_process and container and proc.cmdline contains "ZPROBE"
    output: "DIAG name=%proc.name exe=%proc.exepath cmd=%proc.cmdline pname=%proc.pname ns=%k8s.ns.name"
    priority: WARNING
  ```
  Run your probe, read the DIAG line, then fix the real rule's field/condition.
  **Remove diagnostics before shipping.**
- **Iterating in Kubernetes:** editing `customRules` (Helm) rewrites the rules
  ConfigMap and rolls the DaemonSet. Wait for the rollout, then confirm the
  **running** pod actually has your new text (projected ConfigMaps can lag a few
  seconds):
  ```
  kubectl -n <ns> exec <falco-pod> -c falco -- grep -n '<rule name>' /etc/falco/rules.d/<file>.yaml
  ```
- **Watch for exceptions/`enabled: false`.** A later rule or a macro like
  `and not <some_exception>` may be suppressing your event by design.

## Helper scripts

`../references/tooling/` has two small runners that start Falco with full JSON
output enabled and load a specific rules file — handy for scripted "fire / no-fire"
assertions:

- `falco-json-test-runner.py`
- `falco-rule-loader.py`

## A minimal fire/no-fire checklist for any new rule

- [ ] Loads (`schema validation: ok`, appears in `falco -L`)
- [ ] Fires on the intended event (unique-token grep confirms rule name + fields)
- [ ] Does **not** fire on the benign variant
- [ ] Not suppressed by an exception you forgot about
- [ ] Field choice matches the threat model (see `custom-rules-field-reliability.md`)
- [ ] Diagnostics removed
