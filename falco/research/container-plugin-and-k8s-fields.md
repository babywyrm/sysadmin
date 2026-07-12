# The `container` plugin and `k8s.*` / `container.*` field enrichment

Rules that reference container or Kubernetes metadata —
`container.id`, `container.image.repository`, `k8s.ns.name`, `k8s.pod.name` — only
work if that metadata is actually being collected and attached to events. In modern
Falco this is done by a **plugin**, not the core libs.

## What changed

Starting with **Falco 0.41.0**, container metadata collection moved out of libsinsp
and into a dedicated **`container` plugin**. If the plugin isn't loaded (or its
runtime engines aren't pointed at the right socket), container/k8s fields silently
resolve to empty — and every rule that filters on them silently stops matching.

Symptoms of a missing/misconfigured plugin:

- `container.id` is `host` or empty on events that are clearly in containers.
- Rules with `and container` or `k8s.ns.name = "..."` never fire.
- `%k8s.pod.name` shows `<NA>` in outputs.

## What "loaded and configured" looks like

Config (`falco.yaml`):

```yaml
load_plugins:
  - container

plugins:
  - name: container
    init_config:
      engines:
        containerd:
          enabled: true
          sockets: [/run/host-containerd/containerd.sock]
        cri:
          enabled: true
          sockets: [/run/host-cri/cri.sock]
        docker:
          enabled: true
        # bpm / podman engines as needed
```

The **socket paths matter** and are runtime-specific. On k3s, containerd's socket
is `/run/k3s/containerd/containerd.sock` — set the engine socket accordingly (via
`--set collectors.containerd.socket=...` on the Helm chart, mounted into the pod).
Point the plugin at the wrong socket and enrichment quietly fails.

The stock `container` macro is simply:

```yaml
- macro: container
  condition: (container.id != host)
```

so it inherits whatever the plugin provides. If the plugin is broken, `container`
matches nothing.

## Verify enrichment is working

1. Startup log should show the plugin loaded, e.g.:
   `Loaded plugin 'container' ... libcontainer.so`.
2. Trigger an event inside a known pod and confirm the alert carries a real
   `container.id` / `k8s.pod.name` (not `host` / `<NA>`).
3. If fields are empty, check the engine socket paths and that the host socket is
   mounted into the Falco pod.

## Takeaway

Before trusting *any* container/k8s-scoped rule, confirm the `container` plugin is
loaded **and** enriching. It's a common silent failure mode after upgrades or when
copying rules between clusters with different runtimes/socket paths.
