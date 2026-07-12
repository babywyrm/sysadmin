# Detecting Docker-socket abuse (and why name-based rules aren't enough)

A container with `/var/run/docker.sock` bind-mounted can create a new, privileged
container that bind-mounts the host filesystem — an effective host takeover. This
note covers how to detect it, and the evasion gap that trips up naive rules.

## The attack, briefly

Given access to the docker socket from inside a container, an attacker asks the
Docker daemon (which runs as root on the host) to launch a container like:

```
POST /containers/create   {"Image":"busybox","Cmd":["cat","/host/etc/shadow"],
                           "HostConfig":{"Binds":["/:/host:ro"]}}
POST /containers/{id}/start
```

The daemon does the privileged work; the calling container never needs privileges
itself. Reads/writes land on the host via the bind mount.

## Detection layers

### Layer 1 — tripwire on the client (cheap, evadable)

Catch the common case: someone runs a container-management CLI, or names the socket
on the command line.

```yaml
- rule: Container Mgmt CLI in Container
  desc: A container-management client or a direct docker.sock reference inside a container.
  condition: >
    spawned_process and container
    and (proc.cmdline contains "docker"  or proc.cmdline contains "nerdctl"
         or proc.cmdline contains "podman" or proc.cmdline contains "ctr "
         or proc.cmdline contains "docker.sock")
  output: "container-mgmt activity in container (cmd=%proc.cmdline pod=%k8s.pod.name image=%container.image.repository)"
  priority: WARNING
  tags: [container, escape]
```

This fires for `docker ...`, `nerdctl ...`, and even
`curl --unix-socket /var/run/docker.sock ...`.

**Evasion gap:** it will NOT fire if the attacker speaks the Docker HTTP API over
the socket *from code* (e.g., a Python `http.client` over an `AF_UNIX` socket read
from stdin/a file), because none of the trigger strings appear in `argv`. A
`proc.name`-based version is even weaker (rename the binary → miss). See
`custom-rules-field-reliability.md`.

### Layer 2 — detect the socket connection itself

Watch for any process `connect()`ing to the docker socket path. This catches the
raw-API technique that Layer 1 misses, regardless of the process name:

```yaml
- macro: docker_socket
  condition: (fd.name = /var/run/docker.sock or fd.name = /run/docker.sock)

- rule: Connection To Docker Socket From Container
  desc: A process inside a container opened the Docker daemon socket.
  condition: (evt.type in (connect, sendto, sendmsg)) and container and docker_socket
  output: "docker.sock accessed from container (proc=%proc.name exe=%proc.exepath cmd=%proc.cmdline pod=%k8s.pod.name)"
  priority: WARNING
  tags: [container, escape]
```

Prevention beats detection here: **don't mount the socket into workloads.** If a
mount is unavoidable, treat any access as high severity.

### Layer 3 — detect the effect (strongest)

The most reliable signal is the *outcome*: a new container appears with a host
bind mount or privileges, or a process runs against a host-mounted path. Approaches:

- Alert on containers started with sensitive host mounts / `privileged` (the stock
  ruleset has related rules like *"Launch Privileged Container"* and
  *"Launch Sensitive Mount Container"*; enable the incubating/sandbox feeds to get
  the fuller set).
- Watch reads of sensitive host paths (`/etc/shadow`, cloud cred files) from
  unexpected processes.
- Correlate: docker-socket `connect` **followed by** a new privileged container.

## Recommended posture

1. **Remove the socket mount** from workloads (policy/admission control).
2. Deploy **Layer 2** (socket-connect) as the primary detection — it's name/argv
   independent.
3. Keep **Layer 1** as a cheap high-signal tripwire.
4. Add **Layer 3** effect-based rules for defense in depth.
5. Test each layer actually fires (`rule-testing-methodology.md`).
