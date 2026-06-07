# Containers

Container runtime, image, sandbox, and related hardening research lives here.

## Layout

- `docker/`: Docker operations, hardening, Compose examples, CVE notes, and labs.
- `alpine/`: Alpine container and VM experiments.
- `busybox/`: BusyBox container notes and Dockerfiles.
- `podman/`: Podman, rootless containers, Falco notes, and compose experiments.
- `nerdctl/`: nerdctl and containerd notes.
- `firecracker/`: Firecracker setup and measurement notes.

## Boundaries

- Kubernetes manifests and cluster operations belong under the future
  `kubernetes/` area.
- Cloud registry material such as ECR belongs under `cloud/aws/ecr/`.
- Application security labs remain in their appsec or language-specific areas
  until the appsec migration phase.
