# Podman as a Docker Desktop alternative

## Prerequisites

1. Install Homebrew from https://brew.sh

## Install Podman

```shell
$ brew install podman
$ podman machine init # optionally configure memory / CPU / disk sizes
```

If you want to share your host filesystem with the guest VM, provide the `-v` option to set the host path and the location where it should be mapped to. For convenience, I use the same path in both cases to avoid needing to remember that mapping on every `podman run` command:

```bash
$ podman machine init -v $(realpath ~/Projects):$(realpath ~/Projects)
```

## Using Podman

When you want to run containers, start the VM which Podman will use to run them:

```shell
$ podman machine start
```

The `podman` CLI is mostly compatible with the `docker` CLI. You can either retrain your memory or add an alias to your shell configuration:

```shell
$ alias docker podman
```

### Docker Compose

As of 3.x, podman works with Compose. See e.g. https://www.redhat.com/sysadmin/podman-docker-compose for a tutorial.

If you run into problems with compose builds failing with this error it's because of [compatibility issues with BuildKit](https://github.com/containers/podman/issues/13889) which are in the process of being resolved. You can avoid those by setting `DOCKER_BUILDKIT=0` in your environment:

```bash
$ docker-compose create
[+] Building 0.0s (0/0)                                                                                                                
listing workers for Build: failed to list workers: Unavailable: connection error: desc = "transport: Error while dialing unable to upgrade to h2c, received 404"
$ DOCKER_BUILDKIT=0 docker-compose up
Sending build context to Docker daemon  2.723GB
STEP 1/16: FROM amazonlinux:2
…
```

### Legacy networking

Podman does not support the legacy Docker network linking feature (`docker run --link`) which has been deprecated by Docker as well. You can replace this with the new [network](https://podman.io/getting-started/network.html) calls ([`podman network create`](https://docs.podman.io/en/latest/markdown/podman-network-create.1.html), etc.) and replacing `--link` with `--network` in your invocations, which is a good move for the future when the deprecated functionality is removed from `dockerd`.

### Apple Silicon and AMD-64 x86 container images

Thanks to [a recently-landed QEMU patch](https://github.com/Homebrew/homebrew-core/pull/85173), ARM64 containers work seamlessly. If you want to run x86 containers, the multiarch [qemu-user-static](https://github.com/multiarch/qemu-user-static) package will need a one-time install:

```shell
$ podman machine ssh podman-machine-default sudo rpm-ostree install qemu-user-static
$ podman machine ssh podman-machine-default sudo systemctl reboot
```

##
##

## Secrets

Podman now (well, for a while now) has support for secrets. RedHat has a [blog](https://www.redhat.com/sysadmin/new-podman-secrets-command) about it. This is particularly useful to 1) maintain better compatibility with Kubernetes manifests and 2) keep your secrets out of your git commits!

So, what is not well documented (that I could find) is that you can use these secrets in a Kubernetes manifest to inject secrets into environment variables. To do this, you have to first base64 encode them as you would for an actual Kubernetes secret.

Here, I'm taking a YAML snippet, using `yq` to make it to JSON, then using `jq` to create a base64 encoded JSON. Finally, pass that to podman and tell it to create a secret called `ec-creds`.

```shell
cat <<EOF | yq e -o=json | jq '{ "cloud_id": (.cloud_id | @base64 ), "cloud_auth": (.cloud_auth | @base64)}' | sudo podman secret create ec-creds -
---
cloud_id: "<CLOUD ID NAME>:<ENCODED CLOUD ID}"
cloud_auth: "<CLOUD USER>:<CLOUD PASSWORD>"
EOF
```

You can now use that in a Kubernetes manifest as normal.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: filebeat
spec:
  containers:
  - name: filebeat
    image: docker.elastic.co/beats/filebeat:7.15.0
    env:
      - name: ELASTIC_CLOUD_ID
        valueFrom:
          secretKeyRef:
            name: ec-creds
            key: cloud_id
      - name: ELASTIC_CLOUD_AUTH
        valueFrom:
          secretKeyRef:
            name: ec-creds
            key: cloud_auth
  restartPolicy: Never
```
