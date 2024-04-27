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


# How to sign and distribute container images using Podman and GPG

First of all, we have to create a GPG key pair or select a locally available
one:

```bash
> gpg --list-keys sgrunert@suse.com
pub   rsa2048 2018-11-26 [SC] [expires: 2020-11-25]
      92836C5387398A449AF794CF8CE029DD1A866E52
uid           [ultimate] Sascha Grunert <sgrunert@suse.com>
sub   rsa2048 2018-11-26 [E] [expires: 2020-11-25]
```

Now let’s assume that we run a container registry, for example on our local
machine:

```bash
> sudo podman run -d -p 5000:5000 registry
```

The registry does not know anything about image signing, it just provides the remote
storage for the container images. This means if we want to sign an image, we
have to take care on our own how to distribute the GPG keys in the environment.

We choose a standard image `alpine` image for our signing experiment:

```bash
> sudo podman pull docker://docker.io/alpine:latest
> sudo podman images alpine
REPOSITORY                 TAG      IMAGE ID       CREATED       SIZE
docker.io/library/alpine   latest   e7d92cdc71fe   6 weeks ago   5.86 MB
```

Now we re-tag the image to target it to our local registry:

```bash
> sudo podman tag alpine localhost:5000/alpine
> sudo podman images alpine
REPOSITORY                 TAG      IMAGE ID       CREATED       SIZE
localhost:5000/alpine      latest   e7d92cdc71fe   6 weeks ago   5.86 MB
docker.io/library/alpine   latest   e7d92cdc71fe   6 weeks ago   5.86 MB
```

Podman would now be able to push the image and sign it in one command. But to
let this work, we have to modify our registries configuration at
`/etc/containers/registries.d/default.yaml`:

```yaml
# This is the default signature write location for docker registries.
default-docker:
  sigstore: http://localhost:8000
  sigstore-staging: file:///var/lib/containers/sigstore
```

We have two signature stores configured:

- `sigstore`: referencing a web server for signature reading
- `sigstore-staging`: referencing a file path for signature writing

Now, let’s push and sign the image:

```bash
> sudo -E GNUPGHOME=$HOME/.gnupg \
    podman push \
    --tls-verify=false \
    --sign-by sgrunert@suse.com \
    localhost:5000/alpine
…
Storing signatures
```

If we now take a look at the signature storage, then we see that there is a new
signature available, which was caused by the image push:

```bash
> sudo ls /var/lib/containers/sigstore
'alpine@sha256=e9b65ef660a3ff91d28cc50eba84f21798a6c5c39b4dd165047db49e84ae1fb9'
```

The default signature store in
`/etc/containers/registries.d/default.yaml`references a web server listening at
`http://localhost:8000`. For our experiment, we simply start the server inside
the local staging signature store:

```bash
> sudo bash -c 'cd /var/lib/containers/sigstore && python3 -m http.server'
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Let’ remove the local images for our final test:

```
> sudo podman rmi docker.io/alpine localhost:5000/alpine
```

We have to write a policy to enforce that the signature has to be valid. This
can be done via a new rule in `/etc/containers/policy.json`:

```json
{
  "default": [{ "type": "insecureAcceptAnything" }],
  "transports": {
    "docker": {
      "localhost:5000": [
        {
          "type": "signedBy",
          "keyType": "GPGKeys",
          "keyPath": "/tmp/key.gpg"
        }
      ]
    }
  }
}
```

The `keyPath` does not exist yet, so we have to put the GPG key there:

```bash
> gpg --output /tmp/key.pgp --armor --export sgrunert@suse.com
```

If we now pull the image:

```bash
> sudo podman pull --tls-verify=false localhost:5000/alpine
…
Storing signatures
e7d92cdc71feacf90708cb59182d0df1b911f8ae022d29e8e95d75ca6a99776a
```

Then we can see in the logs of the web server that the signature has been
accessed:

```
127.0.0.1 - - [04/Mar/2020 11:18:21] "GET /alpine@sha256=e9b65ef660a3ff91d28cc50eba84f21798a6c5c39b4dd165047db49e84ae1fb9/signature-1 HTTP/1.1" 200 -
```

As an counterpart example, if we specify the wrong key at `/tmp/key.pgp`:

```bash
> gpg --output /tmp/key.pgp --armor --export mail@saschagrunert.de
File '/tmp/key.pgp' exists. Overwrite? (y/N) y
```

Then a pull is not possible any more:

```bash
> sudo podman pull --tls-verify=false localhost:5000/alpine
Trying to pull localhost:5000/alpine...
Error: error pulling image "localhost:5000/alpine": unable to pull localhost:5000/alpine: unable to pull image: Source image rejected: Invalid GPG signature: …
```

