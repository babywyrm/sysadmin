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



Podman and libpod bindings
go.mod
module example.com

go 1.14

require (
	github.com/containers/libpod v1.9.3 // indirect
	github.com/containers/podman/v2 v2.1.1 // indirect
)
main.go
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/containers/podman/v2/pkg/bindings"
	"github.com/containers/podman/v2/pkg/bindings/containers"
	"github.com/containers/podman/v2/pkg/bindings/images"
	"github.com/containers/podman/v2/pkg/domain/entities"
	"github.com/containers/podman/v2/pkg/specgen"
)

func main() {
	fmt.Println("Looking for a postgreSQL running container...")
	dbDockerName := "postgres"
	// Connection to podman API
	sock_dir := os.Getenv("XDG_RUNTIME_DIR")
	socket := "unix:" + sock_dir + "/podman/podman.sock"
	connText, err := bindings.NewConnection(context.Background(), socket)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Container list
	var latestContainers = 3
	containerLatestList, err := containers.List(connText, nil, nil, &latestContainers, nil, nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var cont_id string

	for cont := 0; cont <= len(containerLatestList)-1; cont++ {
		if containerLatestList[cont].Names[0] == dbDockerName {
			cont_id = containerLatestList[cont].ID
			fmt.Printf("Found container with name postgres: %s\n", cont_id)
		}
	}

	if cont_id == "" {
		// Pull Postgres image
		rawImage := "docker.io/library/postgres:12.3-alpine"
		fmt.Println("Pulling Postgres image...")
		_, err = images.Pull(connText, rawImage, entities.ImagePullOptions{})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		s := specgen.NewSpecGenerator(rawImage, false)
		s.Name = dbDockerName
		s.Terminal = true
		s.Env = map[string]string{
			"POSTGRES_PASSWORD": "admin",
			"POSTGRES_USER":     "admin",
		}
		_, err := containers.CreateWithSpec(connText, s)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	// Container start
	fmt.Println("Starting Postgres container...")
	err = containers.Start(connText, dbDockerName, nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Container inspect
	ctrData, err := containers.Inspect(connText, dbDockerName, nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Container uses image %s\n", ctrData.ImageName)
	fmt.Printf("Container running status is %s\n", ctrData.State.Status)
}


##
#
https://gist.github.com/kaaquist/dab64aeb52a815b935b11c86202761a3
#
##


# Podman with docker-compose on MacOS.  
> Podman an alternative to Docker Desktop on MacOS  

Getting podman installed and started is super easy.  
Just use `brew` to install it. 
```
> brew install podman
```
Now since podman uses a VM just like the Docker Client on MacOS we need to initialize that and start it.
```
> podman machine init
> podman machine start
```
Now we are set to go. 

If you want you can create a symlink so podman can be executed with "docker" command.  
```
> ln -s /usr/local/bin/podman /usr/local/bin/docker
```
Now most of the commands in podman are the same so try `podman images` and you will get a list of images.  
Else the `podman --help` command list all the help you need.  


To get `docker-compose` without the docker client for mac. You can install it using the `brew` command.  
```
> brew install docker-compose
```
When that is done you now should have the ability to use `docker-compose` with `podman`.  

On MacOS the podman project does not expose the `podman.socket` which is similar to `docker.socket`, by default. So to get `docker-compose` working one needs to expose the socket.  

To get the socket running run the following commands.  
First we need to find the port it is exposed on in the VM.  
```
> podman system connection ls
``` 

Then we need to take that port and create a forward ssh connection to that.  
```
> ssh -fnNT -L/tmp/podman.sock:/run/user/1000/podman/podman.sock -i ~/.ssh/podman-machine-default ssh://core@localhost:<port to socket> -o StreamLocalBindUnlink=yes
> export DOCKER_HOST='unix:///tmp/podman.sock'
```
Second, we expose the `DOCKER_HOST` env variable that is used by `docker-compose`. 

Be aware that if the connection is disconnected one needs to delete/overwrite the `/tmp/podman.socket` to run the forward command.  

Overall findings is that if one only runs single images then it is fairly easy to get going using podman. But if you rely on the `compose` part to orchestrate the containers in a bigger setup of different images with networking etc. then `podman` is a lot less easy to get working "out of the box". There is a lot of googling involved and then it still seems that there are a lot of the features that are not too easy to get working. I did have a lot of issues getting the right permissions to mount drives into the images. One of the main features with podman is that it is rootless. Which is great but it means that you need to understand what permissions a container needs before it fully works. 
I have tried to use the `podman-compose` as the goto instead of `docker-compose`, but I had a hard time even getting it installed, and there were alot of issues where it could not load images from the local repository, so in the end that is why I decided to use `docker-compose` and not `podman-compose`. Another thing is that `podman-compose` is also developed by people not really part of the `podman` community it seems, or it is not set to be the frist choice by the `podman` community. So it seems that it is a project that has its own agenda, and is run by a few people and not as many as the `podman` community.
For now I got it working but I will say that there are many wheels that need tuning and kept updated to have the setup running in a daily development environment. 
So if you, like me, just want to use the tools and not need to finetune all the time, it seems a little like there is a way to go before `podman` takes over the MacOS setup. Next for me is to try to setup everything on my linux laptop and see if this works easier out of the box.
