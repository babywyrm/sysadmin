##
#
https://gist.github.com/weltonrodrigo/1ee41b4a474a5f292297a25659ead81d
#
##

  
Using dive (container explorer tool) with a remote docker

When using DOCKER_HOST with a remote daemon, like DOCKER_HOST=ssh:user@vm:22, you'll get an error when using dive to explore an image.

$ dive ubuntu:latest

Image Source: docker://ubuntu:latest
Fetching image... (this can take a while for large images)
Handler not available locally. Trying to pull 'ubuntu:latest'...
latest: Pulling from library/ubuntu
08c01a0ec47e: Pull complete 
Digest: sha256:669e010b58baf5beb2836b253c1fd5768333f0d1dbcb834f7c07a4dc93f474be
Status: Downloaded newer image for ubuntu:latest
docker.io/library/ubuntu:latest
cannot fetch image
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?

I think Dive don't support remote contexts rigth away.

But it can run as a container in the remote host itself with:
```
docker run --rm -it \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v  "$(pwd)":"$(pwd)" \
      -w "$(pwd)" \
      -v "$HOME/.dive.yaml":"$HOME/.dive.yaml" \
      wagoodman/dive:latest bash:latest
```

Image Source: docker://ubuntu:latest
Fetching image... (this can take a while for large images)
Analyzing image...
Building cache...

Then it works!

By the way, if you didn't now it was possible to run docker remotely ( like on a cloud instance ) this article will show you how to configure it.

Hint: SSH authentication and ~/.ssh/config
