

https://github.com/linuxserver/docker-chromium

```
---
services:
  chromium:
    image: lscr.io/linuxserver/chromium:latest
    container_name: chromium
    security_opt:
      - seccomp:unconfined #optional
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Etc/UTC
      - CHROME_CLI=https://www.linuxserver.io/ #optional
    volumes:
      - /path/to/config:/config
    ports:
      - 3000:3000
      - 3001:3001
    shm_size: "1gb"
    restart: unless-stopped

###
###


docker run -d \
  --name=chromium \
  --security-opt seccomp=unconfined `#optional` \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e CHROME_CLI=https://www.linuxserver.io/ `#optional` \
  -p 3000:3000 \
  -p 3001:3001 \
  -v /path/to/config:/config \
  --shm-size="1gb" \
  --restart unless-stopped \
  lscr.io/linuxserver/chromium:latest

```

Parameters

Containers are configured using parameters passed at runtime (such as those above). These parameters are separated by a colon and indicate <external>:<internal> respectively. For example, -p 8080:80 would expose port 80 from inside the container to be accessible from the host's IP on port 8080 outside the container.
Parameter 	Function
-p 3000 	Chromium desktop gui.
-p 3001 	HTTPS Chromium desktop gui.
-e PUID=1000 	for UserID - see below for explanation
-e PGID=1000 	for GroupID - see below for explanation
-e TZ=Etc/UTC 	specify a timezone to use, see this list.
-e CHROME_CLI=https://www.linuxserver.io/ 	Specify one or multiple Chromium CLI flags, this string will be passed to the application in full.
-v /config 	Users home directory in the container, stores local files and settings
--shm-size= 	This is needed for any modern website to function like youtube.
--security-opt seccomp=unconfined 	For Docker Engine only, many modern gui apps need this to function on older hosts as syscalls are unknown to Docker. Chromium runs in no-sandbox test mode without it.
Environment variables from files (Docker secrets)

You can set any environment variable from a file by using a special prepend FILE__.

As an example:

-e FILE__MYVAR=/run/secrets/mysecretvariable

Will set the environment variable MYVAR based on the contents of the /run/secrets/mysecretvariable file.
Umask for running applications

For all of our images we provide the ability to override the default umask settings for services started within the containers using the optional -e UMASK=022 setting. Keep in mind umask is not chmod it subtracts from permissions based on it's value it does not add. Please read up here before asking for support.
User / Group Identifiers

When using volumes (-v flags), permissions issues can arise between the host OS and the container, we avoid this issue by allowing you to specify the user PUID and group PGID.

Ensure any volume directories on the host are owned by the same user you specify and any permissions issues will vanish like magic.

In this instance PUID=1000 and PGID=1000, to find yours use id your_user as below:

id your_user

Example output:

uid=1000(your_user) gid=1000(your_user) groups=1000(your_user)

Docker Mods

Docker Mods Docker Universal Mods

We publish various Docker Mods to enable additional functionality within the containers. The list of Mods available for this image (if any) as well as universal mods that can be applied to any one of our images can be accessed via the dynamic badges above.
Support Info

    Shell access whilst the container is running:

    docker exec -it chromium /bin/bash

To monitor the logs of the container in realtime:

docker logs -f chromium

Container version number:

docker inspect -f '{{ index .Config.Labels "build_version" }}' chromium

Image version number:

docker inspect -f '{{ index .Config.Labels "build_version" }}' lscr.io/linuxserver/chromium:latest

Updating Info

Most of our images are static, versioned, and require an image update and container recreation to update the app inside. With some exceptions (noted in the relevant readme.md), we do not recommend or support updating apps inside the container. Please consult the Application Setup section above to see if it is recommended for the image.

Below are the instructions for updating containers:
Via Docker Compose

    Update images:

        All images:

        docker-compose pull

Single image:

docker-compose pull chromium

Update containers:

    All containers:

    docker-compose up -d

Single container:

docker-compose up -d chromium

You can also remove the old dangling images:

docker image prune

Via Docker Run

    Update the image:

    docker pull lscr.io/linuxserver/chromium:latest

Stop the running container:

docker stop chromium

Delete the container:

docker rm chromium

Recreate a new container with the same docker run parameters as instructed above (if mapped correctly to a host folder, your /config folder and settings will be preserved)

You can also remove the old dangling images:

docker image prune

Image Update Notifications - Diun (Docker Image Update Notifier)

tip: We recommend Diun for update notifications. Other tools that automatically update containers unattended are not recommended or supported.
Building locally

If you want to make local modifications to these images for development purposes or just to customize the logic:

git clone https://github.com/linuxserver/docker-chromium.git
cd docker-chromium
docker build \
  --no-cache \
  --pull \
  -t lscr.io/linuxserver/chromium:latest .

The ARM variants can be built on x86_64 hardware using multiarch/qemu-user-static

docker run --rm --privileged multiarch/qemu-user-static:register --reset

Once registered you can define the dockerfile to use with -f Dockerfile.aarch64.
Versions

##
#
https://github.com/rastasheep/alpine-node-chromium
#
##


# alpine-node-chromium

### Dockerized chromium, built on top of [official Node alpine](https://hub.docker.com/_/node/) images.

## About image

- [What, why, how?](#-what-why-how)
- [Image tags](#-image-tags)
- [Installed packages](#-installed-packages)
- [Environment variables](#-environment-variables)

### • What, why, how?

Image intended to be used in modern front-end development workflow, to be exact, with [Karma test runner](https://karma-runner.github.io/1.0/index.html) via [karma-chrome-launcher](https://github.com/karma-runner/karma-chrome-launcher) which uses headless Chromium instead traditional PhantomJS which doesn't play well with Alpine linux.

If you're interested into actual Karma configuration, it looks like:

```
  browsers: ['ChromiumNoSandbox'],
  customLaunchers: {
    ChromiumNoSandbox: {
      base: 'ChromiumHeadless',
      flags: ['--no-sandbox', '--headless', '--disable-gpu', '--disable-translate', '--disable-extensions']
    }
  }
```

### • Image tags

- rastasheep/alpine-node-chromium:14-alpine (based on: node:14-alpine)
- rastasheep/alpine-node-chromium:12-alpine (based on: node:12-alpine)
- rastasheep/alpine-node-chromium:10-alpine (based on: node:10-alpine)
- rastasheep/alpine-node-chromium:8-alpine (based on: node:8-alpine)
- rastasheep/alpine-node-chromium:7-alpine (based on: node:7-alpine)
- rastasheep/alpine-node-chromium:6-alpine (based on: node:6-alpine)
- rastasheep/alpine-node-chromium:4-alpine (based on: node:4-alpine)

### • Installed packages

Chromium stuff

- [udev](https://pkgs.alpinelinux.org/package/v3.5/main/x86_64/udev)
- [ttf-opensans](https://pkgs.alpinelinux.org/package/edge/testing/x86_64/ttf-opensans)
- [chromium](https://pkgs.alpinelinux.org/package/edge/community/x86_64/chromium)

Image optimization libs

- [gifsicle](https://pkgs.alpinelinux.org/package/edge/community/x86_64/gifsicle)
- [pngquant](https://pkgs.alpinelinux.org/package/edge/community/x86_64/pngquant)
- [optipng](https://pkgs.alpinelinux.org/package/v3.6/community/x86_64/optipng)
- [libjpeg-turbo-utils](https://pkgs.alpinelinux.org/package/edge/main/x86_64/libjpeg-turbo-utils)

### • Environment variables

- `CHROME_BIN=/usr/bin/chromium-browser`
- `LIGHTHOUSE_CHROMIUM_PATH=/usr/bin/chromium-browser`

## Issues

If you run into any problems with this image, please check (and potentially file new) issues on the [rastasheep/alpine-node-chromium](https://github.com/rastasheep/alpine-node-chromium/issues) repository, which is the source for this image.

## License

alpine-node-chromium is licensed under the [MIT license](http://opensource.org/licenses/MIT).

