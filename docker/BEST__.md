How to write great
container images

# That Man
# That Myth 

##
#
https://www.bejarano.io/how-to-write-great-container-images/
#
##

Published Jun 19, 2019 by Ricard Bejarano

Containers, like any other complex technology, can be confusing.

One very common flaw in users’ understanding of containers is how container images are built.

In this post I will lay out what I consider to be “best practices” on designing container images, and simultaneously walk you through them with a real example: we are going to write a Redis image!

Before we begin…
There are some key distinctions to make before proceeding:

Container image: filesystem bundle, meant to be unpacked into a container, as defined by the OCI Image Format Specification.

Dockerfile: manifest syntax for building Dockerfiles.

A Dockerfile: a file in the Dockerfile syntax, containing the instructions to build a container image.

It is important to understand that Dockerfiles and container images are totally different concepts. You can build a container image without a Dockerfile, manually or with tools such as Buildah.

In this walkthrough, I am going to write a Dockerfile, in the Dockerfile syntax, in order to build a container image.

Best practice #1: follow best practices
There exists already a collection of Dockerfile best practices.
Follow them before proceeding.

Best practice #2: compile your app on build
Why?
Doing so requires compiling a list of your app’s build-time dependencies, which is very useful as documentation.

Dockerfiles are nothing but machine-readable lists of instructions. Assuming your Dockerfile works, you can refer users to it when asked about build instructions.

This also removes dependency on software repositories, which is good for reliability, and great for security.

It also enables you to tune compile-time flags, if needed.

How?
ADD your source into your image, install your build-time dependencies, and compile your application:
```
# Dockerfile:
FROM debian

ARG DEBIAN_FRONTEND='noninteractive'
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        gcc \
        make

ARG REDIS_VERSION="6.2.5"
ADD https://download.redis.io/releases/redis-$REDIS_VERSION.tar.gz /tmp/redis.tar.gz
RUN tar -C /tmp -xf /tmp/redis.tar.gz \
    && cd /tmp/redis-$REDIS_VERSION \
    && make CFLAGS='-fstack-protector-all' LDFLAGS='-z relro -z now'  # tuning compile-time flags to enable binary protections (more info: https://wiki.debian.org/Hardening)

```
Best practice #3: package from scratch
Why?
As above, doing so requires compiling a list of your app’s run-time dependencies, which is always useful.

By only including the required contents, your image will inherit no bloat from base layers (such as package managers, unused shared libraries, etc.), which increases image size and can be leveraged by attackers, for little to no utility to us during run-time.

How?
Use multi-stage builds.

First create a build stage to compile your app, then create a FROM scratch stage and COPY --from=build your binaries and run-time dependencies into it:
```
# Dockerfile:
FROM debian AS build

ARG DEBIAN_FRONTEND='noninteractive'
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        gcc \
        make

ARG REDIS_VERSION="6.2.5"
ADD https://download.redis.io/releases/redis-$REDIS_VERSION.tar.gz /tmp/redis.tar.gz
RUN tar -C /tmp -xf /tmp/redis.tar.gz \
    && cd /tmp/redis-$REDIS_VERSION \
    && make CFLAGS='-fstack-protector-all' LDFLAGS='-z relro -z now'

RUN mkdir -p /rootfs/data \
    && cp /tmp/redis-$REDIS_VERSION/src/redis-server /rootfs/ \
    && mkdir -p /rootfs/lib/x86_64-linux-gnu \
    && cp \
        /lib/x86_64-linux-gnu/libc.so.6 \
        /lib/x86_64-linux-gnu/libdl.so.2 \
        /lib/x86_64-linux-gnu/libm.so.6 \
        /lib/x86_64-linux-gnu/librt.so.1 \
        /lib/x86_64-linux-gnu/libpthread.so.0 \
        /rootfs/lib/x86_64-linux-gnu/ \
    && mkdir -p /rootfs/lib64 \
    && cp /lib64/ld-linux-x86-64.so.2 /rootfs/lib64/

```
FROM scratch

COPY --from=build /rootfs /
Best practice #4: don’t run as root
Why?
Security. Running as a user other than root adds another layer of protection, if an exploit were to require container root privileges.

How?
Some applications may require root privileges during initialization, for things such as binding to privileged ports. Tipically, you can tune configuration to listen on other ports, in order to run as non-root.

Create the redis user (/etc/passwd) and group (/etc/group), change ownership of the image’s contents to it, and set the USER:
```
# Dockerfile:
FROM debian AS build

ARG DEBIAN_FRONTEND='noninteractive'
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        gcc \
        make

ARG REDIS_VERSION="6.2.5"
ADD https://download.redis.io/releases/redis-$REDIS_VERSION.tar.gz /tmp/redis.tar.gz
RUN tar -C /tmp -xf /tmp/redis.tar.gz \
    && cd /tmp/redis-$REDIS_VERSION \
    && make CFLAGS='-fstack-protector-all' LDFLAGS='-z relro -z now'

RUN mkdir -p /rootfs/data \
    && cp /tmp/redis-$REDIS_VERSION/src/redis-server /rootfs/ \
    && mkdir -p /rootfs/lib/x86_64-linux-gnu \
    && cp \
        /lib/x86_64-linux-gnu/libc.so.6 \
        /lib/x86_64-linux-gnu/libdl.so.2 \
        /lib/x86_64-linux-gnu/libm.so.6 \
        /lib/x86_64-linux-gnu/librt.so.1 \
        /lib/x86_64-linux-gnu/libpthread.so.0 \
        /rootfs/lib/x86_64-linux-gnu/ \
    && mkdir -p /rootfs/lib64 \
    && cp /lib64/ld-linux-x86-64.so.2 /rootfs/lib64/ \
    && mkdir -p /rootfs/etc \
    && echo 'redis:*:10000:10000::/:/redis-server' > /rootfs/etc/passwd \
    && echo 'redis:*:10000:redis' > /rootfs/etc/group
```

FROM scratch

COPY --from=build --chown=10000:10000 /rootfs /

USER redis:redis
WORKDIR /data
Best practice #5: export your volumes
Why?
Storage is hard, using the VOLUME clause for data volumes makes operation easier.

How?
Add the VOLUME clause followed by the path to your data volume:

# Dockerfile:
# ...

VOLUME ["/data"]
Best practice #6: expose your ports
Why?
It makes your administrator’s job easier.

How?
Add an EXPOSE clause with the ports your app exposes:

# Dockerfile:
# ...

EXPOSE 6379/TCP
Best practice #7: set your stop signal
Why?
If your application handles any form of state, it is recommended to let your process exit gracefully.

If your app takes something other than a SIGTERM (default) as its stop signal, use the STOPSIGNAL clause.

How?
In our case, Redis stops gracefully upon receiving a SIGTERM, so we can skip this step. HAProxy, on the other hand, uses SIGUSR1.

If you still want to make it explicit:

# Dockerfile:
# ...

STOPSIGNAL SIGTERM
Best practice #8: ENTRYPOINT vs. CMD
I’ve lost count of the number of times I’ve been asked the difference between ENTRYPOINT and CMD during job interviews.

For those who don’t know, think of ENTRYPOINT as your binary and CMD as the arguments you pass it.

Why?
Properly configuring these gives you versatility, if you want to change the arguments with which your entrypoint is invoked without repackaging the image.

How?
In our case it’s pretty simple. Our binary is /redis-server and our arguments are --protected-mode no (to allow external connections):

# Dockerfile:
# ...

ENTRYPOINT ["/redis-server"]
CMD ["--protected-mode", "no"]
Best practice #9: keep an open assembly line
If you are offering your image to the public, please have an open continuous integration pipeline so that users can verify the integrity of the images they download from your registry.

Why?
Open-source etiquette.

It is a major red flag for me when an image was “recently updated” but the build log shows the last build was “2 years ago”.

This means the image maintainers are pushing the builds from somewhere else, so we can’t verify the integrity of the supply chain.

It could have been built with a different Dockerfile, for all we know.

How?
Set up your CI pipeline to build and push your image to your registries.

Best practice #10: host your images on 2 registries
Why?
You never know when one may go down. All major public registries have, at some point, gone down, either totally or partially. Some go down multiple times a quarter.

Your service may be interrupted. Your service provider may, knowingly or otherwise, suspend your service. A backup means your images are still available while you sort things out.

How?
Pick two container registry providers (or run your own), then configure your aforementioned CI pipeline to push images to both.

That’s all!
Here’s the final Dockerfile:
```
# Dockerfile:
FROM debian AS build

ARG DEBIAN_FRONTEND='noninteractive'
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        gcc \
        make

ARG REDIS_VERSION="6.2.5"
ADD https://download.redis.io/releases/redis-$REDIS_VERSION.tar.gz /tmp/redis.tar.gz
RUN tar -C /tmp -xf /tmp/redis.tar.gz \
    && cd /tmp/redis-$REDIS_VERSION \
    && make CFLAGS='-fstack-protector-all' LDFLAGS='-z relro -z now'

RUN mkdir -p /rootfs/data \
    && cp /tmp/redis-$REDIS_VERSION/src/redis-server /rootfs/ \
    && mkdir -p /rootfs/lib/x86_64-linux-gnu \
    && cp \
        /lib/x86_64-linux-gnu/libc.so.6 \
        /lib/x86_64-linux-gnu/libdl.so.2 \
        /lib/x86_64-linux-gnu/libm.so.6 \
        /lib/x86_64-linux-gnu/librt.so.1 \
        /lib/x86_64-linux-gnu/libpthread.so.0 \
        /rootfs/lib/x86_64-linux-gnu/ \
    && mkdir -p /rootfs/lib64 \
    && cp /lib64/ld-linux-x86-64.so.2 /rootfs/lib64/ \
    && mkdir -p /rootfs/etc \
    && echo 'redis:*:10000:10000::/:/redis-server' > /rootfs/etc/passwd \
    && echo 'redis:*:10000:redis' > /rootfs/etc/group


FROM scratch

COPY --from=build --chown=10000:10000 /rootfs /

USER redis:redis
WORKDIR /data
VOLUME ["/data"]
EXPOSE 6379/TCP
ENTRYPOINT ["/redis-server"]
CMD ["--protected-mode", "no"]
```
