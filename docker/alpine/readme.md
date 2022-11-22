
##
#
https://luis-sena.medium.com/creating-the-perfect-python-dockerfile-51bdec41f1c8
#
##


Creating the Perfect Python Dockerfile
Increase your python code performance and security without changing the project source code.
Table of Contents


    Introduction
    Motivation
    Benchmarks
    Further Optimizations
    The Perfect Dockerfile for Python

Photo by SpaceX on Unsplash
Introduction

Having a reliable Dockerfile as your base can save you hours of headaches and bigger problems down the road.

This post will share the “perfect” Python Dockerfile. Of course, there is no such thing as perfection and I’ll gladly accept feedback to improve possible issues you might find.

TL;DR;

Skip to the end to find a Dockerfile that is +20% faster than using the default one in docker hub. It also contains special optimizations for gunicorn and to build faster and safer.
Motivation

In a previous project, I built an elastic transcoder farm that used Docker (Alpine), Python, and FFmpeg.

Since the system had to be very cost-efficient, I wanted to make sure the underlying docker image wasn’t creating too much overhead.
After some research, I stumbled upon this StackOverflow question that questioned the FFmpeg execution performance and my Python code when using Alpine.

Turns out, Alpine might be small but in some cases, it can slow things down quite a bit due to some of the equivalent libraries that are used.

I was disheartened. After working so well with my Go projects, I had defaulted to use it with Python to get smaller images.

This led me to start from scratch, benchmark a series of distributions, and create my new default docker image.

The contenders:

    python:3.9-alpine3.13 (the baseline)
    python:3.9
    python:3.9-slim
    python:3.9-buster
    python:3.9-slim-buster
    ubuntu 20.04 (LTS)

To benchmark, instead of reinventing the wheel, I’m just using pyperformance.

    The pyperformance project is intended to be an authoritative source of benchmarks for all Python implementations. The focus is on real-world benchmarks, rather than synthetic benchmarks, using whole applications when possible.

Comparison Table
benchmark comparison

As it turns out, Alpine is not that slower for most of the tests when comparing with the other images from the Python repo.

The big surprise was actually the fact that using Ubuntu and manually installing python was the clear winner with more than 20% margin.

That led me to believe that the biggest factor wasn’t the operating system but how python was compiled. After some research, I found this issue that seems to validate that reasoning.
Further Optimizations

Better execution speed is great, but that’s just one variable you should worry about when deploying your app.

TL;DR; You can see the full Dockerfile at the end, the following examples are meant to serve as an explanation only.

Caching

Caching in docker works by layers. Each “RUN” will create a layer that can potentially be cached.

It will check your local system for previous builds and use each untouched layer as cache.

FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3.9 python3.9-dev
COPY . .
RUN pip install -r requirements.txt
CMD ["python]

In this example, the first time you run it, it will run every single command from scratch.

For the second run, it will automatically skip all steps.

What happens when you change your code? It will use the cached layers up to this point:

RUN pip install -r requirements.txt

And then it will install all your requirements again, even though you didn’t change them.

Since installing requirements usually take the biggest slice of our build time, this is something we want to avoid.

A very simple change we can do is to copy only our requirements file and install them before we copy the code:

FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3.9 python3.9-dev
COPY requirements.txt .
RUN pip install -r requirements.txtCOPY . .
CMD ["python]

Now, even if you change your code, as long as you keep your requirements.txt untouched, it will always use cache if available.

Caching and BuildKit

BuildKit is the new Docker image builder, it brings many improvements, but we’ll mainly focus on allowing better caching with it.

    Using a remote repository as cache.

With BuildKit, in addition to the local build cache, the builder can reuse the cache generated from previous builds with the --cache-from flag pointing to an image in the registry.

To use an image as a cache source, cache metadata needs to be written into the image on creation. This can be done by setting --build-arg BUILDKIT_INLINE_CACHE=1 when building the image. After that, the built image can be used as a cache source for subsequent builds.

Upon importing the cache, the builder will only pull the JSON metadata from the registry and determine possible cache hits based on that information. If there is a cache hit, the matched layers are pulled into the local environment.

Command example:

docker build -t app --build-arg BUILDKIT_INLINE_CACHE=1 --cache-from registry-url/repo

Using a remote image as a cache is especially useful for your CI build where a cache folder might not be available and you would have cold builds for every pipeline.

    Caching pip packages

# syntax=docker/dockerfile:1.2
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3.9 python3.9-dev
COPY requirements.txt .RUN --mount=type=cache,mode=0755,target=/root/.cache pip install -r requirements.txtCOPY . .
CMD ["python"]

With this, you can tell docker to cache the /root/.cache folder which is used by pip. I find it useful for my local Dockerfiles where it’s more usual to test different packages.

Notice the first line # syntax=docker/dockerfile:1.2. Without that, the --mount command will throw an error.

Root user

Unless you really need to do some kind of black magic inside your containers, you should avoid running as root. It will make your production environment much safer if you follow the principle of least privilege (PoLP).

For the majority of scenarios, the only thing you’re doing when you’re running as root is making an attacker's life easier to exploit possible security flaws that could even allow him to control the host.

FROM ubuntu:20.04RUN useradd --create-home myuser
USER myuser
CMD ["bash"]

Virtual environment

Using virtual environment within docker can be a bit controversial but I find it has at least the following advantages:

    You get isolation from your OS default python installation
    Easy to copy packages folder between multi-stage builds
    You can use python instead of python3 or python3.9 command(Yes, there are other ways)
    You can have a single Dockerfile to run tests and deploy. Install your testing and production requirements in different “folders” in the base image and then copy to the “test stage” and “production stage”

FROM ubuntu:20.04# create and activate virtual environment
RUN python3.9 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"CMD ["python"]

In the final dockerfile, we’ll see that we just need to copy the contents of /opt/venv/ to get all the installed packages in a multi-stage build.

Multi-Stage

With docker, each layer is immutable. This means that even if you delete something that was installed in a previous layer, the total image size won’t decrease.

The recommended way to avoid bloated images is using multi-stage builds. Even if you’re just using docker for local development, saving space is always a plus!

But when we’re talking about production, where we pay in storage space, bandwidth, and download time, every saved MB counts!

# using ubuntu LTS version
FROM ubuntu:20.04 AS builder-image

RUN apt-get update && apt-get install --no-install-recommends -y python3.9 python3.9-dev python3.9-venv python3-pip python3-wheel build-essential && \
   apt-get clean && rm -rf /var/lib/apt/lists/*

# create and activate virtual environment
RUN python3.9 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# install requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

FROM ubuntu:20.04 AS runner-image
RUN apt-get update && apt-get install --no-install-recommends -y python3.9 python3-venv && \
   apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=builder-image /opt/venv /opt/venv

# activate virtual environment
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

CMD ["python"]

What we’re doing here is using the first stage as our “builder” where we install tools like the gcc compiler and then we just copy the needed files from the builder image into the runner image.

If you’re serving a Flask, Django, or any other wsgi app

This might be a tangent, but since it is a really big slice of the python ecosystem, I decided to include gunicorn optimizations too.

If you’re deploying a Flask or Django, you should always use something like gunicorn instead of running them stand alone. It will make a massive difference in performance. To know more about gunicorn, you can read this article.

gunicorn uses a file heartbeat system to keep track of the forked processes. Having it on disk can be problematic and you can even read this warning in their docs:

    The current heartbeat system involves calling os.fchmod on temporary file handlers and may block a worker for arbitrary time if the directory is on a disk-backed filesystem.

By default, it will use the /tmp folder which usually would be an in-memory mount. This is not the case with docker and if you’re already running gunicorn with docker and noticed some random freezes, this might be the cause.

In my opinion, the cleanest solution is to simply change the heartbeat directory to a memory-mapped directory inside your docker container, in this case, /dev/shm.

CMD ["gunicorn","-b", "0.0.0.0:5000", "-w", "4", "-k", "gevent", "--worker-tmp-dir", "/dev/shm", "app:app"]

In the above example, you can see how to use the gunicorn --worker-tmp-dir parameter to use /dev/shm as the heartbeat directory.
The Perfect Dockerfile for Python

Without further ado, let's see the final file.

As I said in the beginning, I will update this file with new findings and possible feedback I might get after sharing this.
Bonus

Although .dockerignore is not part of the Dockerfile, I think I should highlight the need to use it.

Just like .gitignoreit serves as a list of files and folders you want to ignore. In this case, it means excluding them from your docker build context.

This results in a faster build, smaller image, and increased security and predictability (you can exclude python cache, secrets, etc).

For some cases, you could be saving hundreds of MB just by excluding your .git folder.

#example of ignoring .git and python cache folder
.git
__pycache__
