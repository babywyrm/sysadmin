##
#
https://gist.github.com/weltonrodrigo/1ee41b4a474a5f292297a25659ead81d
#
##

  
Using dive (container explorer tool) with a remote docker

When using DOCKER_HOST with a remote daemon, like DOCKER_HOST=ssh:user@vm:22, you'll get an error when using dive to explore an image.

```
$ dive ubuntu:latest
```

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





```
Course url: https://linuxacademy.com/containers/training/course/name/docker-deep-dive-part-1

==================== All Docker Command While Learning Docker =========================
Get a list of all of the Docker commands:

docker -h

====== Attaching to Container , run in background , name it ==========

Create a container and attach to it:

docker container run –it busybox
Create a container and run it in the background:

docker container run –d nginx
Create a container that you name and run it in the background:

docker container run –d –name myContainer busybox

========== Exposing Ports =======================

docker container run --expose 1234 [IMAGE]
Publishing:

Maps a container's port to a host`s port
-p or --publish publishes a container's port(s) to the host
-P, or --publish-all publishes all exposed ports to random ports
docker container run -p [HOST_PORT]:[CONTAINER_PORT] [IMAGE]
docker container run -p [HOST_PORT]:[CONTAINER_PORT]/tcp -p [HOST_PORT]:[CONTAINER_PORT]/udp [IMAGE]
docker container run -P

Lists all port mappings or a specific mapping for a container:

docker container port [Container_NAME]

========  Executing Container Commands ====== 
Start a container with a command:

docker container run [IMAGE] [CMD]
Execute a command on a container:

docker container exec -it [NAME] [CMD]
Example:

docker container run -d -p 8080:80 nginx
docker container ps
docker container exec -it [NAME] /bin/bash
docker container exec -it [NAME] ls /usr/share/nginx/html/

======= Container Logging best practices of containerized applications============

Create a container using the weather-app image.

docker container run --name weather-app -d -p 80:3000 linuxacademycontent/weather-app
Show information logged by a running container:

docker container logs [NAME]
Show information logged by all containers participating in a service:

docker service logs [SERVICE]
Logs need to be output to STDOUT and STDERR.

Nginx Example:

RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log
Debug a failed container deploy:

docker container run -d --name ghost_blog \
-e database__client=mysql \
-e database__connection__host=mysql \
-e database__connection__user=root \
-e database__connection__password=P4sSw0rd0! \
-e database__connection__database=ghost \
-p 8080:2368 \
ghost:1-alpine

Useful Link:
12 Factor Logs: https://12factor.net/logs 
Weather App code: https://github.com/linuxacademy/content-intermediate-docker-quest/tree/logging 

============= Docker Networking Details ===============

Docker Networking:

Open-source pluggable architecture
Container Network Model (CNM)
libnetwork implements CNM

Drivers extend the network topologies
Network Drivers:
bridge
host
overlay
macvlan
none
Network plugins


Container Network Model defines three building blocks:
Sandboxes
Endpoints
Networks




============= Docker Networking commands================

Networking Commands
Networking Basics
ifconfig


List all Docker network commands:

docker network -h
connect Connect a container to a network create Create a network disconnect Disconnect a container from a network inspect Display detailed information on one or more networks ls List networks prune Remove all unused networks rm Remove one or more networks

List all Docker networks on the host:

docker network ls
docker network ls --no-trunc
Getting detailed info on a network:

docker network inspect [NAME]
Creating a network:

docker network create br00
Deleting a network:

docker network rm [NAME]
Remove all unused networks:

docker network prune
Adding and Removing containers to a network
Create a container with no network:

docker container run -d --name network-test03 -p 8081:80 nginx
Create a new network:

docker network create br01
Add the container to the bridge network:

docker network connect br01 network-test03
Inspect network-test03 to see the networks:

docker container inspect network-test03
Remove network-test03 from br01:

docker network disconnect br01 network-test03


=========== Networking Containers Commands =========
Creating a network and defining a Subnet and Gateway
Create a bridge network with a subnet and gateway:

docker network create --subnet 10.1.0.0/24 --gateway 10.1.0.1 br02
Run ifconfig to view the bridge interface for br02:

ifconfig
Inspect the br02 network:

docker network inspect br02
Prune all unused networks:

docker network prune
Create a network with an IP range:

docker network create --subnet 10.1.0.0/16 --gateway 10.1.0.1 \
--ip-range=10.1.4.0/24 --driver=bridge --label=host4network br04
Inspect the br04 network:

docker network inspect br04
Create a container using the br04 network:

docker container run --name network-test01 -it --network br04 centos /bin/bash
Install Net Tools:

yum update -y
yum install -y net-tools
Get the IP info for the container:

ifconfig
Get the gateway info the container:

netstat -rn
Get the DNS info for the container:

cat /etc/resolv.conf
Assigning IPs to a container:
Create a new container and assign an IP to it:

docker container run -d --name network-test02 --ip 10.1.4.102 --network br04 nginx
Get the IP info for the container:

docker container inspect network-test02 | grep IPAddr
Inspect network-test03 to see that br01 was removed:

docker container inspect network-test04
Networking two containers
Create an internal network:

docker network create -d bridge --internal localhost
Create a MySQL container that is connected to localhost:

docker container run -d --name test_mysql \
-e MYSQL_ROOT_PASSWORD=P4sSw0rd0 \
--network localhost mysql:5.7
Create a container that can ping the MySQL container:

docker container run -it --name ping-mysql \
--network bridge --network localhost \
centos
Create a container that can't ping the MySQL container:

docker container run -it --name cant-ping-mysql \
centos
Create a Nginx container that is not publicly accessible:

docker container run -d --name private-nginx -p 8081:80 --network localhost nginx
Inspect private-nginx:

docker container inspect private-nginx



=============== Docker Volume Commands ====================
List all volumes on a host:

docker volume ls
Create two new volumes:

docker volume create test-volume1
docker volume create test-volume2
Get the flags available when creating a volume:

docker volume create -h
Inspecting a volume:

docker volume inspect test-volume1
Deleting a volume:

docker volume rm test-volume
Removing all unused volumes:

docker volume prune


==== Using Bind Mounts:
Using the mount flag:

mkdir target

docker container run -d \
  --name nginx-bind-mount1 \
  --mount type=bind,source="$(pwd)"/target,target=/app \
  nginx
docker container ls
Bind mounts won't show up when listing volumes:

docker volume ls
Inspect the container to find the bind mount:

docker container inspect nginx-bind-mount1
Create a new file in /app on the container:

docker container exec -it nginx-bind-mount1 /bin/bash
cd target
touch file1.txt
ls
exit
Using the volume flag:

docker container run -d \
 --name nginx-bind-mount2 \
 -v "$(pwd)"/target2:/app \
 nginx
Create /app/file3.txt in the container:

docker container exec -it nginx-bind-mount2 touch /app/file3.txt
ls target2
Create an nginx.conf file:

mkdir nginx
cat << EOF >  nginx/nginx.conf
user  nginx;
worker_processes  1;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;
}
EOF
Create an Nginx container that creates a bind mount to nginx.conf:

docker container run -d \
 --name nginx-bind-mount3 \
 -v "$(pwd)"/nginx/nginx.conf:/etc/nginx/nginx.conf \
 nginx
Look at the bind mount by inspecting the container:

docker container inspect nginx-bind-mount3


======== Using Volumes for Persistent Storage ========

Create a new volume for an Nginx container:

docker volume create html-volume
Creating a volume using that volume mount:

docker container run -d \
 --name nginx-volume1 \
 --mount type=volume,source=html-volume,target=/usr/share/nginx/html/ \
 nginx
Inspect the volume:

docker volume inspect html-volume
List the contents of html-volume:

sudo ls /var/lib/docker/volumes/html-volume/_data
Creating a volume using that volume flag:

docker container run -d \
 --name nginx-volume2 \
 -v html-volume:/usr/share/nginx/html/ \
 nginx
Edit index.html:

sudo vi /var/lib/docker/volumes/html-volume/_data/index.html
Inspect nginx-volume2 to get the private IP:

docker container inspect nginx-volume2
Login into nginx-volume1 and go to the html directory:

docker container exec -it nginx-volume1 /bin/bash
cd /usr/share/nginx/html
cat index.hml
Install Vim:

apt-get update -y
apt-get install vim -y
Using a readonly volume:

docker run -d \
  --name=nginx-volume3 \
  --mount source=html-volume,target=/usr/share/nginx/html,readonly \
  nginx
Login into nginx-volume3 and go to the html directory:

docker container exec -it nginx-volume3 /bin/bash
cd /usr/share/nginx/html
cat index.hml
Install Vim:

apt-get update -y
apt-get install vim -y


========== Notes on Docker Images ========================

To make docker image we need dockerfile.

Below is the important notes on docker images. 

What is the Dockerfile?
Dockerfiles are instructions. They contains all of the commands used to build an image.

Docker images consist of read-only layers.
Each represents a Dockerfile instruction.
Layers are stacked.
Each layer is a result of the changes from the previous layer.
Images are built using the docker image build command.
Dockerfile Layers

Dockerfile:  
FROM ubuntu:15.04  
COPY . /app  
RUN make /app  
CMD python /app/app.py
FROM creates a layer from the ubuntu:15.04 Docker image.
COPY adds files from your Docker client’s current directory.
RUN builds your application with make.
CMD specifies what command to run within the container.


Best Practices
General guidelines:
Keep containers as ephemeral as possible.
Follow Principle 6 of the 12 Factor App.
Avoid including unnecessary files.
Use .dockerignore.
Use multi-stage builds.
Don’t install unnecessary packages.
Decouple applications.
Minimize the number of layers.
Sort multi-line arguments.
Leverage build cache.


======== Dockerfile : working with instructions =========

FROM: Initializes a new build stage and sets the Base Image

RUN: Will execute any commands in a new layer

CMD: Provides a default for an executing container. There can only be one CMD instruction in a Dockerfile

LABEL: Adds metadata to an image

EXPOSE: Informs Docker that the container listens on the specified network ports at runtime

ENV: Sets the environment variable <key> to the value <value>

ADD: Copies new files, directories or remote file URLs from <src> and adds them to the filesystem of the image at the path <dest>.

COPY: Copies new files or directories from <src> and adds them to the filesystem of the container at the path <dest>.

ENTRYPOINT: Allows for configuring a container that will run as an executable

VOLUME: Creates a mount point with the specified name and marks it as holding externally mounted volumes from native host or other containers

USER: Sets the user name (or UID) and optionally the user group (or GID) to use when running the image and for any RUN, CMD, and ENTRYPOINT instructions that follow it in the Dockerfile

WORKDIR: Sets the working directory for any RUN, CMD, ENTRYPOINT, COPY, and ADD instructions that follow it in the Dockerfile

ARG: Defines a variable that users can pass at build-time to the builder with the docker build command, using the --build-arg <varname>=<value> flag

ONBUILD: Adds a trigger instruction to the image that will be executed at a later time, when the image is used as the base for another build

HEALTHCHECK: Tells Docker how to test a container to check that it is still working

SHELL: Allows the default shell used for the shell form of commands to be overridden

To set up the environment:

sudo yum install git -y
mkdir docker_images
cd docker_images
mkdir weather-app
cd weather-app
git clone https://github.com/linuxacademy/content-weather-app.git src
Create the Dockerfile:

vi Dockerfile
Dockerfile contents:

# Create an image for the weather-app
FROM node
LABEL org.label-schema.version=v1.1
RUN mkdir -p /var/node
ADD src/ /var/node/
WORKDIR /var/node
RUN npm install
EXPOSE 3000
CMD ./bin/www
Build the weather-app image:

docker image build -t linuxacademy/weather-app:v1 .
List the images:

docker image ls
Create the weather-app container:

docker container run -d --name weather-app1 -p 8081:3000 linuxacademy/weather-app:v1
List all running containers:

docker container ls


===== Using Environement varibale in docker via docker file  ======
Use the --env flag to pass an environment variable when building an image:

--env [KEY]=[VALUE]
Use the ENV instruction in the Dockerfile:

ENV [KEY]=[VALUE]  
ENV [KEY] [VALUE]
Clone the weather-app:

git clone https://github.com/linuxacademy/content-weather-app.git src
Create the Dockerfile

vi Dockerfile
Dockerfile contents:

# Create an image for the weather-app
FROM node
LABEL org.label-schema.version=v1.1
ENV NODE_ENV="development"
ENV PORT 3000

RUN mkdir -p /var/node
ADD src/ /var/node/
WORKDIR /var/node
RUN npm install
EXPOSE $PORT
CMD ./bin/www
Create the weather-app container:

docker image build -t linuxacademy/weather-app:v2 .
Inspect the container to see the environment variables:

docker image inspect linuxacademy/weather-app:v2
Deploy the weather-dev application:

docker container run -d --name weather-dev -p 8082:3001 --env PORT=3001 linuxacademy/weather-app:v2
Inspect the development container to see the environment variables:

docker container inspect weather-dev
Deploy the weather-app to production:

docker container run -d --name weather-app2 -p 8083:3001 --env PORT=3001 --env NODE_ENV=production linuxacademy/weather-app:v2
Inspect the production container to see the environment variables:

docker container inspect weather-app2
Get the logs for weather-app2:

docker container logs weather-app2
docker container run -d --name weather-prod -p 8084:3000 --env NODE_ENV=production linuxacademy/weather-app:v2


========== Using Build Arguments ================ 

Build Arguments
In this lesson, we will explore using build arguments to paramerterize an image build.

Use the --build-arg flag when building an image:

--build-arg [NAME]=[VALUE]
Use the ARG instruction in the Dockerfile:

ARG [NAME]=[DEFAULT_VALUE]
Navigate to the args directory:

cd docker_images
mkdir args
cd args
Clone the weather-app:

git clone https://github.com/linuxacademy/content-weather-app.git src
Create the Dockerfile:

vi Dockerfile
Dockerfile:

# Create an image for the weather-app
FROM node
LABEL org.label-schema.version=v1.1
ARG SRC_DIR=/var/node

RUN mkdir -p $SRC_DIR
ADD src/ $SRC_DIR
WORKDIR $SRC_DIR
RUN npm install
EXPOSE 3000
CMD ./bin/www
Create the weather-app container:

docker image build -t linuxacademy/weather-app:v3 --build-arg SRC_DIR=/var/code .
Inspect the image:

docker image inspect linuxacademy/weather-app:v3 | grep WorkingDir
Create the weather-app container:

docker container run -d --name weather-app3 -p 8085:3000 linuxacademy/weather-app:v3
Verify that the container is working by executing curl:

curl localhost:8085

=============== Working with Non-privileged User ============


In this lesson, you will learn how to use the USER instruction to create a non-privileged user. Rather than using root, we can use a non-privileged user to configure and run an application.

Setup your environment:

cd docker_images
mkdir non-privileged-user
cd non-privileged-user
Create the Dockerfile:

vi Dockerfile
Dockerfile contents:

# Creates a CentOS image that uses cloud_user as a non-privileged user
FROM centos:latest
RUN useradd -ms /bin/bash cloud_user
USER cloud_user
Build the new image:

docker image build -t centos7/nonroot:v1 .
Create a container using the new image:

docker container run -it --name test-build centos7/nonroot:v1 /bin/bash
Connecting as a privileged user:

docker container start test-build
docker container exec -u 0 -it test-build /bin/bash
Set up the environment:

cd ~/docker_images
mkdir node-non-privileged-user
cd node-non-privileged-user
Create the Dockerfile:

vi Dockerfile
Dockerfile contents:

# Create an image for the weather-app
FROM node
LABEL org.label-schema.version=v1.1
RUN useradd -ms /bin/bash node_user
USER node_user
ADD src/ /home/node_user
WORKDIR /home/node_user
RUN npm install
EXPOSE 3000
CMD ./bin/www
git clone https://github.com/linuxacademy/content-weather-app.git src
Build the weather-app image using the non-privileged user node_user:

docker image build -t linuxacademy/weather-app-nonroot:v1 .
Create a container using the linuxacademy/weather-app-nonroot:v1 image:

docker container run -d --name weather-app-nonroot -p 8086:3000 linuxacademy/weather-app-nonroot:v1



==== Using the Volume Instruction====

When a container is created using this image, a volume will be created and mounted to the specified directory.

Set up your environment:

cd docker_images
mkdir volumes
cd volumes
Create the Dockerfile:

vi Dockerfile
Build an Nginx image that uses a volume:

FROM nginx:latest
VOLUME ["/usr/share/nginx/html/"]
Build the new image:

docker image build -t linuxacademy/nginx:v1 .
Create a new container using the linuxacademy/nginx:v1 image:

docker container run -d --name nginx-volume linuxacademy/nginx:v1
Inspect nginx-volume:

docker container inspect nginx-volume
List the volumes:

docker volume ls | grep [VOLUME_NAME]
Inspect the volumes:

docker volume inspect [VOLUME_NAME]


===========  ENTRYPOINT Instruction ====
similarly to CMD it's behaviors are vary different.

ENTRYPOINT allows us to configure a container that will run as an executable.
We can override all elements specified using CMD.
Using the docker run --entrypoint flag will override the ENTRYPOINT instruction.
Setup your environment:

cd docker_images
mkdir entrypoint
cd entrypoint
Create the Dockerfile:

vi Dockerfile
Dockerfile contents:

# Create an image for the weather-app
FROM node
LABEL org.label-schema.version=v1.1
ENV NODE_ENV="production"
ENV PORT 3001

RUN mkdir -p /var/node
ADD src/ /var/node/
WORKDIR /var/node
RUN npm install
EXPOSE $PORT
ENTRYPOINT ./bin/www

========= Using .dockerignore file  =============

create a .dockerignore file, so that we can exclude files we don't want copied over when building an image.

Setup your environment:

cd docker_images
mkdir dockerignore
cd dockerignore
git clone https://github.com/linuxacademy/content-weather-app.git src
cd src
git checkout dockerignore
cd ../
Create the .dockerignore file:

vi .dockerignore
Add the following to .dockerignore:

# Ignore these files
*/*.md
*/.git
src/docs/
*/tests/
Create the Dockerfile:

vi Dockerfile
Dockerfile contents:

# Create an image for the weather-app
FROM node
LABEL org.label-schema.version=v1.1
ENV NODE_ENV="production"
ENV PORT 3000

RUN mkdir -p /var/node
ADD src/ /var/node/
WORKDIR /var/node
RUN npm install
EXPOSE $PORT
ENTRYPOINT ["./bin/www"]
Build the image:

docker image build -t linuxacademy/weather-app:v5 .
Create the weather-app container:

docker container run -d --name weather-app-ignore linuxacademy/weather-app:v5
List the contents of /var/node:

docker container exec weather-app-ignore ls -la /var/node



====== Deeper understanding in building images ========

To build one:

docker image build -t <NAME>:<TAG> .
Useful flags:

-f, --file string: This is the name of the Dockerfile (Default is PATH/Dockerfile).
--force-rm: Always remove intermediate containers.
--label list: Set metadata for an image.
--rm: Remove intermediate containers after a successful build (default is true).
--ulimit ulimit: This sets ulimit options (default is []).
cd docker_images/weather-app
cp Dockerfile Dockerfile.test
docker image build -t linuxacademy/weather-app:path-example1 -f Dockerfile.test .
docker image build -t linuxacademy/weather-app:path-example2 --label com.linuxacademy.version=v1.8 -f Dockerfile.test .
Building image by piping the Dockerfile through STDIN:

docker image build -t <NAME>:<TAG> -<<EOF
Build instructions
EOF
Example:

docker image build -t linuxacademy/nginx:stind --rm -<<EOF
FROM nginx:latest
VOLUME ["/usr/share/nginx/html/"]
EOF
Building an image using a URL:

docker image build -t <NAME>:<TAG> <GIT_URL>#<REF>
docker image build -t <NAME>:<TAG> <GIT_URL>#:<DIRECTORY>
docker image build -t <NAME>:<TAG> <GIT_URL>#<REF>:<DIRECTORY>
Example:

docker image build -t linuxacademy/weather-app:github https://github.com/linuxacademy/content-weather-app.git#remote-build
Building an image from a zip file:

docker image build -t <NAME>:<TAG> - < <FILE>.tar.gz
Example:

cd docker_images
mkdir tar_image
cd tar_image
git clone https://github.com/linuxacademy/content-weather-app.
cd content-weather-app
git checkout remote-build
tar -zcvf weather-app.tar.gz Dockerfile src
docker image build -t linuxacademy/weather-app:from-tar - < weather-app.tar.gz


======== Making a Multi Stage Build ======== 
By default, the stages are not named
Stages are numbered with integers
Starting with 0 for the first FROM instruction
Name the stage by adding as to the FROM instruction
Reference the stage name in the COPY instruction
Set up your environment:

cd docker_images
mkdir multi-stage-builds
cd multi-stage-builds
git clone https://github.com/linuxacademy/content-weather-app.git src
Create the Dockerfile:

vi Dockerfile
Dockerfile contents:

# Create an image for the weather-app using multi-stage build
FROM node AS build
RUN mkdir -p /var/node/
ADD src/ /var/node/
WORKDIR /var/node
RUN npm install

FROM node:alpine
ARG VERSION=V1.1
LABEL org.label-schema.version=$VERSION
ENV NODE_ENV="production"
COPY --from=build /var/node /var/node
WORKDIR /var/node
EXPOSE 3000
ENTRYPOINT ["./bin/www"]
Build the image:

docker image build -t linuxacademy/weather-app:multi-stage-build --rm --build-arg VERSION=1.5 .
List images to see the size difference:

docker image ls
Create the weather-app container:

docker container run -d --name multi-stage-build -p 8087:3000 linuxacademy/weather-app:multi-stage-build


========== Detailed notes on tagging ==========

tagging.

Add a name and an optional tag with -t or --tag, in the name:tag format:

docker image build -t <name>:<tag>
docker image build --tag <name>:<tag>
List your images:

docker image ls
Use our Git commit hash as the image tag:

git log -1 --pretty=%H
Use the Docker tag to a create a new tagged image:

docker tag <SOURCE_IMAGE><:TAG> <TARGET_IMAGE>:<TAG>
Get the commit hash:

cd docker_images/weather-app/src
git log -1 --pretty=%H
cd ../
Build the image using the Git hash as the tag:

docker image build -t linuxacademy/weather-app:<GIT_HASH> .
Tag the weather-app as the latest using the image tagged with the commit hash:

docker image tag linuxacademy/weather-app:<GIT_HASH> linuxacademy/weather-app:latest
```
