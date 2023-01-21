Dockerfile - executing shell script file on Entrypoint

While creating auto deployment process, sometime it is needed that you will have to run bash shell script on Entrypoint or at starting point of container. Like you may need to execute multiple commands at start point of container which is not easy to do that. But fortunetly , you can add shell script file in Entrypoint and it will get executed.

Here is the example how you can run shell script from file on Entrypoint in dockerfile.

init.sh file
```

#!/bin/bash
npm install
npx prisma generate
npx start

```
Dockerfile

##########
```

FROM node:16-alpine3.11

ADD init.sh /usr/src/app/init.sh
USER root
RUN chmod +x /usr/src/app/init.sh
ENV PORT 5000
EXPOSE $PORT
ENTRYPOINT ["sh","/usr/src/app/init.sh"]
```


##
## https://devopscube.com/run-scripts-docker-arguments/
##

Use Case:  You need to run a custom shell script on your Docker container with arguments passed to the script. These arguments decide how the script runs inside the container.

We will look into running custom shell scripts inside a Docker container with command line arguments in this guide.
Table of Contents

    Executing Commands Using CMD Vs ENTRYPOINT
    How To Run Custom Script Inside Docker

The key Dockerfile instructions used for this use case are

    ENTRYPOINT: Here you will specify the command that has to be executed when the container starts. The default ENTRYPOINT command is /bin/sh -c
    CMD:  It acts as an argument for ENTRYPOINT.

cloud engineer
Executing Commands Using CMD Vs ENTRYPOINT

Let’s take an example of the following Dockerfile. It installs http-tools and starts the ab (apache benchmark) utility using CMD and Entrypoint. Both do the same job.

Using CMD

```
FROM centos:7
MAINTAINER Devopscube
RUN yum -y update && \
    yum -y install httpd-tools && \
    yum clean all
CMD ["ab"]
```

Using ENTRYPOINT: 

```
FROM centos:7
MAINTAINER Devopscube
RUN yum -y update && \
    yum -y install httpd-tools && \
    yum clean all
ENTRYPOINT ["ab"]
```

Now if you run the container from the above Dockerfile images, it will throw the following error.

➜  docker run demo
ab: wrong number of arguments
Usage: ab [options] [http[s]://]hostname[:port]/path
Options are:
    -n requests     Number of requests to perform

The reason is, ab command requires an http endpoint as an argument to start the service.

We have two ways to get around this problem. Hardcode the HTTP endpoint argument as shown in the below examples.

Using CMD: The ab executable and HTTP URL arguments are added in separate square brackets.

FROM centos:7
MAINTAINER Devopscube
RUN yum -y update && \
    yum -y install httpd-tools && \
    yum clean all
CMD ["ab"] ["http://google.com/"]

Using ENTRYPOINT: The executable and argument are separated by commas in the same square bracket.

FROM centos:7
MAINTAINER Devopscube
RUN yum -y update && \
    yum -y install httpd-tools && \
    yum clean all
ENTRYPOINT ["ab" , "http://google.com/" ]

Here is the key difference between CMD and ENTRYPOINT

Using CMD:

Just add the full ab command at the end of the docker run command. It will override the whole CMD specified in the Dockerfile.

Dockerfile:

FROM centos:7
MAINTAINER Devopscube
RUN yum -y update && \
    yum -y install httpd-tools && \
    yum clean all
CMD ["ab"]

Docker Command:

docker run ab-demo ab http://google.com/

Using ENTRYPOINT:

You cannot override the whole ENTRYPOINT like you do with CMD

So if you want to pass the URL argument to ENTRYPOINT, you need to pass the URL alone. The reason is we have the ab command as part of the ENTRYPOINT definition.

And the URL you pass in the run command will be appended to the ENTRYPOINT script. In this case, CMD instruction is not required in the Dockerfile.

Dockerfile:

FROM centos:7
MAINTAINER Devopscube
RUN yum -y update && \
    yum -y install httpd-tools && \
    yum clean all
ENTRYPOINT ["ab"]

Docker Command:

docker run ab-demo http://google.com/

You can also use both CMD and ENTRYPOINT instructions to achieve this. Here is how the Dockerfile looks.

FROM centos:7
MAINTAINER Devopscube
RUN yum -y update && \
    yum -y install httpd-tools && \
    yum clean all
ENTRYPOINT ["ab"]
CMD ["http://dummy-url.com/"]

When ENTRYPOINT and CMD used in the same Dockerfile, everything in the CMD instruction will be appended to the ENTRYPOINT as an argument.

If you run a container using the above Dockerfile, at container start, ab script will get executed with the dummy-url.com as an argument.
Also Read
Keep Docker Container Running

    DDOCKER

How to Keep Docker Container Running for Debugging

    by
    devopscube
    April 18, 2021

How To Run Custom Script Inside Docker

In this example, we have a custom shell script which accepts three command line arguments ($1, $2 & $3). If you pass true as the the first argument, the script will run in a infinite loop. Other two arguments are just to print the values.

Step 1: Create a script.sh file and copy the following contents.

#!/bin/bash
set -x
while $1
do
    echo "Press [CTRL+C] to stop.."
    sleep 5
    echo "My second and third argument is $2 & $3"
done

Step 2: You should have the script.sh is the same folder where you have the Dockerfile. 

Create the Dockerfile with the following contents which copy the script to the container and runs it part of the ENTRYPOINT using the arguments from CMD.
We are passing true as the first argument, so the script will run in an infinite loop echoing batman and superman arguments as outputs.

```
FROM centos:7
MAINTAINER Devopscube
RUN yum -y update && \
    yum -y install httpd && \
    yum clean all
COPY ./script.sh /
RUN chmod +x /script.sh
ENTRYPOINT ["/script.sh"]
CMD ["true", "batman", "superman"]
```

Step 3: let’s build a docker image from this Dockerfile with name script-demo.

docker build -t script-demo .

Step 4: Now lets create a container named demo using script-demo image.

docker run --name demo -d script-demo

You can check the container logs using the following command.

docker logs demo -f

Step 4: You can also pass the CMD arguments at the end of docker run command. It will override the arguments passed in the Dockerfile. For example,

docker run --name demo -d script-demo false spiderman hulk

Here "false spiderman hulk" will override "true", "batman", "superman" present in the docker image

##
##
