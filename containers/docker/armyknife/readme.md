##
#
https://github.com/MWhyte/swiss-army-knife
#
##

```
FROM nicolaka/netshoot

# Install OpenJDK-8
RUN apk update && apk add openjdk8

# Kafka
ARG kafka_version=3.6.1
ENV kafka_bin_version=2.13-$kafka_version

RUN apk add --no-cache --update-cache --virtual build-dependencies curl ca-certificates \
  && mkdir -p /opt/kafka \
  && curl -SLs "https://www-eu.apache.org/dist/kafka/$kafka_version/kafka_$kafka_bin_version.tgz" | tar -xzf - --strip-components=1 -C /opt/kafka \
  && apk del build-dependencies \
  && rm -rf /var/cache/apk/*

ENV PATH /sbin:/opt/kafka/bin/:$PATH
WORKDIR /opt/kafka
VOLUME ["/tmp/kafka-logs"]

# Kafka Cat
RUN apk add kafkacat

# Postgres
RUN apk add postgresql

# MS Sql Server
RUN curl -O https://download.microsoft.com/download/e/4/e/e4e67866-dffd-428c-aac7-8d28ddafb39b/msodbcsql17_17.6.1.1-1_amd64.apk
RUN curl -O https://download.microsoft.com/download/e/4/e/e4e67866-dffd-428c-aac7-8d28ddafb39b/mssql-tools_17.6.1.1-1_amd64.apk
RUN apk add --allow-untrusted msodbcsql17_17.6.1.1-1_amd64.apk
RUN apk add --allow-untrusted mssql-tools_17.6.1.1-1_amd64.apk
ENV PATH /opt/mssql-tools/bin:$PATH


# Redis
RUN apk --update add redis


# Install grpcurl
RUN curl -sSL "https://github.com/fullstorydev/grpcurl/releases/download/v1.8.7/grpcurl_1.8.7_linux_x86_64.tar.gz" | tar -xz -C /usr/local/bin

# https://github.com/vadimi/grpc-client-cli
RUN curl -L https://github.com/vadimi/grpc-client-cli/releases/download/v1.15.0/grpc-client-cli_linux_x86_64.tar.gz | tar -C /usr/local/bin -xz

# Install ghz
RUN curl -L https://github.com/bojand/ghz/releases/download/v0.117.0/ghz-linux-x86_64.tar.gz | tar -C /usr/local/bin -xz

# custom binaries
COPY binaries/ /app/
ENV PATH "$PATH:/app"
```

# Swiss army knife

This image extends from the base: 
[nicolaka/netshoot](https://github.com/nicolaka/netshoot) 
and adds some additional libraries:

- Java 
- Kafka
- Kafkacat
- Postgres
- Redis
- MS Sql Server
- gRPCurl

## Building 
```
docker build --tag mwhyte/swiss-army-knife .
```

## Running for testing
```
docker run --rm -it --name test mwhyte/swiss-army-knife
```

## publishing
```
docker push mwhyte/swiss-army-knife
```

Pushed to dockerhub [mwhyte/swiss-army-knife](https://hub.docker.com/repository/docker/mrwhyte/swiss-army-knife) 


# Docker System Admin and Troubleshooting Toolkit
[![Docker Build Automated](https://img.shields.io/docker/automated/jonathadv/admin-toolkit.svg)](https://hub.docker.com/r/jonathadv/admin-toolkit/)
[![Docker Build Status](https://img.shields.io/docker/cloud/build/jonathadv/admin-toolkit.svg)](https://hub.docker.com/r/jonathadv/admin-toolkit/)
[![Docker Pulls](https://img.shields.io/docker/pulls/jonathadv/admin-toolkit.svg)](https://hub.docker.com/r/jonathadv/admin-toolkit/)

This project focus on providing system administration and troubleshooting tools without the need of installing them in the host system.

## Tools

* **bash** - GNU Bourne-Again SHell.
* **bind-tools** - The ISC DNS tools (dig, nslookup, host).
* **curl** - Tool to transfer data from or to a server.
* **htop** - A ncurses-based process viewer for Linux. (built from source, allows to watch the **host's processes**)
* **iotop** - Simple top-like I/O monitor.
* **iptraf-ng** - An IP Network Monitoring tool.
* **jq** - Commandline JSON processor.
* **nano** - Text Editor. GNU nano is designed to be a free replacement for the Pico text editor.
* **netcat** - Utility which reads and writes data across network connections using TCP or UDP protocol.
* **net-tools** - Includes network tools such as arp, ifconfig, netstat, rarp, nameif and route.
* **openssh-client** - OpenSSH SSH client.
* **python 2** - An interpreted, interactive, object-oriented programming language.
* **sysstat** - System performance tools for the Linux operating system.
* **tcpdump** - Dump traffic on a network.
* **tshark** - network protoccol analyzer - console version.
* **vim** - Vi IMproved, a programmers text editor.

## Running the container

Use `--net=host` allows `tcpdump` to access the host's network interfaces.

Use `-v /proc:/proc_host` allows `htop` to watch the host's processes. Note that `htop` is unable to kill any host's processes.

Optionally you can create a local directory and map it to the container like `-v /tmp/data/:/tmp/data/`:

```bash
mkdir /tmp/data

docker run \
    --rm \
    --name toolkit \
    --net=host \
    -v /proc:/proc_host \
    -v /tmp/data/:/tmp/data/ \
    -it \
    jonathadv/admin-toolkit \
    bash
```
