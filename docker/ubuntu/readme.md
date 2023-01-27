
```
FROM ubuntu:20.04

ENV CONTAINER_TIMEZONE="Europe/Brussels"
RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone

RUN apt update && apt install -y apache2

ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_LOG_DIR /var/log/apache2
ENV APACHE_RUN_DIR /var/www/html

RUN echo 'Hello, docker' > /var/www/index.html

ENTRYPOINT ["/usr/sbin/apache2"]
CMD ["-D", "FOREGROUND"]
```
##
##
```
FROM ubuntu:latest
LABEL maintainer="SiYu Wu <wu.siyu@hotmail.com>"

ENV DEV_USER=user
ENV UID=1000
ENV GID=1000
ENV DEF_PASSWD=password
ENV TZ=Asia/Shanghai
ENV LANG=en_US.UTF-8

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    yes | unminimize && \
    apt install -y systemd sudo openssh-server bash-completion zsh git curl vim && \
    addgroup --gid $GID $DEV_USER && \
    adduser --uid $UID --gid $GID --gecos "" --disabled-password $DEV_USER && \
    usermod -aG sudo $DEV_USER && \
    echo "$DEV_USER:$DEF_PASSWD" | chpasswd && \
    systemctl mask systemd-resolved.service && \
    echo "LANG=$LANG" > /etc/default/locale && \
    cp /usr/share/doc/util-linux/examples/securetty /etc/securetty

CMD ["systemd"]
```
##
##

# A basic apache server with PHP. To use either add or bind mount content under /var/www
# https://docs.docker.com/engine/reference/builder/
```
FROM ubuntu:16.04

# Use bash instead of sh.
SHELL ["/bin/bash", "-c"]

WORKDIR /app
ADD . /app

# Use the default UTF-8 language.
ENV LANG C.UTF-8

RUN apt-get update && apt-get -y install software-properties-common && add-apt-repository ppa:ondrej/php && apt-get update && apt-get install -y apache2 && apt-get install -y php7.2 && apt-get install -y libapache2-mod-php7.2 php7.2-curl php7.2-json && apt-get clean && rm -rf /var/lib/apt/lists/*

EXPOSE 80 443

RUN cp info.php /var/www/html/

ENTRYPOINT ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
```

##
##

```

FROM ubuntu:16.04
MAINTAINER Sriramajeyam Sugumaran "http://sriramajeyam.com"

SHELL ["/bin/sh", "-c"] 

RUN apt-get update -y
RUN apt-get install -y openssh-server rpm libpam0g-dev libkrb5-dev wget openssl python libcurl4-gnutls-dev cron sudo nano
RUN mkdir /tmp/installation
ADD ./packages/packages-microsoft-prod.deb /tmp/installation/
ADD ./packages/omi-1.1.0.ssl_100.x64.deb /tmp/installation/
ADD ./packages/dsc-1.1.1-294.ssl_100.x64.deb /tmp/installation/
ADD ./start.sh /tmp/installation/

RUN mkdir /var/run/sshd
RUN echo 'root:root' |chpasswd
RUN sed -ri 's/^PermitRootLogin\s+.*/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -ri 's/UsePAM yes/#UsePAM yes/g' /etc/ssh/sshd_config

RUN dpkg -i /tmp/installation/packages-microsoft-prod.deb

ENV RUNLEVEL=1
RUN dpkg -i /tmp/installation/omi-1.1.0.ssl_100.x64.deb
RUN /opt/omi/bin/omiconfigeditor httpport -a 5985 < /etc/opt/omi/conf/omiserver.conf>tmp.conf && mv -f tmp.conf /etc/opt/omi/conf/omiserver.conf
RUN /opt/omi/bin/omiconfigeditor httpsport -a 5986 < /etc/opt/omi/conf/omiserver.conf>tmp.conf && mv -f tmp.conf /etc/opt/omi/conf/omiserver.conf

RUN dpkg -i /tmp/installation/dsc-1.1.1-294.ssl_100.x64.deb
WORKDIR /tmp/installation
EXPOSE 22 5985 5986
ENTRYPOINT ["/bin/sh","/tmp/installation/start.sh"]
CMD    ["/usr/sbin/sshd", "-D"]

```
