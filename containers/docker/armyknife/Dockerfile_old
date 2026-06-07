FROM alpine:3.3
MAINTAINER BehanceRE <qa-behance@adobe.com>

RUN apk update && \
  apk add \
  bash \
  netcat-openbsd \
  vim \
  htop \
  tcpdump \
  strace \
  python \
  py-pip \
  mysql-client \
  heimdal-telnet \
  perl-net-ssleay \
  perl-io-socket-ssl \
  curl \
  && \
  rm -rf /var/cache/apk/* && \
  pip install awscli

COPY .bash_profile /root/.bash_profile

CMD ['/bin/bash']
