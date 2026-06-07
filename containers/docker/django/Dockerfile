FROM python:3.6.5-alpine

WORKDIR /src

RUN apk upgrade --update-cache --available

RUN apk update

# Install bash
RUN apk add bash

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Install python
RUN apk add python3-dev musl-dev

# Install PostgreSQL libraries
RUN apk add postgresql-dev gcc g++ libxslt-dev libxml2 \
    && apk add postgresql-client --repository=http://dl-cdn.alpinelinux.org/alpine/v3.10/main

# Delete cache files used by apk
RUN rm -rf /var/cache/apk/*

# Delete cache files used by apk
RUN rm -rf /var/cache/apk/*

# Update pip
RUN pip install --upgrade pip

# To speed up the build in test environments, e.g. on a continuous integration server,
# disable the C compiler optimisations by setting the CFLAGS environment variable.
# https://lxml.de/installation.html
RUN CFLAGS="-O0"

# Install Python requirements
COPY requirements.txt /src/requirements.txt
RUN pip install --no-cache-dir -r /src/requirements.txt

COPY docker/wait-for-it.sh /src/docker/wait-for-it.sh
COPY docker/entrypoint.sh /src/docker/entrypoint.sh

COPY . /src

EXPOSE 5000

CMD ["/src/docker/entrypoint.sh"]
