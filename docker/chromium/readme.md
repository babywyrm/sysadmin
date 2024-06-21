
##
#
https://github.com/monstrenyatko/docker-chromium
#
https://github.com/chromedp/docker-headless-shell
#
##


```
FROM monstrenyatko/alpine:2024-06-01

LABEL maintainer="Oleg Kovalenko <monstrenyatko@gmail.com>"

RUN apk update && \
    apk add bash shadow supervisor fluxbox x11vnc xvfb novnc chromium && \
    # open novnc by default
    ln -s /usr/share/novnc/vnc.html /usr/share/novnc/index.html && \
    # clean-up
    rm -rf /root/.cache && mkdir -p /root/.cache && \
    rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*

# replace favicon
COPY icon.svg /usr/share/novnc/app/images/icons/novnc-icon-sm.svg
COPY icon.svg /usr/share/novnc/app/images/icons/novnc-icon.svg
RUN buildDeps='make imagemagick rsvg-convert';SHELL=/bin/bash; \
    # novnc makefile syntax requires bash => make bash temporary the default shell
    mv /bin/sh /bin/sh.bkp && \
    ln -s /bin/bash /bin/sh && \
    apk update && \
    apk add $buildDeps && \
    cd /usr/share/novnc/app/images/icons/ && \
    make --always-make && \
    rm /bin/sh && \
    mv /bin/sh.bkp /bin/sh && \
    # clean-up
    apk del $buildDeps && \
    rm -rf /root/.cache && mkdir -p /root/.cache && \
    rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*

ENV APP_NAME="chromium-app" \
    SYS_USERNAME="daemon" \
    SYS_GROUPNAME="daemon" \
    APP_USERNAME="chromium" \
    APP_GROUPNAME="chromium" \
    APP_USERHOME="/data"

RUN addgroup $APP_GROUPNAME && \
    adduser -D -h $APP_USERHOME -G $APP_GROUPNAME $APP_USERNAME

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8 \
    LC_ALL=C.UTF-8 \
    LOG_LEVEL=info \
    DISPLAY=:0.0 \
    DISPLAY_WIDTH=1024 \
    DISPLAY_HEIGHT=768 \
    WEBSOCKIFY_PARAMS= \
    CHROMIUM_PARAMS= \
    XDG_CONFIG_HOME=/data/config \
    XDG_CACHE_HOME=/data/cache

COPY conf.d /app/conf.d
COPY run.sh supervisord.conf /app/
RUN chown -R root:root /app
RUN chmod -R 0744 /app
RUN chmod 0755 /app/run.sh

VOLUME ["/data"]

ENTRYPOINT ["/app/run.sh"]
CMD ["chromium-app"]
```

docker-compose

```
version: '2'
services:
  chromium:
    image: ${DOCKER_REGISTRY}monstrenyatko/chromium
    container_name: chromium
    cap_add:
      - SYS_ADMIN
    environment:
      - LOG_LEVEL=info
      - DISPLAY_WIDTH=1600
      - DISPLAY_HEIGHT=968
    volumes:
      - chromium-data:/data:rw
    ports:
      - "8080:5980"
    shm_size: '128mb'
    restart: unless-stopped
volumes:
  chromium-data:
```

old-lol
```
FROM alpine:3.12
# Add chromium and its dependencies
# based on https://github.com/puppeteer/puppeteer/blob/main/docs/troubleshooting.md#running-on-alpine
# but without nodejs and yarn
RUN apk add --no-cache --update chromium \
        nss \
        freetype \
        freetype-dev \
        harfbuzz \
        ca-certificates \
        ttf-freefont
RUN rm -rf /var/cache/apk
ENV CHROME_BIN /usr/bin/chromium-browser

# Options for chromium
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
# npm is not supposed to run inside this container, so this is
# unnecessary.
#
# ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

# Create chromium user
# as in https://github.com/puppeteer/puppeteer/blob/main/docs/troubleshooting.md#running-on-alpine
# but 'chromium' user, not 'pptruser'
RUN addgroup -S chromium && adduser -S -g chromium chromium \
    && mkdir -p /home/chromium/Downloads /app \
    && chown -R chromium:chromium /home/chromium \
    && chown -R chromium:chromium /app

USER chromium
```


lol
```
#!/bin/bash

VERSION=${1:-101.0.4951.64-0ubuntu0.18.04.1}
TAG=${2:-chromium_101.0}
BASE_TAG=${3:-7.3.6}

# Cleanup stuff
export BUILDKIT_PROGRESS=plain
docker rmi -f selenoid/vnc:$TAG browsers/base:$BASE_TAG $(docker images -q selenoid/dev_chromium:*)
rm -rf ../selenoid-container-tests

# Prepare for building images
go install github.com/markbates/pkger/cmd/pkger@latest
go generate github.com/aerokube/images
go build

# Forked tests with a bugfix
git clone -b add-missing-dependency https://github.com/sskorol/selenoid-container-tests.git ../selenoid-container-tests

# Force build browsers/base image as it has arm64-specific updates
cd ./selenium/base && docker build --no-cache --build-arg UBUNTU_VERSION=18.04 -t browsers/base:$BASE_TAG . && docker system prune -f

# Build chromium image
cd ../../ && ./images chromium -b $VERSION -t selenoid/vnc:$TAG --test && docker system prune -f
