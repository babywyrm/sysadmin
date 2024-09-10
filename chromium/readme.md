```
# Specify the version of Docker Compose syntax being used
version: "2.1"

# Define the services that will be managed by this Docker Compose file
services:
  # Service for running Chromium browser in a container
  chromium:
    # Specify the Docker image to be used for this service
    image: lscr.io/linuxserver/chromium:latest

    # Set the name for the container running this service
    container_name: chromium

    # Define security options for the container
    security_opt:
      # For Docker Engine only, many modern gui apps need this to function on older hosts as syscalls are unknown to Docker. Chromium runs in no-sandbox test mode without it.
      - seccomp:unconfined # Enable unconfined seccomp mode for this container (optional)

    # Set environment variables for the container
    environment:
      - PUID=1000 # Set the user ID for the container process (optional)
      - PGID=1000 # Set the group ID for the container process (optional)
      - TZ=Etc/UTC # Set the timezone inside the container to UTC (optional)
      - CHROME_CLI=https://bigbeartechworld.com/ # Set a URL to be used as home page (optional)

    # Mount volumes from the host into the container
    volumes:
      - /data/chromium/config:/config
      # Map the host directory /data/chromium/config to the container's /config directory
      # This allows the container to read/write configuration files to the specified host directory

    # Expose ports from the container to the host machine
    ports:
      - 3000:3000 # Map port 3000 from the container to port 3000 on the host (http)
      - 3001:3001 # Map port 3001 from the container to port 3001 on the host (https)

    # Set the size of the container's shared memory segment
    shm_size: "1gb" # Allocate 1 GB of shared memory (RAM) for this container

    # Define the restart policy for the container
    restart: unless-stopped
    # This means the container will automatically restart unless explicitly stopped by the user or Docker itself



Source: https://gist.github.com/varyonic/dea40abcf3dd891d204ef235c6e8dd79

Change log:
1. replaced "dl-ssl.google.com" with "dl.google.com" according https://www.google.com/linuxrepositories/
2. replaced "apt-key" as "Warning: apt-key is deprecated. Manage keyring files in trusted.gpg.d instead (see apt-key(8))."
3. use https


Oneliner for Dockerfile:
RUN set -ex; \
    apt-get update; \
    apt-get install -y gnupg wget curl unzip --no-install-recommends; \
    wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | \
    gpg --no-default-keyring --keyring gnupg-ring:/etc/apt/trusted.gpg.d/google.gpg --import; \
    chmod 644 /etc/apt/trusted.gpg.d/google.gpg; \
    echo "deb https://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list; \
    apt-get update -y; \
    apt-get install -y google-chrome-stable; \
    CHROME_VERSION=$(google-chrome --product-version | grep -o "[^\.]*\.[^\.]*\.[^\.]*"); \
    CHROMEDRIVER_VERSION=$(curl -s "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_$CHROME_VERSION"); \
    wget -q --continue -P /chromedriver "https://chromedriver.storage.googleapis.com/$CHROMEDRIVER_VERSION/chromedriver_linux64.zip"; \
    unzip /chromedriver/chromedriver* -d /usr/local/bin/

# To check it after (chrome and chromedriver versions will be the same):
$ docker run --rm -it put_docker_image_name_here bash
$ google-chrome --version
$ chromedriver -v



# installing google-chrome-stable 
RUN apt-get install -y gnupg wget curl unzip --no-install-recommends; \
    wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | \
    gpg --no-default-keyring --keyring gnupg-ring:/etc/apt/trusted.gpg.d/google.gpg --import; \
    chmod 644 /etc/apt/trusted.gpg.d/google.gpg; \
    echo "deb https://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list; \
    apt-get update -y; \
    apt-get install -y google-chrome-stable;

# installing chromedriver
RUN CHROMEDRIVER_VERSION=$(curl https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_STABLE); \
    wget -N https://storage.googleapis.com/chrome-for-testing-public/$CHROMEDRIVER_VERSION/linux64/chromedriver-linux64.zip -P ~/ && \
    unzip ~/chromedriver-linux64.zip -d ~/ && \
    rm ~/chromedriver-linux64.zip && \
    mv -f ~/chromedriver-linux64/chromedriver /usr/bin/chromedriver && \
    rm -rf ~/chromedriver-linux64

```


```
# Run Chromium in a container
#
# docker run -it \
#	--net host \ # may as well YOLO
#	--cpuset-cpus 0 \ # control the cpu
#	--memory 512mb \ # max memory it can use
#	-v /tmp/.X11-unix:/tmp/.X11-unix \ # mount the X11 socket
#	-e DISPLAY=unix$DISPLAY \
#	-v $HOME/Downloads:/home/chromium/Downloads \
#	-v $HOME/.config/chromium/:/data \ # if you want to save state
#	--security-opt seccomp=$HOME/chrome.json \
#	--device /dev/snd \ # so we have sound
#	-v /dev/shm:/dev/shm \
#	--name chromium \
#	jess/chromium
#
# You will want the custom seccomp profile:
# 	wget https://raw.githubusercontent.com/jfrazelle/dotfiles/master/etc/docker/seccomp/chrome.json -O ~/chrome.json

# Base docker image
FROM debian:bullseye-slim
LABEL maintainer "Jessie Frazelle <jess@linux.com>"

# Install Chromium
# Yes, including the Google API Keys sucks but even debian does the same: https://packages.debian.org/stretch/amd64/chromium/filelist
RUN apt-get update && apt-get install -y \
      chromium \
      chromium-l10n \
      fonts-liberation \
      fonts-roboto \
      hicolor-icon-theme \
      libcanberra-gtk-module \
      libexif-dev \
      libgl1-mesa-dri \
      libgl1-mesa-glx \
      libpangox-1.0-0 \
      libv4l-0 \
      fonts-symbola \
      --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/chromium.d/ \
    && /bin/echo -e 'export GOOGLE_API_KEY="AIzaSyCkfPOPZXDKNn8hhgu3JrA62wIgC93d44k"\nexport GOOGLE_DEFAULT_CLIENT_ID="811574891467.apps.googleusercontent.com"\nexport GOOGLE_DEFAULT_CLIENT_SECRET="kdloedMFGdGla2P1zacGjAQh"' > /etc/chromium.d/googleapikeys

# Add chromium user
RUN groupadd -r chromium && useradd -r -g chromium -G audio,video chromium \
    && mkdir -p /home/chromium/Downloads && chown -R chromium:chromium /home/chromium

# Run as non privileged user
USER chromium

ENTRYPOINT [ "/usr/bin/chromium" ]
CMD [ "--user-data-dir=/data" ]
```
    
############

RUN apt-get update && \
    apt-get install -y gnupg wget curl unzip --no-install-recommends && \
    wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - && \
    echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list && \
    apt-get update -y && \
    apt-get install -y google-chrome-stable && \
    CHROMEVER=$(google-chrome --product-version | grep -o "[^\.]*\.[^\.]*\.[^\.]*") && \
    DRIVERVER=$(curl -s "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_$CHROMEVER") && \
    wget -q --continue -P /chromedriver "http://chromedriver.storage.googleapis.com/$DRIVERVER/chromedriver_linux64.zip" && \
    unzip /chromedriver/chromedriver* -d /chromedriver
    
############

# See https://codeship.com/documentation/docker/browser-testing/
FROM myapp:base

# We need wget to set up the PPA and xvfb to have a virtual screen and unzip to install the Chromedriver
RUN apt-get install -y wget xvfb unzip

# Set up the Chrome PPA
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
RUN echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list

# Update the package list and install chrome
RUN apt-get update -y
RUN apt-get install -y google-chrome-stable

# Set up Chromedriver Environment variables
ENV CHROMEDRIVER_VERSION 2.19
ENV CHROMEDRIVER_DIR /chromedriver
RUN mkdir $CHROMEDRIVER_DIR

# Download and install Chromedriver
RUN wget -q --continue -P $CHROMEDRIVER_DIR "http://chromedriver.storage.googleapis.com/$CHROMEDRIVER_VERSION/chromedriver_linux64.zip"
RUN unzip $CHROMEDRIVER_DIR/chromedriver* -d $CHROMEDRIVER_DIR

# Put Chromedriver into the PATH
ENV PATH $CHROMEDRIVER_DIR:$PATH

    
#############
#############  
