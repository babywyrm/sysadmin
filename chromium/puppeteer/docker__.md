
##
#
https://dev.to/cloudx/how-to-use-puppeteer-inside-a-docker-container-568c
#
##


Puppeteer is a Node.js library which provides a high-level API to control Chromium (or Firefox) browsers over the DevTools Protocol.

This guide helps to use Puppeteer inside a Docker container using the Node.js image.

If we use the Docker images for Node.js v14 LTS Gallium, when installing the chromium package from apt, it will be v90.0, which can have compatibility issues with the latest Puppeteer. This is because it was tested with the latest Chromium stable release.
Selecting the correct image

Well... we want to run a web browser inside a container. it's important to know what are the different between the available variants.
Alpine is enough but ...

Yeah, we can run Chromium using Alpine Linux, but we'll need a few extra steps to make it run. That's why we prefer Debian variants to make it easier.
Which distro?

Every major version of Node.js in built over a version of Debian, and that Debian version comes with an old version of Chromium, which one could be not compatible with the latest version of Puppeteer.
Node.js 	Debian 	Chromium
v14 	9.13 	73.0.3683.75
v16 	10.9 	90.0.4430.212
v17 	11.2 	99.0.4844.84

To quickly solve that issue we can use the Google Chrome's Debian package that always installs the latest stable version. Therefore, this Dockerfile is compatible with Node.js v14, v16, or any new one.
Why not the built-in Chromium

When we install Google Chrome, apt will install all the dependencies for us.
Dockerfile
```
FROM node:slim AS app

# We don't need the standalone Chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD true

# Install Google Chrome Stable and fonts
# Note: this installs the necessary libs to make the browser work with Puppeteer.
RUN apt-get update && apt-get install curl gnupg -y \
  && curl --location --silent https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
  && sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' \
  && apt-get update \
  && apt-get install google-chrome-stable -y --no-install-recommends \
  && rm -rf /var/lib/apt/lists/*
```

# Install your app here...

💡 If you are in an ARM-based CPU like Apple M1, you should use the --platform argument when you build the Docker image.

docker build --platform linux/amd64 -t image-name .

The code config

Remember to use the installed browser instead of the Puppeteer's built-in one inside your app's code.

import puppeteer from 'puppeteer';
...

const browser = await puppeteer.launch({
  executablePath: '/usr/bin/google-chrome',
  args: [...] // if we need them.
});

Conclusion

The browser installation via apt will resolve the required dependencies to run a headless browser inside a Docker container without any manual intervention. These dependencies are not included in the Node.js Docker images by default.

The easiest path to use Puppeteer inside a Docker container is installing Google Chrome because, in contrast to the Chromium package offered by Debian, Chrome only offers the latest stable version.
Update 2022-08-24

This new Dockerfile version
```
FROM node:slim

# We don't need the standalone Chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD true

# Install Google Chrome Stable and fonts
# Note: this installs the necessary libs to make the browser work with Puppeteer.
RUN apt-get update && apt-get install gnupg wget -y && \
  wget --quiet --output-document=- https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor > /etc/apt/trusted.gpg.d/google-archive.gpg && \
  sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' && \
  apt-get update && \
  apt-get install google-chrome-stable -y --no-install-recommends && \
  rm -rf /var/lib/apt/lists/*
```

Applies the following changes:

A. Removes the apt-key deprecation warning.

Warning: apt-key is deprecated. Manage keyring files in trusted.gpg.d instead (see apt-key(8)).

B. Uses wget because it's installed by google-chrome-stable and it reduces a few MiB not installing curl.
👋 One new thing before you go
Tired of spending so much on your side projects? 😒

We have created a membership program that helps cap your costs so you can build and experiment for less. And we currently have early-bird pricing which makes it an even better value! 🐥
The DEV Team
Introducing DEV++
Ben Halpern for The DEV Team ・ Aug 29
#meta #news #productivity #career

Just one of many great perks of being part of the network ❤️
Top comments (36)
pic
 
bayokwendo profile image
•
Apr 26 '23 • Edited on Apr 26

After running the code and I got into multiple errors of browser not launching caused by using wrong executablePath etc, Below code help in resolving the issue

            const executablePath: string = await new Promise(resolve => locateChrome((arg: any) => resolve(arg))) || '';

            const browser = await puppeteer.launch({
                executablePath,
                args: ['--no-sandbox', '--disable-setuid-sandbox'],

            });

Reply
 
mrgoonie profile image
•
Jun 16 '23

where is that locateChrome function tho?
Reply
 
__38ab1d02e profile image
•
Aug 28 '23

npmjs.com/package/locate-chrome here
Reply
 
arielerv profile image
•
Sep 14 '23

Hi there, I know it's an old post, but it's still valid. I provide a config that works for image oraclelinux based on rh.

FROM oraclelinux:7-slim

RUN yum -y install oracle-nodejs-release-el7 oracle-instantclient-release-el7 wget unzip && \
    yum-config-manager --disable ol7_developer_nodejs\* && \
    yum-config-manager --enable ol7_developer_nodejs16 && \
    yum-config-manager --enable ol7_optional_latest && \
    yum -y install nodejs node-oracledb-node16 && \
    rm -rf /var/cache/yum/*

RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm && \
    yum install -y google-chrome-stable_current_x86_64.rpm

WORKDIR /srv/app/

COPY . /srv/app/.

RUN npm install

EXPOSE 3006

CMD ["node", "index.js"]

And the lunch:

        const browser = await puppeteer.launch({
            executablePath: '/usr/bin/google-chrome',
            args: [
                '--disable-gpu',
                '--disable-dev-shm-usage',
                '--disable-setuid-sandbox',
                '--no-sandbox'
            ]
        });

Reply
 
mdrijwan profile image
•
Sep 14 '22 • Edited on Sep 14

Hi there,
I used your Dockerfile content along with mine as i am trying to to generate pdf file for this service that i'm building with typescript. now everything works locally but i can't deploy it to AWS as it exceeds the lambda limit. now i am trying to dockerize it and it get's deployed but throws the following error.

"Failed to launch the browser process! spawn /usr/bin/google-chrome ENOENT\n\n\nTROUBLESHOOTING: https://github.com/puppeteer/puppeteer/blob/main/docs/troubleshooting.md\n"

here is my Dockerfile
```

FROM node:slim

# We don't need the standalone Chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD true

# Install Google Chrome Stable and fonts
# Note: this installs the necessary libs to make the browser work with Puppeteer.
RUN apt-get update && apt-get install gnupg wget -y && \
    wget --quiet --output-document=- https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor > /etc/apt/trusted.gpg.d/google-archive.gpg && \
    sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' && \
    apt-get update && \
    apt-get install google-chrome-stable -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

FROM public.ecr.aws/lambda/nodejs:14.2022.09.09.11
ARG FUNCTION_DIR="/var/task"

# Create function directory
RUN mkdir -p ${FUNCTION_DIR}

# Copy package.json
COPY package.json ${FUNCTION_DIR}

# Install NPM dependencies for function
RUN npm install

# Copy handler function and tsconfig
COPY . ${FUNCTION_DIR}

# Compile ts files
RUN npm run build

# Set the CMD to your handler
CMD [ "dist/src/generate.pdf" ]

and here is my code

export async function generatePdf(
  file: FileType,
  options?: OptionsProps,
  callback?: CallBackType
) {
  let args = ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu'];

  if (options?.args) {
    args = options.args;
    delete options.args;
  }

  const browser = await puppeteer.launch({
    headless: false,
    args: args,
    ignoreDefaultArgs: ['--disable-extensions'],
    executablePath: '/usr/bin/google-chrome',
  });

  const page = await browser.newPage();
```

Reply
 
navarroaxel profile image
•
Sep 14 '22 • Edited on Sep 14

Hi! Here, you're using a multi-stage build in Docker. You are taken the node:slim image, installing puppeteer there. But then you started a new stage with FROM public.ecr.aws/lambda/nodejs:14 and you don't have apt or Chrome neither in this image because is based on Amazon Linux and it uses yum as package manager (like RHEL).

You can check some approaches like github.com/shelfio/chrome-aws-lamb... or github.com/alixaxel/chrome-aws-lambda that explains how to use pptr inside Lambdas.

Also, I found this here stackoverflow.com/a/66099373, but I didn't test it

FROM public.ecr.aws/lambda/nodejs:14

RUN yum install -y wget unzip libX11

RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm && \
    yum install -y google-chrome-stable_current_x86_64.rpm

RUN CHROME_DRIVER_VERSION=`curl -sS https://chromedriver.storage.googleapis.com/LATEST_RELEASE` && \
    wget -O /tmp/chromedriver.zip https://chromedriver.storage.googleapis.com/$CHROME_DRIVER_VERSION/chromedriver_linux64.zip && \
    unzip /tmp/chromedriver.zip chromedriver -d /usr/local/bin/

Reply
 
mdrijwan profile image
•
Sep 14 '22

i just tried this.

my Dockerfile

FROM public.ecr.aws/lambda/nodejs:14

RUN yum install -y wget unzip libX11

RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm && \
    yum install -y google-chrome-stable_current_x86_64.rpm

RUN CHROME_DRIVER_VERSION=`curl -sS https://chromedriver.storage.googleapis.com/LATEST_RELEASE` && \
    wget -O /tmp/chromedriver.zip https://chromedriver.storage.googleapis.com/$CHROME_DRIVER_VERSION/chromedriver_linux64.zip && \
    unzip /tmp/chromedriver.zip chromedriver -d /usr/local/bin/

ARG FUNCTION_DIR="/var/task"

# Create function directory
RUN mkdir -p ${FUNCTION_DIR}

# Copy package.json
COPY package.json ${FUNCTION_DIR}

# Install NPM dependencies for function
RUN npm install

# Copy handler function and tsconfig
COPY . ${FUNCTION_DIR}

# Compile ts files
RUN npm run build

# Set the CMD to your handler
CMD [ "dist/src/generate.pdf" ]

and my code

export async function generatePdf(
  file: FileType,
  options?: OptionsProps,
  callback?: CallBackType
) {
  let args = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
  ];

  if (options?.args) {
    args = options.args;
    delete options.args;
  }

  const browser = await puppeteer.launch({
    args: args,
    executablePath: '/usr/bin/google-chrome',
  });

and i get this error "Protocol error (Target.setAutoAttach): Target closed."

2022-09-15T05:46:28.039Z    a251301b-87b7-4e34-bf7c-c1d0a42ae6f5    ERROR   ProtocolError: Protocol error (Target.setAutoAttach): Target closed.
    at /var/task/node_modules/puppeteer/lib/cjs/puppeteer/common/Connection.js:104:24
    at new Promise (<anonymous>)
    at Connection.send (/var/task/node_modules/puppeteer/lib/cjs/puppeteer/common/Connection.js:100:16)
    at ChromeTargetManager.initialize (/var/task/node_modules/puppeteer/lib/cjs/puppeteer/common/ChromeTargetManager.js:253:82)
    at Browser._attach (/var/task/node_modules/puppeteer/lib/cjs/puppeteer/common/Browser.js:219:73)
    at Function._create (/var/task/node_modules/puppeteer/lib/cjs/puppeteer/common/Browser.js:201:23)
    at ChromeLauncher.launch (/var/task/node_modules/puppeteer/lib/cjs/puppeteer/node/ChromeLauncher.js:92:50)
    at processTicksAndRejections (internal/process/task_queues.js:95:5)
    at async generatePdf (/var/task/dist/src/helpers/makePdf.js:21:21)
    at async Runtime.pdf [as handler] (/var/task/dist/src/generate.js:21:29) {
  originalMessage: ''
}

Thread
 
chobotx profile image
•
Dec 19 '22

Any solution to this? Having the exact same error.
Thread
 
navarroaxel profile image
•
Dec 22 '22

You should install all these X Window System dependencies in your Docker image:
alsa-lib
atk
cups-libs
ipa-gothic-fonts
libXcomposite
libXcursor
libXdamage
libXext
libXi
libXrandr
libXScrnSaver
libXtst
pango
xorg-x11-fonts-100dpi
xorg-x11-fonts-75dpi
xorg-x11-fonts-cyrillic
xorg-x11-fonts-misc
xorg-x11-fonts-Type1
xorg-x11-utils
Reply
 
mdrijwan profile image
•
Sep 16 '22

Also, would have a look in here please? I'm so stuck!
stackoverflow.com/questions/737184...
Thread
 
mdrijwan profile image
•
Sep 26 '22

updated my Dockerfile
i'm using your build and copying to my own build

ARG FUNCTION_DIR="/function"
FROM node:slim as build-image
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD true
ARG FUNCTION_DIR
RUN apt-get update && apt-get install gnupg wget -y && \
    wget --quiet --output-document=- https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor > /etc/apt/trusted.gpg.d/google-archive.gpg && \
    sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' && \
    apt-get update && \
    apt-get install google-chrome-stable -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*
RUN mkdir -p ${FUNCTION_DIR}/
COPY . ${FUNCTION_DIR}
RUN ls ${FUNCTION_DIR}
WORKDIR ${FUNCTION_DIR}
RUN npm install

FROM public.ecr.aws/lambda/nodejs:latest
ARG FUNCTION_DIR
WORKDIR ${FUNCTION_DIR}
COPY --from=build-image ${FUNCTION_DIR} ${FUNCTION_DIR}
RUN ls ${FUNCTION_DIR}
COPY package.json ${FUNCTION_DIR}
RUN npm install
COPY . ${FUNCTION_DIR}

RUN npm run build
RUN ls ${FUNCTION_DIR}/node_modules
RUN node node_modules/puppeteer/install.js
CMD [ "/function/dist/api/generate.pdf" ]

but getting this error:
"Failed to launch the browser process! spawn /usr/bin/google-chrome ENOENT\n\n\nTROUBLESHOOTING: https://github.com/puppeteer/puppeteer/blob/main/docs/troubleshooting.md\n"
