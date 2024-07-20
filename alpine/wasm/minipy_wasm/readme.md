
##
#
https://github.com/vluz/minipy_wasm
#
##


# Mini Python in WASM

---

Intended as teaching instrument for a free Python course in Portuguese.

#### *NOTE:* Although my modifications are CC0, the project is hevily taken from the project container2wasm.   
It has a large amount of dependencies all with their own licenses.

**container2wasm project -** https://github.com/ktock/container2wasm   
Please check out the repo, it's wonderfully complex, deep, and amazing.  
Author(s) have many examples and detailed documentation.

I'd like to thank all of the people and projects that made this possible.

I'd like to also thank https://github.com/oevermod for the help in configuring Apache as well as all the support and patience. <3

---

### Project runs Alpine Linux with Python installed plus a few extras to modify it for teaching basic Python.

---

## Build Intructions:

_Everything here was done on Debian 12_

### Install dependencies

Install the following dependencies if not installed yet:

1) Install Docker from https://docs.docker.com/engine/install/
2) Install c2w binaries from https://github.com/ktock/container2wasm/releases  
I used v0.6.1, latest at time of this project
3) Download, Install, and Activate emsdk from https://emscripten.org/docs/getting_started/downloads.html
4) Activate emsdk environment variables  
`source ./emsdk_env.sh`
5) Install openssl  
`sudo apt-get install openssl`
6) Install git  
`sudo apt-get install git`

### Clone this repository

`git clone https://github.com/vluz/minipy_wasm.git`

`cd minipy_wasm`

### Create self-signed certificate for Apache web server.

Change directory to the root of the repository

`
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./certs/server.key -out ./certs/server.crt
`   
Answer all the questions as you see fit   
The one important thing you'll need to fill out is the "Common Name"    
You'll want to set to your server's IP address or domain name

Take note of the certificate password used

### Build Docker image

`cd podman_compose`

`podman build -t minipy .`

_Building will take a long time, please wait for build to complete_

### Create the WASM image with c2w

Change directory to the root of the repository

`c2w minipy ./htdocs/htdocs/out.wasm`

_Building will take a long time, please wait for build to complete_

You can use my image from this link:    
https://drive.google.com/file/d/1uFw8RxWYPgkN6TTGl2ZQmsun9UK25i53/view?usp=sharing

### Load everything into a container and run it

Change directory to the root of the repository

```
docker run -it -p 8080:443 \
-v "./htdocs/htdocs:/usr/local/apache2/htdocs/:ro" \
-v "./htdocs/xterm-pty.conf:/usr/local/apache2/conf/extra/xterm-pty.conf:ro" \
-v "./certs/httpd.conf:/usr/local/apache2/conf/httpd.conf:ro" \
-v "./certs/server.crt:/usr/local/apache2/conf/server.crt:ro" \
-v "./certs/server.key:/usr/local/apache2/conf/server.key:ro"  \
--entrypoint=/bin/sh \
httpd:latest \
-c 'httpd-foreground'
```

You will be prompted with the certificate password

Go to `https://<your_ip>:8080`

Accept the self-signed certificate

_Wait for everything to load, will take some time_

If it all worked you should see something like this:

<img src="Screenshot_firefox_winodws.png" width=75% height=75%>

___

Also works on Android

<img src="Screenshot_firefox_mobile.jpg" width=25% height=25%>

---
