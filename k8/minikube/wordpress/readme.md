# Brothers in ARMs' wordpress


![GitHub release (latest by date)](https://img.shields.io/github/v/release/biarms/wordpress?label=Latest%20Github%20release&logo=Github)
![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/biarms/wordpress?include_prereleases&label=Highest%20GitHub%20release&logo=Github&sort=semver)

[![TravisCI build status image](https://img.shields.io/travis/biarms/wordpress/master?label=Travis%20build&logo=Travis)](https://travis-ci.org/biarms/wordpress)
[![CircleCI build status image](https://img.shields.io/circleci/build/gh/biarms/wordpress/master?label=CircleCI%20build&logo=CircleCI)](https://circleci.com/gh/biarms/wordpress)

[![Docker Pulls image](https://img.shields.io/docker/pulls/biarms/wordpress?logo=Docker)](https://hub.docker.com/r/biarms/wordpress)
[![Docker Stars image](https://img.shields.io/docker/stars/biarms/wordpress?logo=Docker)](https://hub.docker.com/r/biarms/wordpress)
[![Highest Docker release](https://img.shields.io/docker/v/biarms/wordpress?label=docker%20release&logo=Docker&sort=semver)](https://hub.docker.com/r/biarms/wordpress)

<!--
[![Travis build status](https://api.travis-ci.org/biarms/wordpress.svg?branch=master)](https://travis-ci.org/biarms/wordpress)
[![CircleCI build status](https://circleci.com/gh/biarms/wordpress.svg?style=svg)](https://circleci.com/gh/biarms/wordpress)
-->

## Overview
This image is actually based on WordPress official image, version 5.8.2 (php8.1-fpm-alpine and php8.1-apache).
The only differences are
1. The addition of the 'baskerville' and the 'travelera-lite' themes
2. The removal of the default (commerical) wordpress plugin and the addition of some other plugins
3. The configuration of the php settings to authorize the upload of files with a size greater than 2MB.
Resulting docker images are pushed on [dockerhub](https://hub.docker.com/r/biarms/wordpress/).

## How to build locally
1. Option 1: with CircleCI Local CLI:
   - Install [CircleCI Local CLI](https://circleci.com/docs/2.0/local-cli/)
   - Call `circleci local execute`
2. Option 2: with make:
   - Install [GNU make](https://www.gnu.org/software/make/manual/make.html). Version 3.81 (which came out-of-the-box on MacOS) should be OK.
   - Call `make build`

### Tips:
1. It is a good idea to increase the 'upload_max_filesize' php.ini parameter according to your wish: the folder php-conf.d provide sample file to see how to do.
1. If wordpress is installed behind an ngnix reverse proxy, the some 'nginx timeouts' should be increased (because installing the JetPack plugin is for instance very time-consuming, especially is your backend is an arm device (a rock-64 2GB device) running on a single Kubernetes nodes with an nfs provisioner accessing an NFS mount drive shared by an Odroid server !).
   Here is a debugging session of the installation of this plugin on the previously described setup, accessible via an NGX reverse proxy hosted on a Synology server:
   ```
   # First, upload the files on the 'wp-content/update' folder:
   $ watch -n 0.2 -d "du -sh wp-content/upgrade/jetpack*"
   => upload 27MB !
   # Then copy the file on the ' wp-content/plugins/jetpack' folder:
   $ watch -n 0.2 -d "du -sh wp-content/plugins/jetpack"
   1M     wp-content/plugins/jetpack
   2M     wp-content/plugins/jetpack
   ...
   27M     wp-content/plugins/jetpack
   # Then delete the files on the initial folder (that's also very time-consuming !!!!):
   $ watch -n 0.2 -d "du -sh wp-content/upgrade/jetpack*"
   27M     wp-content/upgrade/jetpackXXX
   26M     wp-content/upgrade/jetpackXXX
   ...
   1M      wp-content/upgrade/jetpackXXX
   du: cannot access 'wp-content/upgrade/jetpack*': No such file or directory
   # If the reverse proxy ngnix timeouts are not big enough (see next section):
   $ sudo tail -f /var/log/nginx/error.log (on the reverse proxy server, in my case, my synology server)
   # will return :
   2020/04/30 21:57:45 [error] 1759#1759: *163253 upstream timed out (110: Connection timed out) while reading response header from upstream...
   ```
1. In order to increase timeout on Synology: "Control Panel -> Application Portal -> Reverse proxy -> Edit -> Advanced settings" will authorize to change:
   - proxy_connect_timeout 600
   - proxy_send_timeout 600
   - proxy_read_timeout 600
1. To debug the previous step (on Synology): `cat /etc/nginx/app.d/server.ReverseProxy.conf`

## Release notes
The goal of this section is not to list exhaustively every release, but only to highlight important changes between releases, if any.
For an exhaustive list of releases, see https://hub.docker.com/r/biarms/wordpress/tags and https://github.com/biarms/wordpress/releases.

### Release 4.9.2 (February 2018)
- First build on an arm device: this release is NOT a multi-architecture build

### Release 4.9.8 (September 2018)
- First multi-arch build, supporting (theorically) arm32v5 (never tested on this kind of device), arm32v6 (by running the arm32v5 image...), arm32v7 and arm64v8. amd64 was not supported.

### Release 5.4.0 (May 2020)
- Add arm64 support

### Release 5.4.1 (May 2020)
- Build 'apache' image, but also 'php7.4-fpm-alpine' images

### Release 5.8.2 (January 2022)
- Upgrade to Wordpress 5.8.2
- Upgrade to the latest version of the plugins 
- Upgrade to php 8.1
- Upgrade the docker builder to alpine 3.15.0  
- Use circleci as the main build tool
