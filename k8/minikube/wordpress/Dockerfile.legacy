# Perform multi-stages build as explained at https://docs.docker.com/v17.09/engine/userguide/eng-image/multistage-build/#name-your-build-stages

##
## https://github.com/biarms/wordpress
##

# 1. Define args usable during the pre-build phase
# BUILD_ARCH: the docker architecture, with a tailing '/'. For instance, "arm64v8/"
ARG BUILD_ARCH
# VERSION: the version of the based image. ie: "4.9.8"
ARG VERSION

# 2. Create the 'builder' images.
#
# Can't use 'focal-20200423' (ubuntu 20.04 lts edition) because this image is not published with armv7 :(.
#   FROM ${BUILD_ARCH}ubuntu:focal-20200423 as builder
# Debian don't have the same issue with the 'armv', but has an issue with the "Go Daddy" certificate used by wordpress.com
# (see https://blog.hqcodeshop.fi/archives/304-Fixing-curl-with-Go-Daddy-Secure-Certificate-Authority-G2-CA-root.html)
# So next line won't work neither :(
#   FROM ${BUILD_ARCH}debian:buster-20200422-slim
# So let's stick to ubuntu 18.04 !
# By the way, as our builder image is not building (compling) anything, and is only downloading php files.
# So using ${BUILD_ARCH} in next line is actually cleaner (and slower), but useless !
# Or even better: use an alpine release !
FROM ${BUILD_ARCH}alpine:3.15.0 as builder
RUN apk add curl unzip

##############
# Add themes #
##############
RUN cd /tmp \
 && curl https://downloads.wordpress.org/theme/baskerville.2.1.4.zip --output theme.zip \
 && mkdir -p /tmp/themes \
 && unzip theme.zip -d /tmp/themes

RUN cd /tmp \
 && curl https://downloads.wordpress.org/theme/travelera-lite.1.0.1.7.zip --output theme.zip \
 && mkdir -p /tmp/themes \
 && unzip theme.zip -d /tmp/themes

###############
# Add plugins #
###############
# [Jetpack](https://fr.wordpress.org/plugins/jetpack/): mainly for the web-site monitoring...
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/jetpack.10.4.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [All-in-one-wp-migration](https://fr.wordpress.org/plugins/all-in-one-wp-migration/):
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/all-in-one-wp-migration.7.51.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [foobox-image-lightbox](https://fr.wordpress.org/plugins/foobox-image-lightbox/): mandatory if you install foogallery - v2.7.8
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/foobox-image-lightbox.2.7.16.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [foogallery](https://fr.wordpress.org/plugins/foogallery/): not an awesome, but a good media gallery - v1.9.24
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/foogallery.2.1.18.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [cookie-law-info](https://fr.wordpress.org/plugins/cookie-law-info/): to be gdpr compliant
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/cookie-law-info.2.0.6.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [health-check](https://fr.wordpress.org/plugins/health-check/): give tips about your web site install
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/health-check.1.4.5.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [upload-max-file-size](https://fr.wordpress.org/plugins/upload-max-file-size/): mandatory (but not suffisant) to increase upload file size
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/upload-max-file-size.2.0.4.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [media-library-assistant](https://fr.wordpress.org/plugins/media-library-assistant/): add taxonomy to media, with bulk update ;)
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/media-library-assistant.2.98.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [regenerate-thumbnails](https://fr.wordpress.org/plugins/regenerate-thumbnails/): not perfect, but could help
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/regenerate-thumbnails.3.1.5.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [resize-image-after-upload](https://fr.wordpress.org/plugins/resize-image-after-upload/): mandatory for me: recompress every uploaded media before it is save on the media library
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/resize-image-after-upload.1.8.6.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [server-ip-memory-usage](https://fr.wordpress.org/plugins/server-ip-memory-usage/): add simple debugging info in the footer
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/server-ip-memory-usage.2.1.0.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [user-access-manager](https://fr.wordpress.org/plugins/user-access-manager/): manage groups of users
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/user-access-manager.2.2.15.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins
# [wp-mail-smtp](https://fr.wordpress.org/plugins/wp-mail-smtp/): to be able to send emails
RUN cd /tmp \
 && curl https://downloads.wordpress.org/plugin/wp-mail-smtp.3.2.1.zip --output plugin.zip \
 && mkdir -p /tmp/plugins \
 && unzip plugin.zip -d /tmp/plugins

# 3. Start the creation of the final docker image
FROM ${BUILD_ARCH}wordpress:${VERSION}
MAINTAINER Brother In Arms <project.biarms@gmail.com>

# From https://github.com/docker-library/wordpress/blob/master/php5.6/fpm-alpine/Dockerfile
# COPY docker-entrypoint.sh /usr/local/bin/
# ENTRYPOINT ["docker-entrypoint.sh"]
# USER root

# Add themes
COPY --from=builder /tmp/themes /usr/src/wordpress/wp-content/themes
RUN chown -R www-data:www-data /usr/src/wordpress/wp-content/themes

# Remove default plugins
RUN rm -rf /usr/src/wordpress/wp-content/plugins/*

# Add plugins
COPY --from=builder /tmp/plugins /usr/src/wordpress/wp-content/plugins
RUN chown -R www-data:www-data /usr/src/wordpress/wp-content/plugins

# Add a 'php-ext.ini' file in the relevent folder to increase php "upload_max_filesize" parameters
COPY php-conf.d/php-ext.ini /usr/local/etc/php/conf.d/php-ext.ini
RUN chown -R www-data:www-data /usr/local/etc/php/conf.d/php-ext.ini

# Debug arch
RUN uname -m

ARG VCS_REF
ARG BUILD_DATE
LABEL \
	org.label-schema.build-date=${BUILD_DATE} \
	org.label-schema.vcs-ref=${VCS_REF} \
	org.label-schema.vcs-url="https://github.com/biarms/wordpress"
