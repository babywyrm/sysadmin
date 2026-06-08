# non root user example for debian
#
# usage:
# $ docker build --build-arg "USER=someuser" --tag test .
# $ docker run --rm test

FROM debian:stretch

ARG USER=default
ENV HOME /home/$USER

# install sudo as root
RUN apt-get update \
        && apt-get install -y sudo

# add new user
RUN adduser --disabled-password --gecos "" $USER \
        && echo "$USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$USER \
        && chmod 0440 /etc/sudoers.d/$USER

USER $USER
WORKDIR $HOME

# files in /home/$USER to be owned by $USER
# docker has --chown flag for COPY, but it does not expand ENV so we fallback to:
# COPY src src
# RUN sudo chown -R $USER:$USER $HOME

CMD echo "User $(whoami) running from $PWD with premissions: $(sudo -l)"

##
##

FROM python:3.6-slim-stretch

ADD requirements.txt /tmp/requirements.txt

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        make \
        gcc \
        locales \
        libgdal20 libgdal-dev && \
    python -m pip install numpy cython --no-binary numpy,cython && \
    python -m pip install \
        "rasterio>=1.0a12" fiona shapely \
        --pre --no-binary rasterio,fiona,shapely && \
    python -m pip install -r /tmp/requirements.txt && \
    python -m pip uninstall -y cython && \
    rm -r /root/.cache/pip && \
    apt-get remove -y --purge libgdal-dev make gcc build-essential && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

RUN dpkg-reconfigure locales && \
    locale-gen C.UTF-8 && \
    /usr/sbin/update-locale LANG=C.UTF-8

ENV LC_ALL C.UTF-8

CMD ["/bin/python"]

##
##
