

##
#
https://github.com/Hacking-Lab/alpine-nginx-php
#
https://github.com/Hacking-Lab/alpine-gotty-hacker/blob/main/Dockerfile
#
https://github.com/Hacking-Lab/alpine-siab2
#
https://github.com/sorenisanerd/gotty
#
https://gist.github.com/andyneff/e913adae0a4a19d2eb51a48ef16e8d06
#
##


```
# systemd unit file
# place in /etc/systemd/system
# systemctl enable gotty.service
# systemctl start gotty.service

[Unit]
Description=Gotty Web Terminal
After=network.target

[Service]
User=gotty
Group=gotty

Environment=TERM=xterm-256color
ExecStart=/home/gotty/gotty -a 127.0.0.1 -p "4200" -w ssh root@localhost

[Install]
WantedBy=multi-user.target


FROM hackinglab/alpine-base:3.2
MAINTAINER Ivan Buetler <ivan.buetler@compass-security.com>

ENV LANG="en_US.UTF-8" \
    LC_ALL="en_US.UTF-8" \
    LANGUAGE="en_US.UTF-8" \
    TERM="xterm"


RUN apk -U upgrade && \
    apk --update add \
    bash \
    sudo \
    curl \
    fping \
    go git \
    htop \
    iftop iotop \
    jq \
    nmap \
    rsync \
    screen \
    wget \
    tar tmux tree \
    vim \
    xz \
    zsh && \
    GOPATH=/tmp/gotty go get -u github.com/yudai/gotty && \
    mv /tmp/gotty/bin/gotty /usr/local/bin/ && \
    apk del go musl-dev && \
    echo 'set-option -g default-shell /bin/zsh' >> /root/.tmux.conf && \
    rm -rf /tmp/gotty /var/cache/apk/* /tmp/src

ADD root /

EXPOSE 8080

# RUN GOPATH=/tmp/gotty go get -u github.com/yudai/gotty && \
# RUN GOPATH=/tmp/gotty go get -u github.com/roughentomologyx/gotty && \
# GOPATH=/tmp/gotty go get -u github.com/sorenisanerd/gotty && \



gotty.sh
#!/usr/bin/env bash

# Usage: bash <(curl -L https://git.io/Jfr1J)
#    or: bash <(wget -O - https://git.io/Jfr1J)
#    or: bash <(perl -MLWP::Simple -e "getprint 'https://git.io/Jfr1J'")
#    or: bash <(python -c $'try:\n import urllib2 as u\nexcept:\n import urllib.request as u\nimport os; os.write(1,u.urlopen("https://git.io/Jfr1J").read())')

function gotty_main()
{
  : ${VERSION=2.0.0-alpha.3}
  : ${OS=linux}
  : ${ARCH=amd64}
  : ${URL=https://github.com/yudai/gotty/releases/download/v${VERSION}/gotty_${VERSION}_${OS}_${ARCH}.tar.gz}

  : ${GOTTY_DIR=~/.local/share/vsi/it/gotty}
  : ${GOTTY_TLS_CRT="${GOTTY_DIR}/cert.pem"}
  : ${GOTTY_TLS_KEY="${GOTTY_DIR}/key.pem"}


  mkdir -p "${GOTTY_DIR}"
  cd "${GOTTY_DIR}"

  # Download
  if [ ! -f "${GOTTY_DIR}/gotty" ]; then
    if command -v wget &> /dev/null; then
      wget "${URL}" -O - | tar xz
    elif command -v curl &> /dev/null; then
      curl -L "${URL}" | tar xz
    elif command -v python &> /dev/null; then
      python -c $'try:\n import urllib2 as u\nexcept:\n import urllib.request as u\nimport os; os.write(1,u.urlopen("'"${URL}\").read())" | tar xz
    elif command -v perl &> /dev/null; then
      # Not all Perls have LWP installed
      perl -MLWP::Simple -e "getprint '${URL}'" | tar xz
    else
      echo "Cannot download a file" >&2
      exit 2
    fi
  fi

  # Setup TLS
  export GOTTY_TLS_CRT
  export GOTTY_TLS_KEY
  export GOTTY_TLS=1

  if [ ! -f cert.pem ]; then
    if command -v openssl &> /dev/null; then
      openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 10000 -nodes \
          -subj "/C=US/ST=RI/L=Providence/O=VSI/CN=self.example.com" || {
        unset GOTTY_TLS
        : ${GOTTY_PORT=8080}
        echo "WARNING: openssl failed, this will NOT be a secure connection" >&2
      }
    else
      unset GOTTY_TLS
      : ${GOTTY_PORT=8080}
      echo "WARNING: openssl not found, this will NOT be a secure connection" >&2
    fi
  fi

  : ${GOTTY_PORT=8443}
  export GOTTY_PORT

  # Credentials
  if [ -z "${PASSWORD+set}" ]; then
    read -sp "GoTTY Password: " PASSWORD
  fi
  export GOTTY_CREDENTIAL="${USERNAME-vsi}:${PASSWORD}"

  # Run
  : ${GOTTY_PERMIT_WRITE=1}
  export GOTTY_PERMIT_WRITE
  echo "Username:password : ${GOTTY_CREDENTIAL}" >&2
  echo "Port : ${GOTTY_PORT}" >&2
  echo "Starting gotty..." >&2

  exec ./gotty bash
}

if [ "${BASH_SOURCE[0]}" = "${0}" ] || [ "$(basename "${BASH_SOURCE[0]}")" = "${0}" ]; then
  gotty_main
fi
@andyneff
Author
andyneff commented on Mar 22, 2023
Here's a simple /etc/systemd/systems/gotty.service for starting up gotty as a service

[Unit]
Description=GoTTY service

[Service]
Type=simple
ExecStart=/usr/local/bin/gotty.sh
Environment=PASSWORD=Somepassword
Environment=GOTTY_PORT=8888
Environment=GOTTY_DIR=/tmp/.gotty
User=daemon
Group=daemon

[Install]
WantedBy=multi-user.target
Note: On SELinux, /usr/local/bin/gotty.sh can't be in default context as /tmp, but the gotty executable in there poses no issue 🤷‍♂️
