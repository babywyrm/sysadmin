Docker Compose for nginx and gitea
.env.template
GITEA_DATA_DIR=/tmp/gitea
.gitignore
.env
data/
app.ini.template
APP_NAME = Gitea
RUN_MODE = prod
RUN_USER = git

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH    = /data/gitea
DOMAIN           = 0.0.0.0
SSH_DOMAIN       = 0.0.0.0
HTTP_PORT        = 3000
ROOT_URL         = http://0.0.0.0/gitea/
DISABLE_SSH      = false
START_SSH_SERVER = true
SSH_PORT         = 2222
SSH_LISTEN_PORT  = 2222
OFFLINE_MODE     = false

[mailer]
ENABLED        = true
FROM           = 
MAILER_TYPE    = smtp
HOST           = 
IS_TLS_ENABLED = true
USER           = 
PASSWD         = 

[service]
ENABLE_NOTIFY_MAIL = true
backup_gitea
#! /bin/sh

if [ -z ${GITEA_DIR} ]; then
    echo Variable GITEA_DIR is not specified
    exit 1
fi

BACKUP=`date +%Y-%m-%d_%H`.tar.gz

echo >>log
date >>log

[ -e snapshot ] && touch snapshot

# If tar fails, go to code block
set -o pipefail

tar c -z \
  -f $BACKUP \
  -g snapshot \
  ${GITEA_DIR} \
  2>>log >/dev/null || {
  echo Fail to backup latest tar file | tee -a log
  exit 1
}

echo Succesfully backup >>log
docker-compose.yml
version: "3.7"
services:

  nginx:
    image: nginx:alpine
    container_name: nginx
    volumes:
      - /etc/passwd:/etc/passwd:ro 
      - /etc/group:/etc/group:ro
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ${DOC_DIR}:/doc
    ports:
      - 80:80

  gitea:
    image: gitea/gitea:1.17.2
    container_name: gitea
    env_file: .env
    environment:
      - USER_UID
      - USER_GID
    volumes:
      - ${GITEA_DATA_DIR}:/data
    ports:
      - 2222:2222

networks:
  default:
    name: gitea
gitea.service
[Unit]
Description=Gitea Server with docker
After=docker.service

[Service]
WorkingDirectory=/wk171/gitea
ExecStart=/usr/local/bin/docker-compose up
ExecStop=/usr/local/bin/docker-compose down
Restart=always

[Install]
WantedBy=multi-user.target
Makefile
.ONESHELL:

SHELL := bash

export USER_UID := $(shell id -u)
export USER_GID := $(shell getent group gitea | cut -d: -f3)

all:
	docker-compose up -d
down:
	docker-compose down
install:
	sudo systemctl enable `pwd`/gitea.service
	sudo systemctl start gitea.service
config:
	docker-compose config

# Use root to backup data
# Example of cron jobs:
#   HOME=~/data/gitea
#	0 */4 * * * make backup -f /path/to/here/Makefile >cron.log
#	0 1   1 * * mv snapshot snapshot.bak && make backup -f /path/to/here/Makefile >cron.log
backup:
	DIR=`dirname $(MAKEFILE_LIST)`
	docker run --rm \
	  --volume `pwd`:/data \
	  --volume $$DIR:/app \
	  --workdir /data \
	  --env 'GITEA_DIR=/app/data' \
	  --env USERID=`id -u` \
	  --env GROUPID=`id -g` \
	  --entrypoint /bin/sh \
	  hellyna/tar:latest \
	  -c '/app/backup_gitea && chown $$USERID:$$GROUPID *'
clean:
	rm --force snapshot log *tar.gz
nginx.conf
worker_processes 1;
user root root;

events { worker_connections 1024; }
http {

    sendfile on;

    upstream gitea {
        server gitea:3000;
    }

    server {
        listen 80;
        server_name localhost station.topo.tw;
        charset utf-8;
        client_max_body_size 300m;

        location /gitea/ {
            proxy_pass http://gitea/;

            proxy_redirect   off;
            proxy_set_header Host $host:$server_port;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /doc/ {
            autoindex on;
            alias /doc/;
        }
    }
}
