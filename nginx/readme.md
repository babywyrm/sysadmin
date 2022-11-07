

# Use admin/pass as user/password credentials to login to openemr (from OE_USER and OE_PASS below)
# MYSQL_HOST and MYSQL_ROOT_PASS are required for openemr
# FLEX_REPOSITORY and (FLEX_REPOSITORY_BRANCH or FLEX_REPOSITORY_TAG) are required for flex openemr
# MYSQL_USER, MYSQL_PASS, OE_USER, MYSQL_PASS are optional for openemr and
#   if not provided, then default to openemr, openemr, admin, and pass respectively.
```
version: '3.1'
services:
  mysql:
    restart: always
    image: mariadb:10.2
    command: ['mysqld','--character-set-server=utf8']
    environment:
      MYSQL_ROOT_PASSWORD: root
  openemr:
    restart: always
    image: openemr/openemr:5.0.2
    ports:
    - 82:80
    volumes:
    - websitevolume:/var/www/localhost/htdocs/openemr
    environment:
      MYSQL_HOST: mysql
      MYSQL_ROOT_PASS: root
      MYSQL_USER: openemr
      MYSQL_PASS: openemr
      OE_USER: admin
      OE_PASS: pass
    depends_on:
    - mysql
  nginx:
    restart: always
    image: openemr/dev-nginx:1.0
    ports:
    - 80:80
    - 81:81
    volumes:
    - websitevolume:/usr/share/nginx/html/openemr
    depends_on:
    - openemr
    - dev-php-fpm-7-1
    - dev-php-fpm-7-2
  dev-php-fpm-7-1:
    restart: always
    image: openemr/dev-php-fpm:7.1
    volumes:
    - websitevolume:/usr/share/nginx/html/openemr
    depends_on:
    - openemr
  dev-php-fpm-7-2:
    restart: always
    image: openemr/dev-php-fpm:7.2
    volumes:
    - websitevolume:/usr/share/nginx/html/openemr
    depends_on:
    - openemr
volumes:
  websitevolume: {}
```
  
##
##
##

Scaling Nginx servers via Docker' (a Flask app)
.gitignore
**/__pycache__/*
README.md
How to use
in one terminal
git clone $url docker-scaling
cd docker-scaling
docker-compose up --scale flask=5
in another terminal
for i in `seq 1 200`; do curl localhost:2000; done
app.py
import socket
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello, My container is named: " + socket.gethostname()
docker-compose.yml
version: '3'
services:
  flask:
    image: myflask
    build:
      context: .
      dockerfile: Dockerfile.flask
    volumes:
      - ./:/src
    expose:
      - "5000"
    environment:
      - FLASK_APP=/src/app.py
  nginx:
    image: mynginx
    build:
      context: .
      dockerfile: Dockerfile.nginx
    ports:
      - "2000:80"
    volumes:
      - ${PWD}:/var/www-data/
      - ./:/etc/nginx/conf.d
    depends_on:
      - flask
Dockerfile.flask
FROM python:3
RUN pip3 install flask
CMD flask run --host=0.0.0.0
Dockerfile.nginx
# using Nginx base image
FROM nginx
# delete nginx default .conf file
RUN rm /etc/nginx/conf.d/default.conf
# add the .conf file we have created
COPY nginx.conf /etc/nginx/nginx.conf
nginx.conf
events {}

http {
  
  upstream serv {
    server docker-scaling_flask_1:5000;
    server docker-scaling_flask_2:5000;
    server docker-scaling_flask_3:5000;
    server docker-scaling_flask_4:5000;
    server docker-scaling_flask_5:5000;
  }

  server {
    listen 80;
    location / {
      proxy_pass http://serv;
    }
    location /static/ {
      alias /var/www-data/;
    }
  }

}
