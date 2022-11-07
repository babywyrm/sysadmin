

Nginx production configuration sample
This config assumes that nginx is run from docker image _/nginx.

##
#
https://gist.github.com/nad2000/8230720
#
##

docker commands
docker network create nginx

mkdir -p /etc/myproject/nginx
cd /etc/myproject/nginx
mkdir -p ssl/default && openssl req -x509 -newkey rsa:2048 -nodes -keyout ssl/default/privkey.pem -out ssl/default/fullchain.pem -days 36500 -subj '/CN=localhost'
openssl dhparam -out ssl/dhparam.pem 4096

docker run \
    -d --restart=always \
    --name nginx \
    -p 80:80 -p 443:443 \
    --net nginx \
    --log-driver=syslog --log-opt syslog-facility=local5 -v /dev/log:/dev/log \
    -v /etc/myproject/nginx/nginx.conf:/etc/nginx/nginx.conf:ro \
    -v /etc/myproject/nginx/conf.d/:/etc/nginx/conf.d/:ro \
    -v /etc/myproject/nginx/plugins.d/:/etc/nginx/plugins.d/:ro \
    -v /etc/myproject/nginx/sites-enabled.d/:/etc/nginx/sites-enabled.d/:ro \
    -v /etc/myproject/nginx/ssl/:/etc/nginx/ssl/:ro \
    -v /var/myproject/www/:/var/www:ro \
    nginx:mainline-alpine
    
    
    # call this then to gracefully reload configs
    docker kill -s HUP nginx
Note that we don't overlay the whole /etc/nginx/ folder of the container, so you can easily include stock nginx configs:

fastcgi.conf
fastcgi_params
koi-utf
koi-win
mime.types
nginx.conf
scgi_params
uwsgi_params
win-utf
This config contains the following ones:
Nginx performance optimizations
Nginx A+ score on Qualys SSL Labs
See also:
https://gist.github.com/plentz/6737338
conf.d myupstreamuwsgi.conf
upstream myupstreamuwsgi {
    server myupstream_1:3031;
    server myupstream_2:3031;
}
nginx.conf
# debian
# user www-data;

# alpine
user nginx;

pid /run/nginx.pid;

worker_processes auto;

events {
    # http://nginx.org/en/docs/events.html
    use                 epoll;
    worker_connections  2048;
    multi_accept        on;
}

# feel free to choose any facility you like in range 0..7
error_log syslog:server=unix:/dev/log,facility=local6,tag=nginx,severity=error;

http {
    ##
    # Logging
    ##

    # feel free to choose any facility you like in range 0..7
    access_log syslog:server=unix:/dev/log,facility=local6,tag=nginx,severity=info;
    # log_not_found off;
    
    ##
    # HTML, charset
    ##
    
    index index.html index.htm;
    charset utf-8;
    
    ##
    # Security
    ##
    server_tokens off;
    autoindex off;
    client_max_body_size 2m;

    # Limit requests per IP address
    # limit_req_zone  $binary_remote_addr  zone=common:20m   rate=200r/s;
    # limit_req   zone=common  burst=300;

    ##
    # MIME
    ##
    include       mime.types;
    default_type  application/octet-stream;
    
    ##
    # Performance
    ##
    sendfile            on;
    sendfile_max_chunk  512k;
    
    tcp_nopush   on;
    tcp_nodelay  on;
    
    # use this only when your nginx server serves static files
    open_file_cache           max=1000 inactive=20s;
    open_file_cache_valid     30s;
    open_file_cache_min_uses  2;
    open_file_cache_errors    off;
    
    ##
    # SSL
    ##
    ssl_protocols             TLSv1 TLSv1.1 TLSv1.2;
    ssl_session_tickets off;
    ssl_session_cache         shared:SSL:50m;
    ssl_session_timeout       10m;
    ssl_stapling              on;
    ssl_stapling_verify       on;
    # Don't forget to set `ssl_trusted_certificate` to the chain of your cert in the `server` block.
    resolver                  8.8.8.8 8.8.4.4;  # replace with `127.0.0.1` if you have a local dns server
    ssl_prefer_server_ciphers on;
    ssl_dhparam               ssl/dhparam.pem;  # openssl dhparam -out ssl/dhparam.pem 4096
    
    ##
    # GZIP
    ##
    gzip               on;
    gzip_disable       msie6;
    gzip_vary          on;
    gzip_proxied       any;
    # gzip_http_version  1.0;  # uncomment this to allow gzipping responses on http/1.0. proxy_pass uses http/1.0
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    # uncomment this if you want to provide nginx already gzipped variants of files, like `${file}.gz` 
    # gzip_static on;
    
    ##
    # Pluggable configs
    ##

    include conf.d/*.conf;
    include sites-enabled.d/*.conf;
}
plugins.d hsts.conf
add_header Strict-Transport-Security 'max-age=31536000';

# Use this one if you want to apply to the HSTS preload list. https://hstspreload.appspot.com/
# add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';
sites-enabled.d default.conf
server {
    listen 80 default_server deferred;
    listen [::]:80 default_server deferred;
    listen 443 default_server ssl http2 deferred;
    listen [::]:443 default_server ssl http2 deferred;
    
    server_name _;
    
    # Generate dumb self-signed certificate:
    # mkdir -p ssl/default && openssl req -x509 -newkey rsa:2048 -nodes -keyout ssl/default/privkey.pem -out ssl/default/fullchain.pem -days 36500 -subj '/CN=localhost'
    
    ssl_certificate      ssl/default/fullchain.pem;
    ssl_certificate_key  ssl/default/privkey.pem;
    # comment out the next line if you use a trusted certificate (not a self-signed one)
    ssl_stapling         off;
    
    return 444;  # tells nginx to roughly close connection
    
    # return 302 $scheme://domain.com;
}
sites-enabled.d domain.com.conf
server {
    listen 80;
    listen [::]:80;
    server_name domain.com;
    
    return 302 https://domain.com$request_uri;
}

server {
    listen 80;
    listen [::]:80;
    server_name www.domain.com;
    
    return 302 https://www.domain.com$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name domain.com;
    
    include plugins.d/hsts.conf;
    
    ssl_trusted_certificate  ssl/domain.com/chain.pem;
    ssl_certificate          ssl/domain.com/fullchain.pem;
    ssl_certificate_key      ssl/domain.com/privkey.pem;
    
    return 302 https://www.domain.com$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name www.domain.com;
    
    include plugins.d/hsts.conf;
    
    ssl_trusted_certificate  ssl/domain.com/chain.pem;
    ssl_certificate          ssl/domain.com/fullchain.pem;
    ssl_certificate_key      ssl/domain.com/privkey.pem;
    
    root /var/www/www.domain.com/;
    
    location /api/ {
        uwsgi_pass  myupstreamuwsgi;
        include     uwsgi_params;
    }
}

##
##
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
