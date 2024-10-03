##
#
https://github.com/wodby/docker4wordpress
#
##

```
services:
  mariadb:
    image: wodby/mariadb:$MARIADB_TAG
    container_name: "${PROJECT_NAME}_mariadb"
    stop_grace_period: 30s
    environment:
      MYSQL_ROOT_PASSWORD: $DB_ROOT_PASSWORD
      MYSQL_DATABASE: $DB_NAME
      MYSQL_USER: $DB_USER
      MYSQL_PASSWORD: $DB_PASSWORD
#    volumes:
#    - ./mariadb-init:/docker-entrypoint-initdb.d # Place init .sql file(s) here.
#    - /path/to/mariadb/data/on/host:/var/lib/mysql # I want to manage volumes manually.

  php:
    image: wodby/wordpress-php:$PHP_TAG
    container_name: "${PROJECT_NAME}_php"
    environment:
      # By default xdebug extension also disabled.
      PHP_EXTENSIONS_DISABLE: xhprof,spx
      PHP_MAIL_MIXED_LF_AND_CRLF: "On"
      # Mailpit:
      MSMTP_HOST: mailpit
      MSMTP_PORT: 1025
      #      # OpenSMTPD:
      #      MSMTP_HOST: opensmtpd
      #      MSMTP_PORT: 25
      DB_HOST: $DB_HOST
      DB_USER: $DB_USER
      DB_PASSWORD: $DB_PASSWORD
      DB_NAME: $DB_NAME
      PHP_FPM_USER: wodby
      PHP_FPM_GROUP: wodby
#      # Read instructions at https://wodby.com/docs/stacks/wordpress/local#xdebug
#      PHP_XDEBUG_MODE: debug
#      PHP_XDEBUG_MODE: profile
#      PHP_XDEBUG_USE_COMPRESSION: false
#      PHP_IDE_CONFIG: serverName=my-ide
#      PHP_XDEBUG_IDEKEY: "my-ide"
#      PHP_XDEBUG_LOG: /tmp/php-xdebug.log
    volumes:
    - ./:/var/www/html:cached
## Alternative for macOS users: Mutagen https://wodby.com/docs/stacks/wordpress/local#docker-for-mac
#    - wordpress:/var/www/html
#    # For XHProf and Xdebug profiler traces
#    - files:/mnt/files

  crond:
    image: wodby/wordpress-php:$PHP_TAG
    init: true
    container_name: "${PROJECT_NAME}_crond"
    environment:
      CRONTAB: "0 * * * * wp cron event run --due-now --path=/var/www/html"
    command: sudo crond -f -d 0
    volumes:
    - ./:/var/www/html:cached
## Alternative for macOS users: Mutagen https://wodby.com/docs/stacks/wordpress/local#docker-for-mac
#    - wordpress:/var/www/html

  nginx:
    image: wodby/nginx:$NGINX_TAG
    container_name: "${PROJECT_NAME}_nginx"
    depends_on:
    - php
    environment:
      NGINX_STATIC_OPEN_FILE_CACHE: "off"
      NGINX_ERROR_LOG_LEVEL: debug
      NGINX_BACKEND_HOST: php
      NGINX_VHOST_PRESET: wordpress
      #NGINX_SERVER_ROOT: /var/www/html/subdir
    volumes:
    - ./:/var/www/html:cached
## Alternative for macOS users: Mutagen https://wodby.com/docs/stacks/wordpress/local#docker-for-mac
#    - wordpress:/var/www/html
    labels:
    - "traefik.http.routers.${PROJECT_NAME}_nginx.rule=Host(`${PROJECT_BASE_URL}`)"

  mailpit:
    image: axllent/mailpit
    container_name: "${PROJECT_NAME}_mailpit"
    labels:
    - "traefik.http.services.${PROJECT_NAME}_mailpit.loadbalancer.server.port=8025"
    - "traefik.http.routers.${PROJECT_NAME}_mailpit.rule=Host(`mailpit.${PROJECT_BASE_URL}`)"

#  apache:
#    image: wodby/apache:$APACHE_TAG
#    container_name: "${PROJECT_NAME}_apache"
#    depends_on:
#    - php
#    environment:
#      APACHE_LOG_LEVEL: debug
#      APACHE_BACKEND_HOST: php
#      APACHE_VHOST_PRESET: php
#    volumes:
#    - ./:/var/www/html:cached
## Alternative for macOS users: Mutagen https://wodby.com/docs/stacks/wordpress/local#docker-for-mac
#    - wordpress:/var/www/html
#    labels:
#    - "traefik.http.routers.${PROJECT_NAME}_apache.rule=Host(`${PROJECT_BASE_URL}`)"

#  varnish:
#    image: wodby/varnish:$VARNISH_TAG
#    container_name: "${PROJECT_NAME}_varnish"
#    depends_on:
#    - nginx
#    environment:
#      VARNISH_SECRET: secret
#      VARNISH_BACKEND_HOST: nginx
#      VARNISH_BACKEND_PORT: 80
#      VARNISH_CONFIG_PRESET: wordpress
#      VARNISH_ALLOW_UNRESTRICTED_PURGE: 1
#    labels:
#    - "traefik.http.services.${PROJECT_NAME}_varnish.loadbalancer.server.port=6081"
#    - "traefik.http.routers.${PROJECT_NAME}_varnish.rule=Host(`varnish.${PROJECT_BASE_URL}`)"

#  valkey:
#    container_name: "${PROJECT_NAME}_valkey"
#    image: wodby/valkey:$VALKEY_TAG

#  adminer:
#    container_name: "${PROJECT_NAME}_adminer"
#    image: wodby/adminer:$ADMINER_TAG
#    init: true
#    environment:
#      ADMINER_DEFAULT_DB_HOST: $DB_HOST
#      ADMINER_DEFAULT_DB_NAME: $DB_NAME
#    labels:
#    - "traefik.http.routers.${PROJECT_NAME}_adminer.rule=Host(`adminer.${PROJECT_BASE_URL}`)"

#  webgrind:
#    image: wodby/webgrind:$WEBGRIND_TAG
#    container_name: "${PROJECT_NAME}_webgrind"
#    environment:
#      WEBGRIND_PROFILER_DIR: /mnt/files/xdebug
#    labels:
#    - "traefik.http.routers.${PROJECT_NAME}_webgrind.rule=Host(`webgrind.${PROJECT_BASE_URL}`)"
#    volumes:
#    - files:/mnt/files
#    - ./:/mnt/codebase:cached

#  pma:
#    image: phpmyadmin/phpmyadmin
#    container_name: "${PROJECT_NAME}_pma"
#    environment:
#      PMA_HOST: $DB_HOST
#      PMA_USER: $DB_USER
#      PMA_PASSWORD: $DB_PASSWORD
#      PHP_UPLOAD_MAX_FILESIZE: 1G
#      PHP_MAX_INPUT_VARS: 1G
#    labels:
#    - "traefik.http.routers.${PROJECT_NAME}_pma.rule=Host(`pma.${PROJECT_BASE_URL}`)"

#  gotenberg:
#    image: gotenberg/gotenberg
#    container_name: "${PROJECT_NAME}_gotenberg"

#  solr:
#    image: wodby/solr:$SOLR_TAG
#    container_name: "${PROJECT_NAME}_solr"
#    environment:
#      SOLR_HEAP: 1024m
#    labels:
#    - "traefik.http.services.${PROJECT_NAME}_solr.loadbalancer.server.port=8983"
#    - "traefik.http.routers.${PROJECT_NAME}_solr.rule=Host(`solr.${PROJECT_BASE_URL}`)"

#  elasticsearch:
#    image: wodby/elasticsearch:$ELASTICSEARCH_TAG
#    environment:
#      ES_JAVA_OPTS: "-Xms500m -Xmx500m"
#    ulimits:
#      memlock:
#        soft: -1
#        hard: -1

#  kibana:
#    image: wodby/kibana:$KIBANA_TAG
#    depends_on:
#    - elasticsearch
#    labels:
#    - "traefik.http.services.${PROJECT_NAME}_kibana.loadbalancer.server.port=5601"
#    - "traefik.http.routers.${PROJECT_NAME}_kibana.rule=Host(`kibana.${PROJECT_BASE_URL}`)"

#  node:
#    image: wodby/node:$NODE_TAG
#    container_name: "${PROJECT_NAME}_node"
#    working_dir: /app
#    labels:
#    - "traefik.http.services.${PROJECT_NAME}_node.loadbalancer.server.port=3000"
#    - "traefik.http.routers.${PROJECT_NAME}_node.rule=Host(`node.${PROJECT_BASE_URL}`)"
#    expose:
#    - "3000"
#    volumes:
#    - ./path/to/your/single-page-app:/app
#    command: sh -c 'npm install && npm run start'

#  memcached:
#    container_name: "${PROJECT_NAME}_memcached"
#    image: wodby/memcached:$MEMCACHED_TAG

#  opensmtpd:
#    container_name: "${PROJECT_NAME}_opensmtpd"
#    image: wodby/opensmtpd:$OPENSMTPD_TAG

#  rsyslog:
#    container_name: "${PROJECT_NAME}_rsyslog"
#    image: wodby/rsyslog:$RSYSLOG_TAG

#  xhprof:
#    image: wodby/xhprof:$XHPROF_TAG
#    restart: always
#    volumes:
#    - files:/mnt/files
#    labels:
#    - "traefik.http.routers.${PROJECT_NAME}_xhprof.rule=Host(`xhprof.${PROJECT_BASE_URL}`)"

  traefik:
    image: traefik:v2.0
    container_name: "${PROJECT_NAME}_traefik"
    command: --api.insecure=true --providers.docker
    ports:
    - '8000:80'
#    - '8080:8080' # Dashboard
    volumes:
    - /var/run/docker.sock:/var/run/docker.sock

#x-mutagen:
#  sync:
#    defaults:
#      ignore:
#        vcs: true
#        paths:
#        - .DS_Store
#        - .history
#        - .idea
#    wordpress:
#      alpha: "."
#      beta: "volume://wordpress"
#      configurationBeta:
#        permissions:
#          defaultFileMode: 0644
#          defaultDirectoryMode: 0755
#          defaultOwner: "id:501"
#          defaultGroup: "id:20"

#volumes:
## For macOS users (Mutagen)
#  wordpress:
## For Xdebug profiler
#  files:

```
version: '3.9'

services:
  # Database
  db:
    image: mysql:8.0
    volumes:
      - db_data:/var/lib/mysql
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: password
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpress
    networks:
      - wpsite

  # phpMyAdmin
  phpmyadmin:
    depends_on:
      - db
    image: phpmyadmin:latest
    restart: always
    ports:
      - '8081:80'
    environment:
      PMA_HOST: db
      MYSQL_ROOT_PASSWORD: password
    networks:
      - wpsite

  # WordPress
  wordpress:
    depends_on:
      - db
    image: wordpress:latest
    ports:
      - '8000:80'
    restart: always
    volumes:
      - ./wordpress:/var/www/html
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress
    networks:
      - wpsite

networks:
  wpsite:


volumes:
  db_data:

##
##

version: '3'

services:
   db:
     image: mysql:5.7
     volumes:
       - db_data:/var/lib/mysql
     restart: always
     environment:
       MYSQL_ROOT_PASSWORD: ${MYSQL_DATABASE_PASSWORD}
       MYSQL_DATABASE: wordpress
       MYSQL_USER: wordpress
       MYSQL_PASSWORD: wordpress

   wordpress:
     image: wordpress:latest
     ports:
       - 80
     restart: always
     environment:
       WORDPRESS_DB_HOST: db:3306
       WORDPRESS_DB_USER: wordpress
       WORDPRESS_DB_PASSWORD: wordpress

volumes:
    db_data:
