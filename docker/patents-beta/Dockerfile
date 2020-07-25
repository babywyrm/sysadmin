############################
############################

FROM ubuntu:18.04

USER root

RUN apt-get update

RUN apt-get upgrade -y

RUN DEBIAN_FRONTEND='noninteractive' apt-get install -y apache2 php7.2

COPY webroot/ /var/www/html/

COPY default.conf /etc/apache2/sites-enabled/000-default.conf

RUN chown -R www-data:www-data /var/www/html

EXPOSE 80

CMD ["apachectl", "-D", "FOREGROUND"]

###########################
###########################
