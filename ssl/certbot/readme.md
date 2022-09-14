#
##
https://aws.plainenglish.io/configure-ssl-on-amazon-ec2-for-free-4e015813f3b4
##
#


Someone intelligent, like you, doesn’t like to pay too much. That’s why we’re such fans of cloud development. If we only pay for what we use, the final bill will be a lot less. Precisely for this reason, it is stupid to spend a lot on HTTPS. It increases security, but for many applications, it’s just a necessary thing.

The only thing you need to enable HTTPS is a signed certificate. You can generate this yourself, but this is quite complex. Instead, you better use a free service like LetsEncrypt. This service offers free certificates.

This article will show how you can secure your website in just a few minutes. We cover the following three steps:

How to configure Nginx for HTTPS
Docker-compose configuration
The init-letsencrypt.sh for certificate generation
How to configure Nginx for HTTPS
To configure an HTTPS server, you need to add some lines to your nginx.conf configuration file. The first line tells the server to listen to port 443 for an SSL connection.

Cloud users (for example AWS): You will also need to open this port in your security group, to be able to make use of HTTPS. This port is closed by default, so add it to the security group that is attached to your EC2 instance. Without opening this port, traffic from outside AWS won’t be able to reach your website on HTTPS.

listen 443 ssl;
After adding this line, the following four lines are also crucial. They specify the location of the SSL certificate and the private key for the website. abc.com.

ssl_certificate /etc/letsencrypt/live/abc.com/fullchain.pem;  ssl_certificate_key /etc/letsencrypt/live/abc.com/privkey.pem;
include /etc/letsencrypt/options-ssl-nginx.conf;
ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
Finally, you will also need to specify the server name if you haven’t done that already. These lines are sufficient for almost any application, but you can find more information here.

server_name abc.com www.abc.com
Docker-compose configuration
Launching our application and the certbot in one EC2 container is easy to accomplish with docker-compose.

In this section, I’ll give you everything to get started. You can also accomplish the same thing using docker commands, but this gives you a basic idea of the setup.

First, we’re going to configure the certbot plugin using the certbot docker image.

image: certbot/certbot
This image needs access to two volumes to access LetsEncrypt and one to access the certbot folder.

Configure SSL on Amazon EC2 for Free by 
@Dieter_Jordensvolumes:
 - ./data/certbot/conf:/etc/letsencrypt
 - ./data/certbot/www:/var/www/certbot
Every twelve hours, the script renews the certification if required.

entrypoint: "/bin/sh -c 'trap exit TERM; while:; do certbot renew; sleep 12h & wait $${!}; done;"
And that’s all the configuration you need for the certbot plugin to work. Do not forget to change your Nginx container (most likely part of your frontend application) as well. You’ll need two configure two things:

This application needs access to the secure SSL port 443:

ports:
 - 80:80
 - 443:443
It needs access to three volumes:

volumes: 
 - ./data/nginx:/etc/nginx/conf.d
 - ./data/certbot/conf:/etc/letsencrypt
 - ./data/certbot/www:/var/www/certbot 
Add everything as described above to your docker-compose file. You’ve done it. This configuration step is all finished. The only thing left to do is to request an initial certificate for your website.

The init-letsencrypt.sh for certificate generation

I’ve found this script online, and it’s fantastic. It does a lot for you. You might want to change a few things to the script above when you’re applying this to your website.

The most important one is to turn on ‘staging’ if you’re setting this thing up. If you don’t do this, you risk hitting rate limits. I’ve hit those, and you won’t be able to secure your website for a whole week. So my advice, change that number to 1 in the beginning!

The rest of the configuration is self-explanatory. Just fill in the blanks. Use your docker image, your email and your domain name. After giving the script execution rights, you can execute init-letsencrypt.sh with one easy command inside your EC2 container:

./init-letsencrypt.sh
LetsEncrypt will retrieve the certificate for you. Afterwards, the only thing you need to do is executing docker-compose. And your website is now fully secured! Awesome right?

Conclusion
You’ve seen in this article what it takes to enable HTTPS for your application. In three steps, you’ll be able to do this yourself. I didn’t particularly like configuring HTTPS. It’s a lot of work. With this article, you should have an easier time. Focus on developing without spending a dollar on an expensive service.

The same thing, as I explained above, is offered for free initially. Amazon AWS provides a free service in the first year that does precisely this and more. But, after the first year, you’ll be paying 20 or more dollars each month for a load balancer you don’t need. It would be awesome if they could make HTTPS free for limited usage.

