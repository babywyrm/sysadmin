https://gist.githubusercontent.com/cloudybdone/ff914b8086156335f963b8d948fde242/raw/fcb594c995a3f2956dce41ed793ff7fb6756e856/Deployment%2520PM2.sh



```
#!/bin/sh

#Install NodeJS and Yarn
curl -sL https://deb.nodesource.com/...
sudo apt-get install gcc...
curl -sL https://dl.yarnpkg.com/debian/....
echo "deb https://dl.yarnpkg.com/debian/ stable main"
sudo apt-get update && sudo apt-get install yarn -y

#Install pm2 With yarn:
yarn global add..

#Install pm2 With npm:
npm install pm2 

#CLI autocompletion
pm2 completion install

#Update: Keep your pm2 up to date with:
npm install pm2 -g && pm2 update
                        -------------

__/\\\\\\\\\\\\\____/\\\\____________/\\\\____/\\\\\\\\\_____
 _\/\\\/////////\\\_\/\\\\\\________/\\\\\\__/\\\///////\\\___
  _\/\\\_______\/\\\_\/\\\//\\\____/\\\//\\\_\///______\//\\\__
   _\/\\\\\\\\\\\\\/__\/\\\\///\\\/\\\/_\/\\\___________/\\\/___
    _\/\\\/////////____\/\\\__\///\\\/___\/\\\________/\\\//_____
     _\/\\\_____________\/\\\____\///_____\/\\\_____/\\\//________
      _\/\\\_____________\/\\\_____________\/\\\___/\\\/___________
       _\/\\\_____________\/\\\_____________\/\\\__/\\\\\\\\\\\\\\\_
        _\///______________\///______________\///__\///////////////__


                          Runtime Edition

        PM2 is a Production Process Manager for Node.js applications
                     with a built-in Load Balancer.

                Start and Daemonize any application:
                $ pm2 start app.js

                Load Balance 4 instances of api.js:
                $ pm2 start api.js -i 4

                Monitor in production:
                $ pm2 monitor

                Make pm2 auto-boot at server restart:
                $ pm2 startup

                To go further checkout:
                http://pm2.io/


                        -------------

[PM2] Spawning PM2 daemon with pm2_home=/root/.pm2
[PM2] PM2 Successfully daemonized
 ✓ pm2 tab-completion installed.

#Create Etherpad user
sudo adduser --home /opt/etherpad...
sudo install -d -m 755 -o etherpad -g..
sudo usermod -aG

cd /opt/etherpad/
git clone git://github.com/ether/...
bin/installDeps.sh

#Start Etherpad with PM2
pm2 start etherpad-lite/src..
pm2 list

#How to Use and Manage PM2 in Linux
sudo pm2 monit

sudo pm2 start etherpad-lite/src/node/...
sudo pm2 scale 0 8			#scale cluster app to 8 processes

#How to Manage Node Apps Using PM2
sudo pm2 stop                     		#stop process
sudo pm2 reset 		         	          #reset all counters
sudo pm2 delete all                		#kill and remove all apps
                

#To manage application logs, use the following commands.
sudo pm2 logs                      	#view logs for all processes 
sudo pm2 logs 1	                  	#view logs for app 1
sudo pm2 logs                   	#view logs for all processes in JSON format
 

#To manage the PM2 process, use the following commands.
sudo pm2 startup            #enable PM2 to start at system boot
sudo pm2 unstartup          #disable PM2 from starting at system boot
