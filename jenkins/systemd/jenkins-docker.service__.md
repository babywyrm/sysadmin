##
#
https://www.jenkins.io/doc/book/system-administration/systemd-services/
#
##

```
[Unit]
Description=Jenkins Docker Container
After=docker.service
Requires=docker.service

[Service]
Restart=always
RestartSec=5s
ExecStartPre=-/usr/bin/docker rm -f jenkins
ExecStart=/usr/bin/docker run --name jenkins -p 8080:8080 -p 50000:50000 -v /var/jenkins_home:/var/jenkins_home my-jenkins
ExecStop=/usr/bin/docker stop jenkins

[Install]
WantedBy=multi-user.target


##
##


# /etc/systemd/system/jenkins.service
[Unit]
Description=Standalone Jenkins Master server
Documentation=https://www.jenkins.io/doc

Wants=network-online.target
After=network-online.target

[Service]
User=jenkins
Group=jenkins
Environment=HTTP_PORT=8080
Environment=JAVA_ARGS=-Djava.awt.headless=true
Environment=JENKINS_HOME=/var/lib/jenkins
Environment=JENKINS_WAR=/usr/lib/jenkins/jenkins.war
Environment=LISTEN_ADDRESS=127.0.0.1
Environment=WEBROOT=/var/cache/jenkins/war
WorkingDirectory=/var/lib/jenkins
LimitNOFILE=8192
ExecStart=/usr/bin/java ${JAVA_ARGS} -jar ${JENKINS_WAR} --webroot=${WEBROOT} --httpPort=${HTTP_PORT} --httpListenAddress=${LISTEN_ADDRESS}

[Install]
WantedBy=multi-user.target



##
##



# Steps to install Jenkins Agent using JNLP connection on Ubuntu 20.04 Focal Fossa
#
# * create an Agent node on the web GUI: https://wiki.jenkins.io/display/JENKINS/Step+by+step+guide+to+set+up+master+and+agent+machines+on+Windows

# * $ sudo apt-get install -y openjdk-14-jre-headless
# * $ sudo adduser jenkins
# * $ curl http://jenkins-master.internal/jnlpJars/agent.jar -o /home/jenkins/agent.jar
# * create systemd service: place this file in /lib/systemd/system/jenkins-agent.service
# * $ sudo systemctl enable myservice
# * $ sudo systemctl start jenkins-agent

[Unit]
Description=Jenkins Agent
After=network.target
Requires=network.target

[Service]
Type=simple
# optional file to provide environment variables (e.g. http_proxy, https_proxy):
#EnvironmentFile=/etc/sysconfig/jenkins
# TODO: adapt -jnlpUrl und -secret, as found on the web GUI: Jenkins > Nodes > ...
ExecStart=/usr/bin/java -jar /home/jenkins/agent.jar -jnlpUrl http://jenkins-master.internal:8080/computer/Linux/slave-agent.jnlp -secret 6bd5082ce1531212341234123412341234123412341234123412341234764898 -workDir "/home/jenkins"
Restart=always
User=jenkins
RestartSec=20

[Install]
WantedBy=multi-user.target


##
##



1. Create user jenkins
2. Create file /etc/systemd/system/jenkins.service:

```
```
[Unit]
Description=Jenkins slave
           
[Service]
ExecStart=/usr/bin/java -jar /home/jenkins/jenkins/slave.jar -jnlpUrl http://***/jenkins/computer/CentOS7/slave-agent.jnlp -secret ***
User=jenkins
Restart=always
           
[Install]
WantedBy=default.target
```
3. Ensure it works:
```
sudo systemctl daemon-reload
sudo systemctl start jenkins.service
sudo systemctl status jenkins.service
sudo systemctl stop jenkins.service
sudo journalctl -u jenkins.service
sudo systemctl enable jenkins.service #autostart
```

4. Add env variables:
```
#/etc/systemd/system/jenkins.service.d/env.conf:
[Service]
#Looks like there is no way to use variables here like PATH+=my_path
Environment="PATH=/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/home/jenkins/AccuRev/bin"

restart and check it works:
cat /proc/$pid/environ
