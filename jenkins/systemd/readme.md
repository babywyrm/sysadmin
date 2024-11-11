
Step 1: Update the Systemd Service with Periodic Checking
Modify the systemd service file /etc/systemd/system/jenkins-docker.service to include a timer that will trigger every 30 minutes.

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
```

Step 2: Create a Health Check Script for Jenkins

Create a script to check the health of the Jenkins service by querying the status or checking if the service responds on port 8080.
Create a script at /usr/local/bin/check_jenkins.sh:


```
#!/bin/bash

# Check if Jenkins is responding on port 8080
if ! curl -s http://localhost:8080 > /dev/null; then
    echo "Jenkins is not responding, restarting container."
    /usr/bin/docker restart jenkins
fi
```

Make this script executable:

```
sudo chmod +x /usr/local/bin/check_jenkins.sh
```

Step 3: Create a Systemd Timer for Periodic Checks
Create a timer file, /etc/systemd/system/jenkins-check.timer, to run the health check every 30 minutes.

```
[Unit]
Description=Periodic Jenkins Health Check

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
```

This timer will start the health check 5 minutes after boot and then every 30 minutes afterward.

Step 4: Create the Systemd Service for the Health Check
Create a service unit file, /etc/systemd/system/jenkins-check.service, to execute the health check script:

```
[Unit]
Description=Check Jenkins Health

[Service]
Type=oneshot
ExecStart=/usr/local/bin/check_jenkins.sh
```

Step 5: Enable and Start the Timer
Reload systemd to recognize the new timer and enable it to start automatically:

```
sudo systemctl daemon-reload
sudo systemctl enable jenkins-check.timer
sudo systemctl start jenkins-check.timer
```

Step 6: Verify the Timer
You can check the timer status and confirm that it’s set to trigger every 30 minutes:

```
sudo systemctl list-timers --all | grep jenkins-check
