```
#!/usr/bin/env bash

# Run a curl against the Jenkins instance installed in Docker to perform a basic health check

CURL_MAX_TIME=15
ATTEMPTS=5  # Adjust as needed for periodic checking
SLEEP_TIME=20

for ATTEMPT in $(seq ${ATTEMPTS}); do
    echo "Attempt ${ATTEMPT} of ${ATTEMPTS}"
    STATUS_CODE=$(curl -sL -w "%{http_code}" localhost:8080 -o /dev/null --max-time ${CURL_MAX_TIME})

    if [[ "$STATUS_CODE" == "200" ]]; then
        echo "Jenkins is up and running."
        exit 0
    else
        echo "Jenkins did not return a 200 status code (returned: $STATUS_CODE)"
        sleep ${SLEEP_TIME}
    fi
done

##
##

echo "Jenkins failed to return a 200 status code after ${ATTEMPTS} attempts"
# Trigger a restart if health check fails (optional)
systemctl restart jenkins-docker.service
exit 1
```

##
##


Now, create a new systemd service at /etc/systemd/system/jenkins-healthcheck.service:

```
[Unit]
Description=Jenkins Health Check

[Service]
Type=oneshot
ExecStart=/usr/local/bin/jenkins_health_check.sh
```
  
This service will execute the health check script as a one-time action.

Create a systemd Timer to Run the Health Check
Next, create a timer to trigger the health check every 30 minutes. Save this file as /etc/systemd/system/jenkins-healthcheck.timer:

```
[Unit]
Description=Runs Jenkins Health Check every 30 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min
Unit=jenkins-healthcheck.service

[Install]
WantedBy=timers.target
  ```

Enable and Start the Timer
Reload systemd to apply the changes, and enable the timer to run automatically on boot:

```
sudo systemctl daemon-reload
sudo systemctl enable jenkins-healthcheck.timer
sudo systemctl start jenkins-healthcheck.timer
```

Check Timer Status
You can verify the status of the timer with:

```
sudo systemctl status jenkins-healthcheck.timer
