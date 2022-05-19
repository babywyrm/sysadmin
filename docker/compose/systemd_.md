Docker compose as a systemd unit
================================

Create file `/etc/systemd/system/docker-compose@.service`. SystemD calling binaries using an absolute path. In my case is prefixed by `/usr/local/bin`, you should use paths specific for your environment.

```ini
[Unit]
Description=%i service with docker compose
PartOf=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=true
WorkingDirectory=/etc/docker/compose/%i
ExecStart=/usr/local/bin/docker-compose up -d --remove-orphans
ExecStop=/usr/local/bin/docker-compose down

[Install]
WantedBy=multi-user.target
```

Place your `docker-compose.yml` into `/etc/docker/compose/myservice` and call

```
systemctl start docker-compose@myservice
```


Docker cleanup timer with system
================================

Create `/etc/systemd/system/docker-cleanup.timer` with this content:

```ini
[Unit]
Description=Docker cleanup timer

[Timer]
OnUnitInactiveSec=12h

[Install]
WantedBy=timers.target
```

And service file `/etc/systemd/system/docker-cleanup.service`:

```ini
[Unit]
Description=Docker cleanup
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=/tmp
User=root
Group=root
ExecStart=/usr/bin/docker system prune -af

[Install]
WantedBy=multi-user.target
```

run `systemctl enable docker-cleanup.timer` for enabling the timer

JournalD support
================

Just add the following line to the `/etc/docker/daemon.json`:

```json
{
    ...
    "log-driver": "journald",
    ...
}
```

And restart your docker service.
