#############
##
## 
## likely needs a facelift for latest, greatest
##

install-teleport.sh
#!/bin/bash

export version=v4.2.8
export os=linux
export arch=amd64

#####################################

curl -O https://get.gravitational.com/teleport-$version-$os-$arch-bin.tar.gz
tar -xzf teleport-$version-$os-$arch-bin.tar.gz
cd teleport
./install

#####################################

mkdir -p /var/lib/teleport

#####################################

cat > /etc/systemd/system/teleport.service <<- "EOF"
[Unit]
Description=Teleport SSH Service
After=network.target
[Service]
Type=simple
Restart=on-failure
EnvironmentFile=-/etc/default/teleport
ExecStart=/usr/local/bin/teleport start --config=/etc/teleport.yaml --pid-file=/var/run/teleport.pid
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/run/teleport.pid
[Install]
WantedBy=multi-user.target
EOF

#####################################

cat > /etc/teleport.yaml <<- "EOF"
teleport:
  nodename: test.indivar.in
  auth_token: <<REDACTED>>
  auth_servers:
  - teleport.indivar.in:3025
  data_dir: /var/lib/teleport
proxy_service:
  enabled: "no"
auth_service:
  enabled: "no"
ssh_service:
  enabled: "yes"
  commands:
    - name: arch
      command: [/bin/uname, -p]
      period: 1h0m0s
    - name: hostname
      command: [/bin/hostname]
      period: 1m0s
EOF

#####################################

systemctl daemon-reload
systemctl enable teleport
systemctl start teleport

#####################################  
##
##
