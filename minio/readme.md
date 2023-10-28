##
#
https://github.com/AbelChe/evil_minio
#
##


# Setup MinIO on Ubuntu 20.04 LTS with Let's Encrypt SSL

✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨  
SUPPORT MY WORK - Everything Helps Thanks  
YouTube 🔗 <https://YouTube.GetMeTheGeek.com>  
Buy Me a Coffee ☕ <https://www.buymeacoffee.com/getmethegeek>  
Hire US 🔗 <https://getmethegeek.com>  
Digital Ocean referral 🔗 <https://tiny.cc/plxdigitalocean>  
✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨  

## Google Download Link for Go!

<https://golang.org/dl/>

## Install Go  

```console
wget -c https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
tar xvf go1.14.2.linux-amd64.tar.gz
sudo chown -R root:root ./go
sudo mv go /usr/local
sudo echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
source /etc/profile
go version
rm go1.14.2.linux-amd64.tar.gz
```

## Install MinIO on Ubuntu 20.04 LTS

```console
cd ~
wget https://dl.min.io/server/minio/release/linux-amd64/minio

sudo useradd --system minio --shell /sbin/nologin
sudo usermod -L minio
sudo chage -E0 minio

sudo mv minio /usr/local/bin
sudo chmod +x /usr/local/bin/minio
sudo chown minio:minio /usr/local/bin/minio

sudo touch /etc/default/minio
sudo echo 'MINIO_ACCESS_KEY="minio"' >> /etc/default/minio
sudo echo 'MINIO_VOLUMES="/usr/local/share/minio/"' >> /etc/default/minio
sudo echo 'MINIO_OPTS="-C /etc/minio --address :9000"' >> /etc/default/minio
sudo echo 'MINIO_SECRET_KEY="miniostorage"' >> /etc/default/minio

sudo mkdir /usr/local/share/minio
sudo mkdir /etc/minio

sudo chown minio:minio /usr/local/share/minio
sudo chown minio:minio /etc/minio

cd ~

wget https://raw.githubusercontent.com/minio/minio-service/master/linux-systemd/minio.service

sed -i 's/User=minio-user/User=minio/g' minio.service
sed -i 's/Group=minio-user/Group=minio/g' minio.service

sudo mv minio.service /etc/systemd/system

sudo systemctl daemon-reload
sudo systemctl enable minio
sudo systemctl start minio

sudo systemctl status minio

cd ~

sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 9000
sudo ufw enable
sudo ufw allow http
sudo ufw allow https
sudo ufw status verbose

sudo apt install software-properties-common
sudo add-apt-repository universe
sudo apt update
sudo apt install certbot
sudo certbot certonly --standalone -d minio-server.your_domain
sudo cp /etc/letsencrypt/live/minio-server.your_domain_name/privkey.pem /etc/minio/certs/private.key
sudo cp /etc/letsencrypt/live/minio-server.your_domain_name/fullchain.pem /etc/minio/certs/public.crt
sudo chown minio:minio /etc/minio/certs/private.key
sudo chown minio:minio /etc/minio/certs/public.crt
sudo systemctl restart minio
```
