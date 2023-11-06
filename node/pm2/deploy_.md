Deploy nodejs app with gitlab.com and pm2
=========================================

This manual is about setting up an automatic deploy workflow using [nodejs](https://nodejs.org/en/),
[PM2](http://pm2.keymetrics.io/), [nginx](https://nginx.org/) and
[GitLab CI](https://about.gitlab.com/features/gitlab-ci-cd/). It is tested on:

*   Target server: **Ubuntu 16.04 x64.** This is suitable for Ubuntu 14.x.
*   **Windows 10** on my PC to work.

I use **Alpine Linux** in Docker container (gitlab) to speed up deployment.

What do we need:

*   Account on gitlab.com
*   New virtual server with **Ubuntu 16.04 x64** (or 14.x) to run application
(i will call it the "target server")


Configure target server
-----------------------

### 1. Create new sudo-user

Login with SSH user "root " and run:
 
```bash
adduser ubuntu
usermod -aG sudo ubuntu
```

To check sudo access run:

```bash
su ubuntu
sudo ls -la /root
```

### 2. Install nodejs and npm

You can find official instruction
[here](https://nodejs.org/en/download/package-manager/#debian-and-ubuntu-based-linux-distributions).

For Ubuntu 16.04 run:

```bash
curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
sudo apt-get install -y nodejs
```

To check an installation run:

```bash
node -v
npm -v
```

### 3. Install process manager pm2

[PM2](http://pm2.keymetrics.io/) is a beautiful production process manager for nodejs. It will observe, log and
automatically restart your application if it fall. Run now:

```bash
sudo npm install -g pm2@latest
```

To enable auto start pm2 on reboot run:

```bash
pm2 startup
```

then **(!important)** follow the instructions on your screen (run displayed command).

### 4. Install git

```bash
sudo apt-get install git -y
```

If you haven't deploy git keys yet, you should run:

```bash
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

This command will generate private (`/home/ubuntu/.ssh/id_rsa`) and public
(`/home/ubuntu/.ssh/id_rsa.pub`) key. Print public key:

```bash
cat /home/ubuntu/.ssh/id_rsa.pub
```

copy it clipboard and paste to gitlab (Repo settings / Tab "Repository" / Deploy Keys).

Check ssh access to repository:
```bash
ssh -T git@gitlab.com
```

On the question "The authenticity of host...?" answer "yes".
If all is okay, you should see string like *"Welcome to GitLab, yourUsername!"*.

### 5. Generate SSH keys for current server

Now we should generate SSH keys to access current server without password.
Run next command again, but set file path to `/home/ubuntu/access`:

```bash
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

This command will generate private (`/home/ubuntu/access`) and public (`/home/ubuntu/access.pub`) key.
Move new generated key to *authorized_keys*:

```bash
cat /home/ubuntu/access.pub >> ~/.ssh/authorized_keys
```

You must copy and save private key on your computer. To print this key on screen use:

```bash
cat ~/access
```

### 6. Install nginx

```bash
sudo apt-get install nginx -y
sudo rm /etc/nginx/sites-enabled/default
```

Open nginx config:

```bash
sudo nano /etc/nginx/sites-available/app
```

and replace it with:

```nginx
server {
  listen 80;
  server_name app;
  location / {
    proxy_set_header  X-Real-IP  		$remote_addr;
	proxy_set_header  X-Forwarded-For 	$proxy_add_x_forwarded_for;
    proxy_set_header  Host       		$http_host;
	proxy_set_header  X-NginX-Proxy 	true;
    proxy_pass        http://127.0.0.1:3000;
	proxy_redirect off;
    proxy_buffering off;
  }
}
```

Then run:

```bash
sudo ln -s /etc/nginx/sites-available/app /etc/nginx/sites-enabled/app
sudo systemctl restart nginx
# Note: for Ubuntu 14.x run instead: sudo service nginx restart
```

And check nginx status (it should be "active"):

```bash
sudo systemctl status nginx
```


Configure deployment with Gitlab CI
-----------------------------------

### 1. Create file `ecosystem.config.js`in root directory of your project:

```javascript
// Target server hostname or IP address
const TARGET_SERVER_HOST = process.env.TARGET_SERVER_HOST ? process.env.TARGET_SERVER_HOST.trim() : '';
// Target server username
const TARGET_SERVER_USER = process.env.TARGET_SERVER_USER ? process.env.TARGET_SERVER_USER.trim() : '';
// Target server application path
const TARGET_SERVER_APP_PATH = `/home/${TARGET_SERVER_USER}/app`;
// Your repository
const REPO = 'git@gitlab.com:yourUsername/test-server.git';

module.exports = {
  /**
   * Application configuration section
   * http://pm2.keymetrics.io/docs/usage/application-declaration/
   */
  apps: [
    {
      name: 'testApp',
      script: 'index.js',
      env: {
        NODE_ENV: 'development'
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000
      }
    }
  ],

  /**
   * Deployment section
   * http://pm2.keymetrics.io/docs/usage/deployment/
   */
  deploy: {
    production: {
      user: TARGET_SERVER_USER,
      host: TARGET_SERVER_HOST,
      ref: 'origin/master',
      repo: REPO,
      ssh_options: 'StrictHostKeyChecking=no',
      path: TARGET_SERVER_APP_PATH,
      'post-deploy': 'npm install --production'
        + ' && pm2 startOrRestart ecosystem.config.js --env=production'
        + ' && pm2 save'
    }
  }
};
```

### 2. Add secret variables in gitlab:

Go to [gitlab.com](https:/gitlab.com) -> Your project -> "Settings" -> "CI/CD" -> "Secret variables".
Add some variables:

| Variable                        | Description                                              |
|---------------------------------|----------------------------------------------------------|
| TARGET_SERVER_HOST              | Target server host like `127.0.0.1` or `your.host.com`   |
| TARGET_SERVER_USER              | SSH username for login. Example `ubuntu`                                |
| TARGET_SERVER_SECRET_KEY_BASE64 | Base64 encoded private RSA key to login target server. Make it protected |

### 3. Create file `.gitlab-ci.yml` in root directory of project:

```yaml
image: keymetrics/pm2:6

stages:
  - deploy

deploy_prod:
  stage: deploy
  script:
    - echo "====== Deploy to production server ======"
    - apk update && apk upgrade
    - apk add git openssh bash
    # Add target server`s secret key
    - mkdir ~/.ssh
    - echo $TARGET_SERVER_SECRET_KEY_BASE64 | base64 -d > ~/.ssh/id_rsa
    - chmod 700 ~/.ssh && chmod 600 ~/.ssh/*
    - echo "Test ssh connection"
    - ssh -o StrictHostKeyChecking=no -T "ubuntu@$TARGET_SERVER_HOST"
    # Delploy
    - echo "Setup tagget server directories"
    - pm2 deploy ecosystem.config.js production setup 2>&1 || true
    - echo "make deploy"
    - pm2 deploy ecosystem.config.js production
  environment:
    name: deploying
  only:
  - master
```

If all is okay, your project will be automatically deployed every push and merge to master branch.
