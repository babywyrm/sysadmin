##
#
https://gist.github.com/hoangmirs/b2cb60e0aa60019f0c8b13927ce9d0a2
#
##

# 1. Preparing the server
## Install git
```
sudo apt install git-all
```

## Generate Server's SSH public key
```
ssh-keygen -t rsa -b 4096 -C "deploy"
cat ~/.ssh/id_rsa.pub
```
Then add this to Deploy keys on Github repo

## Add your local SSH public key to server
Insert your local SSH public key to `.ssh/authorized_keys` on server.
If server don't has this file, let create one :
```
cd
mkdir ~/.ssh
touch ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

## Install Nodejs and pm2
In **local machine** and **server** install nodejs and pm2

#### Install Nodejs

```
sudo apt-get install nodejs npm
```

#### Install pm2

```
sudo npm install pm2 -g
```

#### CLI autocompletion

```
pm2 completion install
```

About pm2, follow the instructions [here](https://pm2.io/doc/en/runtime/overview/)

# 1. Deploy project(local machine)
## Config Ecosystem file

Generate an `ecosystem.config.js` template with:

```
pm2 init
```

```javascript
module.exports = {
  apps : [{
    // Name of app
    name: 'API',
    // Script for pm2 run forever
    // If use static website, remove it
    script: 'app.js',

    // Options reference: https://pm2.io/doc/en/runtime/reference/ecosystem-file/

    // Args for script for pm2 run forever
    // If use static website, remove it
    args: 'one two',
    // Current directory on server
    cwd: "/var/www/production/current",
    // Config out file for web errors
    error_file: "/var/www/production/logs/web.err.log",
    // Config out file for web logs
    out_file: "/var/www/production/logs/web.out.log",
    // Number of instances to be started in cluster mode
    instances: 1,
    // Enable or disable auto restart after process failure
    autorestart: true,
    // Enable or disable the watch mode
    watch: false,
    // Restart the app if an amount of memory is exceeded (format: /0-9?/ K for KB, ‘M’ for MB, ‘G’ for GB, default to B)
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'development'
    },
    // ^env_\S*$ => Specify environment variables to be injected when using –env
    env_production: {
      NODE_ENV: 'production'
    }
  }],

  deploy : {
    production : {
      // SSH user
      user : 'node',
      // SSH host
      host : '212.83.163.175',
      // GIT remote/branch
      ref  : 'origin/master',
      // GIT remote
      repo : 'git@github.com:repo.git',
      // Fetch all branches or fast
      fetch: 'all'
      // Path in the server
      path : '/var/www/production',
      // Command run after pull source code
      'post-deploy' : 'npm install && pm2 reload ecosystem.config.js --env production'
    }
  }
};
```

Edit `ecosystem.config.js` for your project.
#### You can reference my config files
* For Vue static app with multiple environments on this [link](https://gist.github.com/hoangmirs/798d3344f63864515f5a7bc8b62db4f7)
* OR for nuxt app on this [link](https://gist.github.com/hoangmirs/cbf677c694d58b159f394a0160bbc4f2)

## Setup and Deploy
### Setup

Make your first deploy and populate the distant path with:

```
pm2 deploy production setup
```

### Deploy

```
pm2 deploy production
```

## Config Nginx on server
### Install NGINX
```
sudo apt update
sudo apt install nginx
```

Then you will need to add some configurations for our app.
Create a config file at `/etc/nginx/conf.d/azui_front_end.conf`:

```
server {
  listen 80;
  server_name 212.83.163.175;
  root /var/www/production/current/dist;
        access_log      /var/www/production/logs/nginx_access.log;
        error_log       /var/www/production/logs/nginx_error.log;

  try_files $uri $uri/ /index.html;
}
```
"/var/www/production/current" is your cwd in above ecosystem config
This is simple config for nginx.

#### You can reference my config for Vue static app or Nuxt on this [link](https://gist.github.com/hoangmirs/578909c5ffa4e1530ed03ece1b12c35c).

### Restart Nginx

```
sudo service nginx restart
```

### Create symbolic link (optional)
You can create symbolic link for cwd
Take a look at the nginx config above, the doc root points to `/var/www/production/current/dist`, if you wanna shortcut this to `/home/deploy/www` directory, you need to create a symbolic link from the build directory to `/home/deploy/www`.
The build will be placed at `/var/www/production/current/dist`, so run the command below to create a symbolic link
```
ln -s /var/www/production/current/dist /home/deploy/www
```
and replace `/home/deploy/www` to root key in nginx config file
