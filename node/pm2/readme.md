##
#
https://gist.github.com/hoangmirs/b2cb60e0aa60019f0c8b13927ce9d0a2
#
https://medium.com/@saderi/to-pm2-or-not-to-pm2-embracing-docker-for-node-js-b4a8adce141c
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


##
##


Usage

Hello world:

```
$ pm2 start app.js

Raw Examples

# Fork mode
$ pm2 start app.js --name my-api # Name process

# Cluster mode
$ pm2 start app.js -i max        # Will start maximum processes with LB depending on available CPUs

# Listing

$ pm2 list               # Display all processes status
$ pm2 jlist              # Print process list in raw JSON
$ pm2 prettylist         # Print process list in beautified JSON

$ pm2 describe 0         # Display all informations about a specific process

$ pm2 monit              # Monitor all processes

# Logs

$ pm2 logs               # Display all processes logs in streaming
$ pm2 ilogs              # Advanced termcaps interface to display logs
$ pm2 flush              # Empty all log file
$ pm2 reloadLogs         # Reload all logs

# Actions

$ pm2 stop all           # Stop all processes
$ pm2 restart all        # Restart all processes

$ pm2 reload all         # Will 0s downtime reload (for NETWORKED apps)
$ pm2 gracefulReload all # Send exit message then reload (for networked apps)

$ pm2 stop 0             # Stop specific process id
$ pm2 restart 0          # Restart specific process id

$ pm2 delete 0           # Will remove process from pm2 list
$ pm2 delete all         # Will remove all processes from pm2 list

# Misc

$ pm2 reset <process>    # Reset meta data (restarted time...)
$ pm2 updatePM2          # Update in memory pm2
$ pm2 ping               # Ensure pm2 daemon has been launched
$ pm2 sendSignal SIGUSR2 my-app # Send system signal to script
$ pm2 start app.js --no-daemon
Different ways to launch a process

$ pm2 start app.js           # Start app.js

$ pm2 start app.js -- -a 23  # Pass arguments '-a 23' argument to app.js script

$ pm2 start app.js --name serverone # Start a process an name it as server one
                                    # you can now stop the process by doing
                                    # pm2 stop serverone

$ pm2 start app.js --node-args="--debug=7001" # --node-args to pass options to node V8

$ pm2 start app.js -i max    # Start maximum processes depending on available CPUs (cluster mode)

$ pm2 start app.js --log-date-format "YYYY-MM-DD HH:mm Z"    # Log will be prefixed with custom time format

$ pm2 start app.json                # Start processes with options declared in app.json
                                    # Go to chapter Multi process JSON declaration for more

$ pm2 start app.js -e err.log -o out.log  # Start and specify error and out log

$ pm2 --run-as-user foo start app.js  # Start app.js as user foo instead of the user that started pm2

$ pm2 --run-as-user foo --run-as-group bar start app.js  # Start app.js as foo:bar instead of the user:group that started pm2

```
###
###
```
module.exports = {
  apps: [{
    name: "app",
    script: "app.js"
  }],
  deploy: {
    // "production" is the environment name
    production: {
      // SSH key path, default to $HOME/.ssh
      key: "/path/to/some.pem",
      // SSH user
      user: "ubuntu",
      // SSH host
      host: ["192.168.0.13"],
      // SSH options with no command-line flag, see 'man ssh'
      // can be either a single string or an array of strings
      ssh_options: "StrictHostKeyChecking=no",
      // GIT remote/branch
      ref: "origin/master",
      // GIT remote
      repo: "git@github.com:Username/repository.git",
      // path in the server
      path: "/var/www/my-repository",
      // Pre-setup command or path to a script on your local machine
      pre-setup: "apt-get install git ; ls -la",
      // Post-setup commands or path to a script on the host machine
      // eg: placing configurations in the shared dir etc
      post-setup: "ls -la",
      // pre-deploy action
      pre-deploy-local: "echo 'This is a local executed command'"
      // post-deploy action
      post-deploy: "npm install",
    },
  }
}

```
##
##
