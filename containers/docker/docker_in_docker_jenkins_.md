# Jenkins in Docker (docker-in-docker)

##
##

https://gist.github.com/afloesch/ea855b30cfb9f157dda8c207d40f05c0

##
##
##

Testing Jenkins flows on your local machine, or running Jenkins in production in a docker container can be a little tricky with a docker-in-docker scenario. You could [install Jenkins](https://jenkins.io/doc/book/installing/#macos) to avoid any docker-in-docker issues, but then you have Jenkins on your machine, and the local environment is likely going to be a fairly different from the actual production build servers, which can lead to annoying and time-consuming issues to debug. 

Build environment differences are precisely why there is a strong argument to be made to run build processes strictly in docker containers. If we follow the philosophy that every build step or action should run in a docker container, even the Jenkins server itself, then we get massive benefits from things like, total control over the build environment, easily modify the build environment without the possibility of adversely effecting other jobs, explicit and strongly controlled tool versions, easily change or test new tool versions, simplified Jenkins master or slave node creation, enable any job to run on any node, and reduced-to-completely-eliminated [configuration drift](https://www.continuitysoftware.com/blog/what-is-configuration-drift/). All of this maximizes how flexible our jobs are, and makes them much less brittle.

The crux of the issue with Jenkins in docker is that Jenkins is running as a container, and inside that container we want to run other docker containers for various project builds, which complicates mounting drives or managing credentials.

## Make Docker available inside the Jenkins container

The first problem is that the official Jenkins docker image doesn\'t contain docker, so docker commands won\'t execute. One approach to solving this is to build a custom Jenkins docker image that would run on any and all Jenkins nodes with docker explicitly installed inside the Jenkins container. For this setup, we could use a Dockerfile that looks something like this:

```text
FROM  jenkins/jenkins:lts

RUN yum install docker -y

EXPOSE 8080
```

With a basic Dockerfile like above we could then build a custom Jenkins image, and now docker calls inside this docker container will have an installed docker version. The problem with this is now this image either needs to be hosted and retrieved any time a new Jenkins node is created, or the Dockerfile used to create a fresh build on a new node.

A better solution is to simply use the pre-built Jenkins image, and mount in the docker executable and socket from the host machine, so we don\'t have to install docker into the Jenkins container, and thus no Dockerfile to write or maintain.

```shell
docker run -it -u root -p 8080:8080 -p 50000:50000 \
-v /var/run/docker.sock:/var/run/docker.sock \
-v $(which docker):/usr/bin/docker \
--name jenkins jenkins/jenkins:lts
```

By mounting in the docker sock and the docker executable from the host with the `-v` flag we avoid installing docker explicitly.

## Persist Jenkins data

Now we have Jenkins up and running in a container, with docker available to our jobs, but the workspace data and jobs we create will only live as long as the container does. To solve this we can mount in the jenkins\_home folder so our data persists to the host after the Jenkins container is removed and/or restarted.

```shell
mkdir ~/jenkins_home
sudo ln -s ~/jenkins_home /var

docker run -it -u root -p 8080:8080 -p 50000:50000 \
-v /var/jenkins_home:/var/jenkins_home \
--name jenkins jenkins/jenkins:lts
```

By mounting the `/var/jenkins_home` folder inside the Jenkins container to the same path on the host machine we alleviate issues with missing files when mounting volumes inside a container running inside the Jenkins container, because docker will mount the path from the host machine, not the Jenkins container, when trying to mount directories into a container running inside Jenkins.

On a Mac it's best practice to avoid modifying `/` or `/var` directly, which is easily worked-around by creating a symlink to the jenkins_home folder somewhere in your `/Users` directory, and then setting the Docker for mac preferences to allow mounts from that location. The Docker preferences should look like below in the end. FYI, `/private` is a symlink to `/` on Mac OS, but due to docker-in-docker volume mounts we want the path in our Jenkins container to be the same as on the host machine, so we explicitly add `/var/jenkins_home`.

![docker_for_mac_preferences](https://gist.githubusercontent.com/afloesch/ea855b30cfb9f157dda8c207d40f05c0/raw/0f21df46ec19d0e3492d4a406c89bac06f71b3da/z_docker_for_mac_preferences.png)

This gets us a running Jenkins server which we can safely destroy or restart without losing any data, but one that doesn't have any credentials.

## Host machine SSH agent

In a production Jenkins instance best practice would be to use the Jenkins Credential manager to store ssh keys, or aws creds, but for local testing you can avoid this manual setup, and simply mount the necessary credentials into the Jenkins docker container. If the SSH agent from the host is available in the Jenkins container then it's possible to use the [Jenkins Git plugin](https://wiki.jenkins.io/display/JENKINS/Git+Plugin) to pull private or public repos.

### Linux

If running on a Linux machine it is possible to simply forward the SSH agent for the host directly into the Jenkins docker container for authentication.

```shell
docker run -it -u root -p 8080:8080 -p 50000:50000 \
-v ${SSH_AUTH_SOCK}:${SSH_AUTH_SOCK} -e ${SSH_AUTH_SOCK} \
-v ${HOME}/.ssh/known_hosts:/etc/ssh/ssh_known_hosts \
--name jenkins jenkins/jenkins:lts
```

### Mac OS

If you are running on Mac OS, SSH Agent forwarding is not supported by Docker for Mac, and as a simple workaround you can use the [Docker SSH Agent](https://github.com/nardeas/ssh-agent/) image to mount in the host machine SSH keys. For Mac the commands become:

```shell
docker run -d --name=ssh-agent nardeas/ssh-agent

docker run --rm --volumes-from=ssh-agent -v ~/.ssh:/.ssh -it nardeas/ssh-agent ssh-add /root/.ssh/id_rsa

docker run -it -u root -p 8080:8080 -p 50000:50000 \
--volumes-from=ssh-agent -e SSH_AUTH_SOCK=/.ssh-agent/socket \
-v ${HOME}/.ssh/known_hosts:/etc/ssh/ssh_known_hosts \
--name jenkins jenkins/jenkins:lts
```

## AWS access keys

AWS credentials, or other similar secrets, can also be mounted into the Jenkins container so that the AWS CLI commands have valid credentials. As long as the aws config directory is mounted in on the correct path then the `awscli` will find it. For AWS credential storage on a production Jenkins instance use the [CloudBees AWS Credentials Plugin](https://wiki.jenkins.io/display/JENKINS/CloudBees+AWS+Credentials+Plugin).

```shell
docker run -it -u root -p 8080:8080 -p 50000:50000 \
-v ~/.aws:/root/.aws \
--name jenkins jenkins/jenkins:lts
```

Now the Jenkins container at least has the AWS creds, but it doesn\'t have the AWS CLI to make calls to AWS, which we will cover later.

## Putting it all together and starting Jenkins

### Linux

```shell
mkdir -p /var/jenkins_home

docker run -it -u root -p 8080:8080 -p 50000:50000 \
-v ${SSH_AUTH_SOCK}:${SSH_AUTH_SOCK} -e ${SSH_AUTH_SOCK} \
-v ${HOME}/.ssh/known_hosts:/etc/ssh/ssh_known_hosts \
-v /var/run/docker.sock:/var/run/docker.sock \
-v $(which docker):/usr/bin/docker \
-v ~/.aws:/root/.aws \
-v /var/jenkins_home:/var/jenkins_home \
--name jenkins jenkins/jenkins:lts
```

### Mac OS

```shell
mkdir ~/jenkins_home
sudo ln -s ~/jenkins_home /var

docker run -d --name=ssh-agent nardeas/ssh-agent
docker run --rm --volumes-from=ssh-agent -v ~/.ssh:/.ssh -it nardeas/ssh-agent ssh-add /root/.ssh/id_rsa

docker run -it -u root -p 8080:8080 -p 50000:50000 \
--volumes-from=ssh-agent -e SSH_AUTH_SOCK=/.ssh-agent/socket \
-v ${HOME}/.ssh/known_hosts:/etc/ssh/ssh_known_hosts \
-v /var/run/docker.sock:/var/run/docker.sock \
-v $(which docker):/usr/bin/docker \
-v ~/.aws:/root/.aws \
-v /var/jenkins_home:/var/jenkins_home \
--name jenkins jenkins/jenkins:lts
```

## Running docker in a Jenkins docker container

The commands from the putting it all together section only get us the SSH Agent for the host machine inside the Jenkins docker container, so any Job that runs natively in the Jenkins container won't have any problems SSH'ing to anything, but that container also doesn't have many tools installed, and there's a high probability that shell commands inside the Jenkins container will fail because they simply aren't installed. This is where docker-in-docker comes into play, since we can use docker agents and images in multiple stages to gain access to the necessary build tools for our pipeline.

There are two approaches to running a Jenkins job in a container, a declarative pipeline using a docker agent, or a scripted pipeline where essentially manual docker calls are made. Let's take a simple example and compare the two options for the official Python docker image:

### Declarative Pipeline

When using a declarative pipeline you define the docker image to run using the agent block. Pre-built images and Dockerfiles are both supported. See the Jenkins docs for more details on [declarative pipeline syntax](https://jenkins.io/doc/book/pipeline/syntax/).


```js
pipeline {
  agent {
    docker {
      image 'python:3.7.3'
    }
  }
  stages {
    stage('Do job stage') {
      steps {
        sh "python --version"
      }
    }
  }
}
```

The reason this works is because we mounted in the docker executable and sock into the Jenkins container from the host machine; without it Jenkins would not have a `docker` command.

With a docker agent Jenkins manages a few things for us, like the actual docker command which is run to start the container, and also adds a number of environment variables to the docker container, which can be either helpful or a problem depending on what build process needs to be implemented. Since the docker container has a completely different filesystem from the Jenkins container, Jenkins will automatically mount the workspace folder into the container on the same path, and also set that folder as the working directory inside the running container. The above pipeline code would result in a docker command that looks something like this:

```shell
docker run --rm -v /var/jenkins_home/workspaces/project_name:/var/jenkins_home/workspaces/project_name \ 
-w /var/jenkins_home/workspaces/project_name \
python --version
```

This works because we mounted the Jenkins home directory from the Jenkins container at the same path on the host. Docker volumes and mounts will mount the path from the host machine, not the Jenkins container, so if we had made the mistake when starting Jenkins of mounting the jenkins home directory on the host from `~/jenkins_home` directly, which resolves to `/Users/someuser/jenkins_home`, then inside the job container the mounted workspace folder will likely be empty since the path `/var/jenkins_home` probably doesn\'t exist on the host machine, only in the Jenkins container.

The path that Jenkins mounts as the workspace and working directory cannot be modified when using a declarative pipeline. Even if you attempt to set it explicitly in the docker args, when the container is actually run, Jenkins will overwrite those settings with the above. This is a non-starter for something like a GoLang build with vendored packages. You won\'t be able to set a proper GOPATH for go to find the vendored dependencies.

### Scripted Pipeline

In a scripted pipeline there's no concept of an agent, so docker commands need to be constructed manually, but this also gives more control when the path you are mounting to is critical.

```js
node {
  stage('Do job stage') {
    sh 'docker run --rm -v ${WORKSPACE}:/var/app -w /var/app python:3.7.3 python --version'
  }
}
```

We use the Jenkins environment variable `WORKSPACE` to obtain the path to the job workspace.

## Managing SSH creds for docker-in-docker

A simple option, which could be used for quick testing but may not be ideal for a production build server, is to forward the SSH agent from the Jenkins container into the host, similarly to how we forwarded it from the host to the Jenkins container. Let's take a simple example of a Python application that pulls in a number of private repos. Here are a couple simple Jenkinsfile examples, one as a declarative pipeline and one as a scripted pipeline.

### Declarative Pipeline

```js
pipeline {
  agent {
    docker {
      image 'python:3.7.3'
      args '--volumes-from=ssh-agent -e SSH_AUTH_SOCK=/.ssh-agent/socket -v ${HOME}/.ssh/known_hosts:/etc/ssh/ssh_known_hosts'
    }
  }
  stages {
    stage('Do job stage') {
      steps {
        sh "pip install -requirements.txt"
      }
    }
  }
}
```

### Scripted Pipeline

```js
node {
  stage('Do job stage') {
    sh 'docker run --rm -v ${WORKSPACE}:/var/app -w /var/app \
    --volumes-from=ssh-agent -e SSH_AUTH_SOCK=/.ssh-agent/socket -v ${HOME}/.ssh/known_hosts:/etc/ssh/ssh_known_hosts \
    pip install -requirements.txt'
  }
}
```

### SSH Agent Plugin

This method is an easy way to do some quick testing, but would not work for a Jenkins cluster with slave nodes unless every node had the same SSH keys local to them. For production Jenkins servers you should use the Jenkins Credential Manager, which will manage credential passing to Jenkins slaves, in combination with the [SSH Agent Plugin](https://wiki.jenkins.io/display/JENKINS/SSH+Agent+Plugin). The SSH agent plugin takes care of mounting in the SSH agent for us, so we don\'t have to do it explicitly, and also breaks-up the environment dependencies we have with forwarding the SSH Agent when running on Linux versus Mac. If we use the SSH agent plugin the Jenkinsfile can stay the same regardless of whether Jenkins is hosted on Linux or Mac, and the declarative pipeline from above becomes:

```js
pipeline {
  agent {
    docker {
      image 'python:3.7.3'
    }
  }
  stages {
    stage('Do job stage') {
      steps {
        sshagent(credentials: ['jenkins']) {
          sh "pip install -requirements.txt"
        }
      }
    }
  }
}
```

This works for either declarative or scripted pipelines.

## Managing AWS creds for docker-in-docker

Similarly to the SSH credentials problem, if working with AWS infrastructure there are AWS credentials which the job container will need access to. If the AWS credentials were mounted into the Jenkins container, as specified in the putting it all together section, then the same method of passing in the mounted `~/.aws` credentials will work inside the job container. Here's an example as a declarative pipeline, but the same principle works for scripted pipelines as well.

```js
pipeline {
  agent { 
    docker {
      image 'xueshanf/awscli:latest'
      args '-v ~/.aws:/root/.aws'
    }
  } 
  stages {   
    stage('Publish content ') {
      steps {
        sh "aws s3 sync '${WORKSPACE}/content' s3://some-bucket-name"
      }
    }
  }
}
```

The above command uses a simple AWS CLI command to sync workspace content to an S3 bucket.

Remember, docker mount paths are relative to the host machine file system, because we are using the docker executable and sock from the host machine, so we use `~/.aws` as the host directory to mount since this is the default path on the host machine to the AWS credentials files.

This is not going to work well in a configuration with one or multiple Jenkins slaves, and is simply not very flexible when managing new or changing credentials, but those issues can be solved with the [CloudBees AWS Credentials Plugin](https://wiki.jenkins.io/display/JENKINS/CloudBees+AWS+Credentials+Plugin). Let's change the declarative pipeline above to use the AWS credentials plugin.

```js
pipeline {
  agent { 
    docker {
      image 'xueshanf/awscli:latest'
    }
  } 
  stages {   
    stage('Publish content ') {
      steps {
        script {
          withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'jenkins']]) {
            sh "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} aws s3 sync '${WORKSPACE}/content' s3://some-bucket-name"
          }
        }
      }
    }
  }
}
```

***Why not pass the AWS environment variables in the docker `args` key?*** Two reasons: first is that Jenkins doesn't support any plugin execution inside the `agent`, and second, environment variables aren't supported in the `agent` block. If you absolutely need to pass an environment variable value somewhere into the `agent` block then above the pipeline create a groovy variable, set the value to the desired environment variable value, and then pass the groovy variable into the `agent` block so that the variable value is initialized before the pipeline and docker agent execute.

**Why is there a `script` block around the `withCredentials` call?** Largely the same reason. If the script block had been omitted then the values for `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` will be empty when the job starts. By wrapping the withCredentials call in a script block we ensure that the environment values get set and passed in at run-time.

## Summary

Working with Jenkins in a docker-in-docker scenario is a little tricky, and requires us to think differently about writing our Jenkins jobs, but with these core things explained you should have enough info to quickly get started and avoid time-consuming and fundamental issues.
