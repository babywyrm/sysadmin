# AWS-ECR.SH

##
##
https://github.com/omeroot/aws-ecr.sh
##
##


![version](https://img.shields.io/badge/0.1.3-version-brightgreen)


This is utility script in order to push image to aws ecr service. 
Aws Login use `get-authorization-token` method in order to authentication.

You can;
1. You build image without push to aws for your local development 
2. You build and push to aws and you can see image in the ecr service.

## Requirements

1. Your aws iam user must be configured with aws cli with named profiles

```text
aws configure --profile <your aws profile name | default: aws-ecr>
```

_You find out more details https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html_

## Running

On the fly (I recommend) running.
```text
bash < (curl -s <raw aws-ecr.sh file URL>) [OPTIONS] COMMAND

For example;
bash <(curl -s https://raw.githubusercontent.com/omeroot/aws-ecr.sh/master/aws-ecr.sh) [OPTIONS] [COMMAND]

```

If you want to pass options when running script, you could create .env file and define variables which using in script.

.env file content
```text
URI=<ecr uri>
REPO=<image repository uri>
APP_NAME=<image name>
PROFILE=<aws profile name>
SSH_KEY=~/.ssh/<your_key_rsa>
```
> `SSH_KEY` is optional 

### OPTIONS

| OPTIONS            	| DESCRIPTION                                                               	|
|--------------------	|---------------------------------------------------------------------------	|
| -t \| --tag        	| Tag of your docker image (beta, latest, version x.x.x ...)                	|
| -r \| --repository 	| Your aws image repository (You should push same image to same repository) 	|
| -p \| --profile		 	| Your aws profile name for ecr																							 	|
| -n \| --name       	| Image name                                                                	|
| -u \| --uri        	| Aws ecr url created according to your aws account.                        	|

### COMMAND

| COMMAND 	| DESCRIPTION                                 	|
|---------	|---------------------------------------------	|
| release 	| Push image to aws ecr                       	|
| build   	| Build image with tag version and tag latest 	|
| auth    	| Login to Aws Ecr with authenticated profile  	|


> If you dont pass no command script only build your image according to given options.
