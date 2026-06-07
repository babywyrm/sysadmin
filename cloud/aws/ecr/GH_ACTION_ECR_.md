
Using an AWS ECR image as a Github Action container
Oct 28, 2020
Moving from Docker Hub to ECR

#
#
#
https://agileek.github.io/software/aws/2020/10/28/using-an-ecr-image-in-github-actions/
#
#
#
#

Pubstack, my current client decided to migrate all its docker images to ECR.

With the recent announcement about rate limiting on Docker Hub, maybe we will not be the only ones moving away.

For our CI/CD pipelines we use both CircleCI and GitHub Actions.

Using an ECR image is a really simple task in CircleCI, it consists of adding the aws_auth to the image configuration.

  docker:
    - image: ACCOUNT.dkr.ecr.REGION.amazonaws.com/IMAGE:VERSION
      aws_auth:
        aws_access_key_id: $AWS_ACCESS_KEY_ID
        aws_secret_access_key: $AWS_SECRET_ACCESS_KEY

On the other hand, using ECR images in GitHub Actions was a bit more tricky.

The problem is, you could only use images from private registries in job and service containers since late september, and they only did the “credentials” implementation. It means something like this is expected:

jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: ACCOUNT.dkr.ecr.REGION.amazonaws.com/IMAGE:VERSION
      credentials:
        username: AWS
        password: ${{ secrets.ECR_PASSWORD }}
    steps:
      - run: echo "inside an ecr container"

With aws, you can get a password with aws ecr get-login-password, and it is valid 12 hours.

You can manually set the GitGub secret “ECR_PASSWORD” every 12 hours, but that’s not really convenient.

After a little digging, I found an answer on a GitHub community thread explaining what seems like a good solution.1

Basically what we will do is:

    Retrieve ECR password from aws
    Store it as a GitHub secret name ECR_PASSWORD

All that inside a GitHub action scheduled to run every 6 hours.

It was not really as simple as I first thought, so here is all I had to do. I hope it can help you.

First, I created some aws credentials (ie. a couple aws_access_key_id and aws_secret_access_key with enough right to pull from ECR) I put them as secrets inside the GitHub project, let’s call them AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. Then I generated a personal access token (the “provided by default” GITHUB_TOKEN doest not have sufficient rights), let’s call it GH_API_ACCESS_TOKEN.

The complete GitHub workflow:

name: ecr-login
on:
  # Every 6 hours, the password validity is 12 hours
  schedule:
    - cron:  '0 */6 * * *'
jobs:
  login:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
      - name: AWS cli install action
        uses: chrislennon/action-aws-cli@1.1
      - name: retrieve ecr password and store as secret
        run: |
          pip3 install -r .github/requirements.txt
          python3 .github/ecr_password_updater.py
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: AWS_REGION
          GH_API_ACCESS_TOKEN: ${{ secrets.GH_API_ACCESS_TOKEN }}
  # This 'test' job is usefull for fast debugging
  test:
    needs: login
    runs-on: ubuntu-latest
    container:
      image: ACCOUNT.dkr.ecr.REGION.amazonaws.com/IMAGE:VERSION
      credentials:
        username: AWS
        # Here is the password retrieved as a secret that is set by the `login` job
        password: ${{ secrets.ECR_PASSWORD }}
    steps:
      - run: echo "Inside a container pulled from ECR \o/"

The python file ecr_password_updater.py:

# From https://github.community/t/github-actions-new-pulling-from-private-docker-repositories/16089/28
# The goal is to retrieve the ecr password every 6 hours and put it as a secret
from base64 import b64encode, b64decode
from nacl import encoding, public
import requests
import os
import json
import boto3


def encrypt(raw_public_key: str, secret_value: str) -> str:
    """Encrypt a Unicode string using the public key."""
    public_key = public.PublicKey(raw_public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")


def get_ecr_password() -> str:
    """Retrieve ECR password, it comes b64 encoded, in the format user:password
       From https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecr.html#ECR.Client.get_authorization_token
    """
    ecr = boto3.client('ecr')
    response = ecr.get_authorization_token()
    encoded_login_password = response['authorizationData'][0]['authorizationToken']

    decoded_login_password = b64decode(encoded_login_password).decode('UTF-8')
    return decoded_login_password.split(':')[1]


if __name__ == '__main__':

    get_public_key = requests.get('https://api.github.com/repos/ORG/REPOSITORY/actions/secrets/public-key',
                                  headers={'Accept': 'application/vnd.github.v3+json',
                                           'Authorization': 'token ' + os.environ['GH_API_ACCESS_TOKEN']})
    if get_public_key.ok is False:
        print('could not retrieve public key')
        print(get_public_key.text)
        exit(1)
    get_public_key_response = get_public_key.json()
    public_key_value = get_public_key_response['key']
    public_key_id = get_public_key_response['key_id']

    password = get_ecr_password()
    encrypted_password = encrypt(public_key_value, password)
    update_password = requests.put('https://api.github.com/repos/ORG/REPOSITORY/actions/secrets/ECR_PASSWORD',
                                   headers={'Accept': 'application/vnd.github.v3+json',
                                            'Authorization': 'token ' + os.environ['GH_API_ACCESS_TOKEN']},
                                   data=json.dumps({'encrypted_value': encrypted_password, 'key_id': public_key_id,
                                                    'visibility': 'all'}))
    if update_password.ok is False:
        print('could not update password')
        print(update_password.text)
        exit(1)

The dependencies used by the python code:

pynacl==1.4.0
requests==2.25.1
boto3==1.17.107

I first started with a simple bash script, but it became quite complex2, so I switched to python.

Enjoy!
Edit 2021-07-09

Thanks to Alex Pavlenko, I switched from using the aws cli to boto3. Python all the way!

    ok, maybe not good, but at least it works ↩

    you need to encrypt the password, and you need the public key id of the repository when you put the encrypted secret. I often start with bash, if it’s simple enough I keep it, if not I switch to python. ↩


##
#
https://github.com/marketplace/actions/ecr-push-and-ecs-deploy
#
##


on:
  push:
    branches:
      - master

name: Push image to ECR and force new ECS deploy

jobs:
  deploy:
    name: Deploy
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v2

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-west-2

      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1

      - name: Build and redeploy
        uses: jaroldwong/ecr-push-and-ecs-deploy@v1.1
        with:
          ecr-registry: ${{ steps.login-ecr.outputs.registry }}
          ecr-repository: 'Repository name'
          ecs-cluster: 'ECS Cluster name'
          ecs-service: 'Service name'
          


#########
#

https://levelup.gitconnected.com/fully-automated-nextjs-builds-deployments-github-aws-ecr-fargate-service-ecs-part-2-4-36caa082676a

#
#########


Fully Automated NextJS Builds/Deployments (GitHub, AWS ECR, Fargate Service, ECS)- Part 2/4

As announced in the first part of my DevOps/ AWS Deployment Tutorial, this time it will be about GitHub Workflows/Actions and OIDC Tokens for the authentication from GitHub to AWS.
Picture Source: stock.adobe.com

In my last post, we dove into typical DevOps topics and started looking at deploying a NextJS application on AWS. At this point, I’d like to reiterate right away that I think it’s an essential part of modern software development to be able, as a developer, to take a service from the first line of code all the way to production.
Contents of the tutorial

Part I — Docker Image/ ECR Terraform Deployment & Push Image.

Part II — Full GitHub Integration & TF Backend AWS/S3

Part III — Fargate Terraform Deployment on AWS (Infrastructure as Code)

Part IV — Optimizing Dockerfile for Production
A few thoughts…

It is important to think about operation and, of course, security and stability when making any decisions about choosing technologies and frameworks. The most beautifully programmed application is useless if it only runs on its own machine. From procedural methods of days gone by, I remember that people often coded away without thinking that someone would have to run the application at some point. “Let’s do it at the end”, was often the statement. It was often a downstream step to build pipelines for the rollout. From my experience and knowledge, however, deployment must be the initial step at the start of the project. After all, I want to know exactly how and where my application will run and be able to continuously monitor and present the results and intermediate statuses.

There is also nothing wrong with setting up a CI/CD pipeline at the beginning. We have all the necessary tools to do that. GitHub, Azure DevOps or Gitlab make it easy for us to do exactly that.

In this tutorial, I will use GitHub to launch the web app on AWS Elastic Container Services as a Fargate service.
Open ID Connect

I have seen hundreds of CI/CD pipelines where credentials have been stored to access cloud resources. Obviously, this is not a good idea. Even if GitHub secrets are no longer readable after saving, the credentials would at least have to have a longer validity if you don’t want to change them daily. Or you create permanently valid credentials, but I think this is questionable from a security point of view. Often, a kind of technical user was introduced for this purpose, which was used for authorization from pipelines in the direction of the cloud provider. All in all, not good approaches.

For some time now, however, GitHub has been offering OpenID Connect to authenticate against AWS. The setup is quite simple. We first need to set up a few things in the AWS Console.

First, in the AWS Console, under Identity and Access Management (IAM), we need to create the identity provider if none exists for GitHub.

The provider URL is https://token.actions.githubusercontent.com and the Audience is sts.amazonaws.com. It is also necessary to get the thumbprint using the “Get thumbprint” button.

Once the provider is created, we can create the necessary IAM Role that will allow us to access AWS resources from the GitHub Action.

The Trusted Entity Type is Web Identity. The identity provider must be selected as token.actions.githubusercontent.com. It is the provider we just created. In the selection list for Audience, you should only see the entry sts.amazonaws.com, which must also be selected.

The next step is to assign permissions. This can be very specific or full access. It is of course possible to create an exact policy. For our case we keep it a bit more open and give the role full access.

In the last step we have to assign the name of the role, e.g. github-role.

After creating the role, we need to open it again for editing to adjust the trust relationships. There we have to correct the condition. The key token.actions.githubusercontent.com:sub must get the desired GitHub repository as value, see the following code example.

"Condition": {
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": "repo:<your-github-org>/<your-repo>:*",
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                }
            }

After that, the role is ready to go and can be used in the GitHub workflow.
GitHub Workflow

To integrate a workflow, we now need to create the following new folders in our project.

$ mkdir .github
$ cd .github && mkdir workflows
$ cd workflows

In the .github/workflows folder, we then need a file that will contain our Actions.

$ touch ci-cd-pipeline.yml

After that, we should have the following project structure.

.
|-- .github
| `-- workflows
|-- pages
| `-- api
|-- public
|-- styles
`-- terraform
`-- registry

In the first step, I add the following code to ci-cd-pipeline.yml.

name: CI/CD Pipelineon:
  push:
    branches: [ main ]permissions:
  id-token: write
  contents: readenv:
  AWS_REGION: eu-central-1

The name of the pipeline can be chosen freely and is optional. However, it makes sense to use a name in order to see in the GitHub Actions which pipeline it is.

The new section permission is important. The “id-token” write entry allows the OIDC JWT ID token to be requested. Without this setting, it is not possible to use the authentication method described in the previous chapter.

The “contents: read” permission is again necessary to use the “checkout” action.

Under env, I have set an AWS_REGION where the resources should be created.

We remember the first part of the tutorial where we had already created a Terraform script to create an Elastic Container Registry (ECR). We had run this locally to create the resource on AWS. To do this, we had added the AWS credentials to the terminal. As described up front, the OIDC provider will now avoid using credentials. We have established trust between our GitHub repository and AWS and now want to leverage this when creating the ECR using a step in our GitHub workflow.

To do this, we use the aws-actions/configure-aws-credentials@v1 action as follows:

jobs:
registry:
runs-on: ubuntu-20.04
steps:
- name: Check Out
uses: actions/checkout@v2
- name: Configure AWS Credentials
uses: aws-actions/configure-aws-credentials@v1
with:
role-to-assume: arn:aws:iam::<your-account-id>:oidc-provider/token.actions.githubusercontent.com
aws-region: ${{ env.AWS_REGION }}
- name: Create Registry
id: create-registry
run: |
...

For this action, we need to enter the ARN of the AWS role with: role-to-assume and aws-region.

In principle, we could now use the pipeline like this, since we have taken care of authentication using OIDC tokens.

But stop. If we don’t use our Terraform scripts locally alone anymore, we have to make sure that the Terraform state is centrally available and locked on execution.

For this we need a so called backend config.
Terraform State

To make the Terraform state persistent in a multi-user environment, we first need to add the following line to the resource “terraform” in our /terraform/registry/main.tf.

backend "s3" { /* See the backend config in config/backend-config.tf */ }

As you can already see, we will need an S3 bucket to store the state.

After that we will create a new file called backend-config.tf in the folder /terraform/registry. This will get all the necessary settings, see the following example.

bucket                      = "terraform-states"
key                         = "ci-cd-example.tfstate"
region                      = "eu-central-1"
encrypt                     = true
dynamodb_table              = "terraform-locks"

Important. The S3 bucket and DynamoDB must exist before execution. Basically, these can be created once for multiple pipelines on AWS. It is critical that the key is unique per pipeline.

For the DynamoDB table, a partition key named “LockID” is required.

Now the job remains to add a step for the execution of the Terraform commands:

- name: Create Registry
id: create-registry
run: |
cd terraform/registry/

terraform init \
-backend-config=config/backend-config.tf \
-reconfigure \
-input=false

terraform apply \
-var-file=vars.tfvars \
-input=false \
-auto-approve

With this, we are now basically ready to roll out the ECR using GitHub Pipeline. Let’s take another look at the GitHub workflow we have created so far.

With the Git commit & push of the repository, the pipeline is automatically executed and the resource is created on AWS. As you can see, I outsourced the ARN of the AWS GitHub OIDC role to a GitHub secret and only reference it in the workflow. This, of course, increases security.

Ok. Goal achieved. The ECR is now created using pipeline. The Terraform state is securely managed centrally and locked on execution.
Docker Build & Push

Let’s now pipeline the Docker build in a second workflow job and automate it.

We had already looked at the individual necessary steps in depth in the first part of the tutorial. Now we just need to transfer the code into a workflow job. In addition, we still need proper tags, which I want to obtain from the Git commit hash. This is important later, so that the Fargate service/task recognizes that a new image version is available and the container is also renewed. Furthermore I don’t like to fix the name of the repository but want to get it from the Terraform output.

We had already defined the terraform output in the /terraform/registry/main.tf.

output "repository_name" {
  description = "The name of the repository."
  value = aws_ecr_repository.repository.name
}

We just need to transfer it to the next workflow job. For this, GitHub gives the possibility to specify job outputs. The first step of the ECR creation has to be supplemented a bit for this:

jobs:
  registry:
    runs-on: ubuntu-20.04
    outputs:
      repository-name: ${{ steps.create-registry.outputs.repository-name }}

In the create-registry step, the following lines must be added at the end to map the Terraform output to the step/job output.

export REPOSITORY_NAME=$(terraform output --raw repository_name)

echo "::set-output name=repository-name::$REPOSITORY_NAME"

This allows the job output to be reused in the next job.

It is time to create the next job in the workflow. This job should only be executed if the creation of the ECR was successful. GitHub Actions know the needs attribute for this. This indicates that the successful execution of the respective specified is required for the execution of the job.

In our case, the job “registry” is required.

docker-build:
    runs-on: ubuntu-20.04
    needs: [registry]

We also want to use the output of the registry job to duplicate as few variables as possible. The environment variable REPOSITORY_NAME is obtained from the output of the registry job as follows.

docker-build:
    runs-on: ubuntu-20.04
    needs: [registry]
    env:
      REPOSITORY_NAME: ${{ needs.registry.outputs.repository-name }}
      ACCOUNT_ID: {{ secrets.ACCOUNT_ID }}

The run step in the Docker build job then looks like this.

- name: Image build and push
        id: docker-build
        run: |
          export IMAGE_TAG=$(git rev-parse --short HEAD)

          export ACCOUNT_ID=$(aws sts get-caller-identity | jq -r .Account)
          aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com
          export REPOSITORY_URL=${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${REPOSITORY_NAME}
          
          docker build --platform linux/amd64 -t ${REPOSITORY_NAME}:${IMAGE_TAG} .
          docker tag ${REPOSITORY_NAME}:${IMAGE_TAG} ${REPOSITORY_URL}:${IMAGE_TAG}
          docker push ${REPOSITORY_URL}:${IMAGE_TAG}

This consists of the login to the ECR and Docker commands build, tag and push, as described in the previous episode.

We now dynamically create the image tag from the Git commit hash to initiate container updates on the Fargate later.

With the current setup, we are now ready to run the workflow to have the ECR and Docker image created fully automatically. This happens automatically when pushing the main branch to GitHub.

Then, in the next episode, we’ll look at creating a Fargate service on AWS using Terraform and GitHub workflow.

Happy coding!

As always, you can find all the code on GitHub.

