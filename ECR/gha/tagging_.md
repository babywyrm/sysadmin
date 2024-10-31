Automatic Building Docker Image & Upload to AWS ECR with version tags using GitHub Actions
Aaryan Gupta

##
#
https://medium.com/@aaryangupta2201/automatic-end-to-end-docker-image-upload-to-aws-ecr-using-github-actions-2da09431cbc4
#
https://snehalchaure.medium.com/create-and-push-docker-image-to-amazon-ecr-with-github-actions-4b35d26e1563
#
https://github.com/byu-oit/github-action-create-ecr-repo-if-missing
#
##

Follow
8 min read
·
Jan 13, 2024


Welcome back to my weekly new devops Projects blog..
So This time we will create a complete end to end automatic docker image building & will publish to aws ecr using github actions.
So here are steps we have followed in whole project…

    Create GitHub Repository
    Create Golang App
    Create Dockerfile for Golang
    Create GitHub Actions Workflow
    Create AWS ECR Repository
    Create AWS IAM User, Policy, and Group
    Test GitHub Actions
    Add Automatic Tagging of Releases

So lets start..

    First create a github repository whatever name you want. Here i have created “Docker Image Upload To ECR”. Always add a readme file for best practice.

After creating repository, we will clone that repository into our local system. using:

git clone "repository url"

After that run :

go mod init github.com/username/repository name
#this command basically will initiate go module. 

After that run:

code .
#this command will start vs code . You can use any editor.

Tip: if you face issue witl "code ." command execution install vs code and add path to env variable. 

Now after opening Vs code, it ill ask you to install some dependence. Just click install it will automatically install everything.

Now copy the below code written in Go language. Its just a hello world program. You can chose any programming language. Then create a new file there name “main.go”. Paste that code .

```
package main

import (
 "errors"
 "fmt"

 log "github.com/sirupsen/logrus"
)

// Hello returns a greeting for the named person.
func Hello(name string) (string, error) {
 if name == "" {
  return "", errors.New("empty name")
 }
 message := fmt.Sprintf("Hello, %v. Welcome!", name)
 return message, nil
}

func main() {
 message, err := Hello("Aaryan, How are You !!!")
 if err != nil {
  log.Fatal(err)
 }
 log.Info(message)
}
```
Here in this code line number 7 “log “github.com/sirupsen/logrus” is bacially is a completely API compatible with the standard library logger.

You can learn more about here:

https://github.com/sirupsen/logrus#:~:text=completely%20API%20compatible%20with%20the%20standard%20library%20logger.

Now to install other dependency , run :

go mod tidy

#this command genrally install all dependecy whatever is left.

Now run :

go run main.go

#this command run our go language code. 

No we need to make a Dockerfile from which we will make our docker image of code. Copy below code and make a Dockerfile in vs code and paste there.

FROM golang:latest AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
COPY *.go ./

RUN go mod tidy


RUN go build -o /Docker-Image-Upload-to-AWS-ECR #replace with folder name

FROM gcr.io/distroless/base-debian10

WORKDIR /

COPY --from=build /Docker-Image-Upload-to-AWS-ECR /Docker-Image-Upload-to-AWS-ECR

USER nonroot:nonroot

ENTRYPOINT ["/Docker-Image-Upload-to-AWS-ECR"]

Now for next part, come to AWS console & go to AWS ECR” Elastic container registry” .

Click on get started >> give repository name >> create repository.

My repository name is “dockermage-001”.

Now we have to create a policy to give permission to our user to access ECR repository.

Go to IAM service >> Click on Policies >> create policy.

Copy below code, but replace whatever datils is like your region,account number,ecr repository name.
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GetAuthorizationToken",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:BatchGetImage",
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:GetDownloadUrlForLayer",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart"
      ],
      "Resource": [
        "arn:aws:ecr:ap-south-1:aws account number:repository/ecr repository name"
      ]
    }
  ]
}
```
Go to json format and paste above policy by making suitable changes. Then click on next. Give your policy a name. Here i have give “ECRpolicyforimage”.

Now go to user group or else you can directly can create a user. But for best practice create a user group. Give a user group name. I have give “ecrpushpullimage”. Then select policy that e have create above.

No go to user >> create user >> give user name >> select “i want to create a iam user” >> Autogenrate password >> Next.

Now in set permission select group name>> select permission boundary >> select the policy which we created above. Click on next and click on create user.

User is ready. Click on user name >> create access key >> select CLI >> create access key. Donload that access key as we will use further.

No come to your github repository and go to setting >> secret & variables >> New repository secret.

Give first secret name : AWS_ACCESS_KEY_ID

give access key id which we have download above. Click on Add secret.

Repeat same for other secret variable name : AWS_SECRET_ACCESS_KEY

Your both access key are secure now.

Now in settings >> Action >> Genral >> In workflow permission >> select read & write permission.

This permission is needed for generating tags for github branch.

Now copy the below script to update version tags for docker image file as well as git tags.
```
#! /usr/bin/bash

VERSION=""


# get parameters
while getopts v: flag
do
  case "${flag}" in
    v) VERSION=${OPTARG};;
  esac
done

# get highest tag number, and add v0.1.0 if doesn't exist
git fetch --prune --unshallow 2>/dev/null
CURRENT_VERSION=`git describe --abbrev=0 --tags 2>/dev/null`


if [[ $CURRENT_VERSION == '' ]]
then
  CURRENT_VERSION='v0.1.0'
fi
echo "Current Version: $CURRENT_VERSION"

# replace . with space so can split into an array
CURRENT_VERSION_PARTS=(${CURRENT_VERSION//./ })

# get number parts
VNUM1=${CURRENT_VERSION_PARTS[0]}
VNUM2=${CURRENT_VERSION_PARTS[1]}
VNUM3=${CURRENT_VERSION_PARTS[2]}

if [[ $VERSION == 'major' ]]
then
  VNUM1=v$((VNUM1+1))
elif [[ $VERSION == 'minor' ]]
then
  VNUM2=$((VNUM2+1))
elif [[ $VERSION == 'patch' ]]
then
  VNUM3=$((VNUM3+1))
else
  echo "No version type (https://semver.org/) or incorrect type specified, try: -v [major, minor, patch]"
  exit 1
fi
```
# create new tag
NEW_TAG="$VNUM1.$VNUM2.$VNUM3"
echo "($VERSION) updating $CURRENT_VERSION to $NEW_TAG"

# get current hash and see if it already has a tag
GIT_COMMIT=`git rev-parse HEAD`
NEEDS_TAG=`git describe --contains $GIT_COMMIT 2>/dev/null`

# only tag if no tag already
if [ -z "$NEEDS_TAG" ]; then
  echo "Tagged with $NEW_TAG"
  git tag $NEW_TAG
  git push --tags
  git push
else
  echo "Already a tag on this commit"
fi

echo ::set-output name=git-tag::$NEW_TAG

exit 0

Make a folder name build & make a script file git_update.sh, you can give any name. Just update script.

Now paste above script in that file.

Now important part, creating yml workflow.

copy below yml workflow by changing needed ecr repository name.

---
```
name: Build and Push Golang Image to AWS ECR
on:
  push:
    branches: [ main ]
jobs:
  build-and-push:
    name: Build and Push to ECR
    runs-on: ubuntu-latest
    steps:
    - name: Checkout
      uses: actions/checkout@v2

    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v1
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: ap-south-1

    - name: Login to Amazon ECR
      id: login-ecr
      uses: aws-actions/amazon-ecr-login@v1

    - name: Automatic Tagging of Releases
      id: increment-git-tag
      run: |
        chmod +x ./build/git_update.sh
        bash ./build/git_update.sh -v minor

    - name: Build, Tag, and Push the Image to Amazon ECR
      id: build-image
      env:
        ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
        ECR_REPOSITORY: dockermage-001 #replace with your ecr repository name
        IMAGE_TAG: ${{ steps.increment-git-tag.outputs.git-tag }}
      run: |
        docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
        docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
```
Now make a folder name “.github”, then in that folder make another folder “workflows”. in that folder make a file name “ main.yml”.

Paste above yml file in this file.

That’s it. All ready……

No go to git bash & run follwoing commands …
```
git add .
git commit -m "Final commit of project"
git push
```
Your pipeline will get start in github action.

Here your dockerfile will build, get tags in github & upload to ECR repository.

Finally, go to ECR repositry, you ill see you Docker image.

In github a tag will also create for your docker image.
