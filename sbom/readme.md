
##
#
https://github.com/pvnovarese/syft-demo
#
##


# Demo: CICD Integrations with Syft

[![Syft Demo](https://github.com/pvnovarese/syft-demo/actions/workflows/syft-demo.yaml/badge.svg)](https://github.com/pvnovarese/syft-demo/actions/workflows/syft-demo.yaml)

This is a very rough set of demos for integrating Syft with various CICD tools.  If you don't know what Syft is, read up here: https://github.com/anchore/syft

## Scenario 1: GitHub Workflow

Honestly, this is a redundant demo, as there is a pre-canned Action available for your GitHub Workflows: https://github.com/anchore/sbom-action - however, this exercise may be useful in understanding what's going on behind the scenes or as a roadmap to integrating with other tools.

Pretty straightforward, just take a look at the .gitlab/workflows/syft-demo.yaml and edit as needed.  The workflow as-is will build an alpine-based image, generate a SPDX SBOM, archive the SBOM, and push the image to ghcr.io.

There are some commented-out portions that you can use as a roadmap to doing additional stuff, such as checking the SBOM for forbidden packages, etc.

## Senario 2: Jenkins Pipeline

This is a more complex demo.  You'll need access to a Jenkins instance and a container registry (the Jenkinsfile assumes you have a Docker Hub account, but can be easily modified to use any other registry).  If you don't have access to a working Jenkins installation, step 1 below will walk you through setting up a disposable Jenkins instance for this exercise.  

### Part 1: Jenkins Setup

We're going to run jenkins in a container to make this fairly self-contained and easily disposable.  This command will run jenkins and bind to the host's docker sock (if you don't know what that means, don't worry about it, it's not important).

`$ docker run -u root -d --name jenkins --rm -p 8080:8080 -p 50000:50000 -v /var/run/docker.sock:/var/run/docker.sock -v /tmp/jenkins-data:/var/jenkins_home jenkinsci/blueocean` 

and we'll need to install jq in the jenkins container:

`$ docker exec --user=root jenkins apk add jq`

Once Jenkins is up and running, we have just a few things to configure:
- Get the initial password (`$ docker logs jenkins`)
- log in on port 8080
- Unlock Jenkins using the password from the logs
- Select “Install Selected Plugins” and create an admin user
- Create a credential so we can push images into Docker Hub:
	- go to manage jenkins -> manage credentials
	- click “global” and “add credentials”
	- Use your Docker Hub username and password (get an access token from Docker Hub if you are using multifactor authentication), and set the ID of the credential to “Docker Hub”.

### Part 2: A Simple Package Stoplist

Now we’ll set up a simple package stoplist with syft:

- Fork this repo
- From the jenkins main page, select “New Item” 
- Name it “syft-demo”
- Choose “pipeline” and click “OK”
- On the configuration page, scroll down to “Pipeline”
- For “Definition,” select “Pipeline script from SCM”
- For “SCM,” select “git”
- For “Repository URL,” paste in the URL of your forked github repo
	e.g. https://github.com/pvnovarese/syft-demo (with your github user ID)
- Click “Save”
- You’ll now be at the top-level project page.  Click “Build Now”

Jenkins will check out the repo and build an image using the provided Dockerfile.  This image will be a simple copy of the alpine base image with minor additions.  Once the image is built, Jenkins will call Syft, generate an sbom (SPDX format), then archive the sbom as a build artifact and push the image to docker hub (or wherever you have configured it). 

Optionally, we can also parse through the output to search for forbidden packages, and break the pipeline before the image is pushed if blocklisted packages are found.

If you are implementing the package blocking and would like to see a successful build, go to the github repo, edit the Dockerfile, and change curl to vim or something else harmless, then go back to the Jenkins project page and click “Build now” again. This time, once the image passes our Syft check, Jenkins will push it to Docker Hub using the credentials you provided.

**Challenge: can you update the Jenkinsfile to check for both curl and wget at the same time?**

### Part 3: Check for CVEs with Grype (optional)
There is a companion repo and demo for Anchore Grype here: https://github.com/pvnovarese/jenkins-grype-demo

### Part 4: Cleanup
- Kill the jenkins container (it will automatically be removed since we specified --rm when we created it):
	`pvn@gyarados /home/pvn> docker kill jenkins`
- Remove the jenkins-data directory from /tmp
	`pvn@gyarados /home/pvn> sudo rm -rf /tmp/jenkins-data/`
- Remove all demo images from your local machine:
	`pvn@gyarados /home/pvn> docker image ls | grep -E "grype-demo|syft-demo" | awk '{print $3}' | xargs docker image rm -f`

