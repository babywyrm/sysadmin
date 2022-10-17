
https://www.cloudsavvyit.com/14680/how-to-index-your-docker-images-dependencies-with-syft/

##
##

https://pythonlang.dev/repo/anchore-anchore-engine/

##
##
##

Changing the Output Format
The default output format is called table. It renders a columnar-based table of results in your terminal, creating a new row for each detected package. An alternative human-readable format is text which presents a list of packages with Version and Type fields nested under each section.



Syft supports several programmatic formats too:

json – Save package data to a JSON structure.
cyclonedx – A CycloneDX report in XML format.
spdx and spdx-json – SPDX-compatible reports in either tag-value or JSON format.
Using one of these reports lets you archive findings to a file for later reference:

syft packages alpine:latest -o json > alpine-packages.json
The standardized CycloneDX and SPDX formats can help integrate Syft scans into your CI/CD pipelines. The data is accessible to other ecosystem tools that work with package lists and SBOM results.

Syft also integrates with Grype, Anchore’s standalone container filesystem vulnerability finder. Data from Syft can be fed straight into Grype if you use the JSON output format.

syft packages example-image:latest -o json > sbom.json
grype sbom:./sbom.json
Grype will compare the package list to its index of known vulnerabilities. It’ll highlight the packages which contain problems, giving you an immediate starting point to improve your security posture.

Using Other Image Sources
Syft can use images from other sources besides public Docker registries. You can reference any OCI-compliant image, either via a registry tag or as a saved image tar. Paths to image archives can be handed straight to Syft:

docker image save my-image:latest > my-image.tar
syft packages ./my-image.tar
ADVERTISEMENT

Syft works with private Docker registries too. It uses your existing credentials in your ~/.docker/config.json file:

{
    "auths": {
        "registry.example.com": {
            "username": "",
            "password": ""
        }
    }
}
Although Syft focuses on container image scans, it can also create an SBOM for arbitrary filesystem paths. You can use Syft to index your host’s packages by scanning directories that commonly contain software binaries and libraries:

syft packages dir:/usr/bin
You must explicitly add the dir: scheme if you’re referencing a path outside your working directory. Otherwise Syft will try to interpret it as an image tag reference.



#######################
#######################


I have node 12.14 docker image which I am using for my applications. But today I was asked to provide Software Bill of materials (SBOM) for this docker image. I am not sure how to get that.

Any inputs that you provide to help me get Software Bill of materials will be greatly appreciated.

node.js
docker
Share
Follow
asked Jul 21, 2020 at 16:23
user avatar
Raghavendra Prasad
56911 gold badge44 silver badges1010 bronze badges
The Dockerfile of the image may be a good start. – 
Henry
 Jul 21, 2020 at 16:33
Your service's package.json file is probably a key part of this too. – 
David Maze
 Jul 21, 2020 at 16:47
Add a comment
1 Answer
Sorted by:

Highest score (default)


Anchore Engine CircleCI
For the most up-to-date information on Anchore Engine, Anchore CLI, and other Anchore software, please refer to the Anchore Documentation .

The Anchore Engine is an open-source project that provides a centralized service for inspection, analysis, and certification of container images. The Anchore Engine is provided as a Docker container image that can be run standalone or within an orchestration platform such as Kubernetes, Docker Swarm, Rancher, Amazon ECS, and other container orchestration platforms.

In addition, we also have several modular container tools that can be run standalone or integrated into automated workflows such as CI/CD pipelines.

Syft : a CLI tool and library for generating a Software Bill of Materials (SBOM) from container images and filesystems

Grype : a vulnerability scanner for container images and filesystems

The Anchore Engine can be accessed directly through a RESTful API or via the Anchore CLI .

With a deployment of Anchore Engine running in your environment, container images are downloaded and analyzed from Docker V2 compatible container registries and then evaluated against user-customizable policies to perform security, compliance, and best practices enforcement checks.

Anchore Engine can be used in several ways:

Standalone or interactively.
As a service integrated with your CI/CD to bring security/compliance/best-practice enforcement to your build pipeline
As a component integrated into existing container monitoring and control frameworks via integration with its RESTful API.
Anchore Engine is also the OSS foundation for Anchore Enterprise , which adds a graphical UI (providing policy management, user management, a summary dashboard, security and policy evaluation reports, and many other graphical client controls), and other back-end features and modules.

Supported Operating Systems

Alpine
Amazon Linux 2
CentOS
Debian
Google Distroless
Oracle Linux
Red Hat Enterprise Linux
Red Hat Universal Base Image (UBI)
Ubuntu
Supported Packages

GEM
Java Archive (jar, war, ear)
NPM
Python (PIP)
Installation
There are several ways to get started with Anchore Engine, for the latest information on quickstart and full production installation with docker-compose, Helm, and other methods, please visit:

Anchore Engine Installation
The Anchore Engine is distributed as a Docker Image available from DockerHub.

Quick Start (TLDR)
See documentation for the full quickstart guide.

To quickly bring up an installation of Anchore Engine on a system with docker (and docker-compose) installed, follow these simple steps:

curl https://engine.anchore.io/docs/quickstart/docker-compose.yaml > docker-compose.yaml
docker-compose up -d

 
Once the Engine is up and running, you can begin to interact with the system using the CLI.

Getting Started using the CLI
The Anchore CLI is an easy way to control and interact with the Anchore Engine.

The Anchore CLI can be installed using the Python pip command, or by running the CLI from the Anchore Engine CLI container image. See the Anchore CLI project on Github for code and more installation options and usage.

CLI Quick Start (TLDR)
By default, the Anchore CLI tries to connect to the Anchore Engine at http://localhost:8228/v1 with no authentication. The username, password, and URL for the server can be passed to the Anchore CLI as command-line arguments:

--u   TEXT   Username     eg. admin
--p   TEXT   Password     eg. foobar
--url TEXT   Service URL  eg. http://localhost:8228/v1

 
Rather than passing these parameters for every call to the tool, they can also be set as environment variables:

ANCHORE_CLI_URL=http://myserver.example.com:8228/v1
ANCHORE_CLI_USER=admin
ANCHORE_CLI_PASS=foobar
Add an image to the Anchore Engine:

anchore-cli image add docker.io/library/debian:latest
Wait for the image to move to the 'analyzed' state:


 
anchore-cli image wait docker.io/library/debian:latest
List images analyzed by the Anchore Engine:

anchore-cli image list
Get image overview and summary information:

anchore-cli image get docker.io/library/debian:latest
List feeds and wait for at least one vulnerability data feed sync to complete. The first sync can take some time (20-30 minutes) after that syncs will only merge deltas.


 
anchore-cli system feeds list
anchore-cli system wait
Obtain the results of the vulnerability scan on an image:

anchore-cli image vuln docker.io/library/debian:latest os
List operating system packages present in an image:

anchore-cli image content docker.io/library/debian:latest os
API
For the external API definition (the user-facing service), see External API Swagger Spec . If you have Anchore Engine running, you can also review the Swagger by directing your browser at http://:8228/v1/ui/ (NOTE: the trailing slash is required for the embedded swagger UI browser to be viewed properly).

Each service implements its own API, and all APIs are defined in Swagger/OpenAPI spec. You can find each in the anchore_engine/services/<servicename>/api/swagger directory.

More Information
For further details on the use of the Anchore CLI with the Anchore Engine, please refer to the Anchore Engine Documentation

Developing
This repo was reformatted using Black in Nov. 2020. This commit can be ignored in your local environment when using git blame since it impacted so many files. To ignore the commit you need to configure git-blame to use the provided file: .git-blame-ignore-revs as a list of commits to ignore for blame.

Set your local git configuration to use the provided file by running this from within the root of this source tree: git config blame.ignoreRevsFile .git-blame-ignore-revs

Anchore - Anchore-Engine

Anchore / Anchore-engine

A service that analyzes docker images and applies user-defined acceptance policies to allow automated container image validation and certification.

Apache License 2.0

python, shell, makefile, dockerfile, c
Pull Requests (22)
Issues (100+)
Categories
Docker Containers Security Python Static Analysis Vulnerabilities Docker Image Anchore Engine Dockerhub Whitelist
Pull Requests - Issues


I've personally not been tasked with something like this before, but I'd take a guess that looking at the history might be a good start:

# You may need to first run "docker pull node:12.14"
docker history --format '{{.CreatedBy}}' --no-trunc --human node:12.14
This will output the list of commands used to build the image and you'll have to decide what's appropriate for the team requesting the bill of materials from you.

Otherwise, you can look at the source for the Dockerfile directly at GitHub. This point in the history appears to be the latest commit that builds the 12.14 release (I could be wrong so please feel free to dig around that repository and its history yourself as well).

Share
Follow
    
##
##
    
    

Announcing Docker SBOM: A step towards more visibility into Docker images

Justin Cormack

Apr 7 2022

Today, Docker takes its first step in making what is inside your container images more visible so that you can better secure your software supply chain. Included in Docker Desktop 4.7.0 is a new, experimental docker sbom CLI command that displays the SBOM (Software Bill Of Materials) of any Docker image. It will also be included in our Linux packages in an upcoming release. The functionality was developed as an open source collaboration with Anchore using their Syft project.

As I wrote in my blog post last week, at Docker our priorities are performance, trust and great experiences. This work is focused on improving trust in the supply chain by making it easier to see what is in images and providing SBOMs to consumers of software, and improving the developer experience by making container images more transparent, so you can easily see what is inside of them. This command is just a first step that Docker is taking to make container images more self descriptive. We believe that the best time to determine and record what is in a container image is when you are putting the image together with docker build. To enable this, we are working on making it easy for partners and the community to add SBOM functionality to docker build using BuildKit’s extensibility.

As this information is generated at build time, we believe that it should be included as part of the image artifact. This means that if you move images between registries (or even into air gapped environments), you should still be able to read the SBOM and other image build metadata off of the image.

We’re looking to collaborate with partners and those in the community on our SBOM work in BuildKit. Take a look at our PoC and leave feedback here.
What is an SBOM?

A Software Bill Of Materials (SBOM) is analogous to a packing list for a shipment; it’s all the components that make up the software, or were used to build it. For container images, this includes the operating system packages that are installed (e.g.: ca-certificates) along with language specific packages that the software depends on (e.g.: log4j). The SBOM could include only some of this information or even more details, like the versions of components and where they came from.

SBOMs are sometimes required by governments or other software consumers who are trying to improve their supply chain security. This is because knowing what is inside your software gives you confidence that it is safe to use and can be useful in understanding impact when a vulnerability is made public.
Using the container image SBOM to check for a vulnerability

Let’s take a quick look at what the docker sbom command can do to help when a vulnerability like log4shell is made public. When a vulnerability like this appears, it’s crucial that you can quickly determine if your software is impacted. We’ll use the neo4j:4.4.5 Docker Official Image. Just running docker sbom neo4j:4.4.5 outputs a tabulated form of the SBOM:

$ docker sbom neo4j:4.4.5

Syft v0.42.2

 ✔ Loaded image            

 ✔ Parsed image            

 ✔ Cataloged packages      [385 packages]




NAME                      VERSION                        TYPE

... 

bsdutils                  1:2.36.1-8+deb11u1             deb

ca-certificates           20210119                       deb

...

log4j-api                 2.17.1                         java-archive  

log4j-core                2.17.1                         java-archive  

...

Note that the output includes not only the Debian packages that have been installed inside the image but also the Java libraries used by the application. Getting this information reliably and with minimal effort allows you to promptly respond and reduce the chance that you will be breached. In the above example, we can see that Neo4j uses version 2.17.1 of the log4j-core library which means that it is not affected by log4shell.

Without docker sbom or another SBOM scanning tool, you would need to check your application’s source code to see which version of log4j-core you are using. When you have several applications or services deployed and multiple versions of them, this can be difficult.

In addition to outputting the SBOM in a table, the docker sbom command has options for outputting SBOM in the standard SPDX and CycloneDX formats along with the GitHub and native Syft formats.

We are sharing the docker sbom functionality early, as an experimental command, with the intention of getting feedback from the community on the direction that we’re going. We’d like to know about your use cases and any other feedback that you have. You can leave it on the command’s repo.
What’s next?

We’d love to collaborate with partners and the community on bringing SBOMs to all container images through BuildKit so please hack on our example and leave feedback on our RFC. Please also give the experimental docker sbom command a try and leave us any feedback that you have. You can also read more about the docker sbom collaboration with Anchore on their blog.
    
##
##
############
    
    
