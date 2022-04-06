

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

1

I've personally not been tasked with something like this before, but I'd take a guess that looking at the history might be a good start:

# You may need to first run "docker pull node:12.14"
docker history --format '{{.CreatedBy}}' --no-trunc --human node:12.14
This will output the list of commands used to build the image and you'll have to decide what's appropriate for the team requesting the bill of materials from you.

Otherwise, you can look at the source for the Dockerfile directly at GitHub. This point in the history appears to be the latest commit that builds the 12.14 release (I could be wrong so please feel free to dig around that repository and its history yourself as well).

Share
Follow
