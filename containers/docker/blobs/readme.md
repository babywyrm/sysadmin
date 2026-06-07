
##
#
https://devops.stackexchange.com/questions/2731/downloading-docker-images-from-docker-hub-without-using-docker
#
##


Downloading Docker Images from Docker Hub without using Docker
Asked 5 years, 7 months ago
Modified 1 year, 4 months ago
Viewed 133k times
74

I want to manually download a Docker Image from Docker Hub. More specifically, I want to download a Docker Image from Docker Hub on a machine in a restricted environment which does not (and cannot) have the Docker client software installed. I would have thought that this would be possible using the official API, but this does not appear to be the case - see the following discussion:

Fetch docker images without docker command. e.g. with wget
Is it really the case that the API doesn't support downloading images? Is there a way to work around this?

UPDATE 1:

I came across the following ServerFault post:

Downloading docker image for transfer to non-internet-connected machine
The accepted solution uses the docker save command, which doesn't help in my situation. But another solution posted there cites the following StackOverflow post:

Pulling docker images
One of the solutions there refers to a command-line tool called docker-registry-debug which, among other things, can generate a curl command for downloading an image. Here is what I got:

user@host:~$ docker-registry-debug curlme docker ubuntu

# Reading user/passwd from env var "USER_CREDS"
# No password provided, disabling auth
# Getting token from https://index.docker.io
# Got registry endpoint from the server: https://registry-1.docker.io
# Got token: signature=1234567890abcde1234567890abcde1234567890,repository="library/docker",access=read
curl -i --location-trusted -I -X GET -H "Authorization: Token signature=1234567890abcde1234567890abcde1234567890,repository="library/docker",access=read" https://registry-1.docker.io/v1/images/ubuntu/layer

user@host:~$ curl \
-i --location-trusted -I -X GET \
-H "Authorization: Token signature=1234567890abcde1234567890abcde1234567890,repository="library/docker",access=read" 

https://registry-1.docker.io/v1/images/ubuntu/layer
HTTP/1.1 404 NOT FOUND
Server: gunicorn/18.0
Date: Wed, 29 Nov 2017 01:00:00 GMT
Expires: -1
Content-Type: application/json
Pragma: no-cache
Cache-Control: no-cache
Content-Length: 29
X-Docker-Registry-Version: 0.8.15
X-Docker-Registry-Config: common
Strict-Transport-Security: max-age=31536000
So unfortunately it looks like the curl command generated does not work.

UPDATE 2:

It looks like I'm able to download layer blobs from Docker Hub. Here is how I'm currently going about it.

Get an authorization token:

user@host:~$ export TOKEN=\
"$(curl \
--silent \
--header 'GET' \
"https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/ubuntu:pull" \
| jq -r '.token' \
)"
Pull an image manifest:

user@host:~$ curl \
--silent \
--request 'GET' \
--header "Authorization: Bearer ${TOKEN}" \
'https://registry-1.docker.io/v2/library/ubuntu/manifests/latest' \
| jq '.'
Pull an image manifest and extract the blob sums:

user@host:~$ curl \
--silent \
--request 'GET' \
--header "Authorization: Bearer ${TOKEN}" \
'https://registry-1.docker.io/v2/library/ubuntu/manifests/latest' \
| jq -r '.fsLayers[].blobSum'

sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
sha256:be588e74bd348ce48bb7161350f4b9d783c331f37a853a80b0b4abc0a33c569e
sha256:e4ce6c3651b3a090bb43688f512f687ea6e3e533132bcbc4a83fb97e7046cea3
sha256:421e436b5f80d876128b74139531693be9b4e59e4f1081c9a3c379c95094e375
sha256:4c7380416e7816a5ab1f840482c9c3ca8de58c6f3ee7f95e55ad299abbfe599f
sha256:660c48dd555dcbfdfe19c80a30f557ac57a15f595250e67bfad1e5663c1725bb
Download a single layer blob and write it to a file:

user@host:~$ BLOBSUM=\
"sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"

user@host:~$ curl \
--silent \
--location \
--request GET \
--header "Authorization: Bearer ${TOKEN}" \
"https://registry-1.docker.io/v2/library/ubuntu/blobs/${BLOBSUM}" \
> "${BLOBSUM/*:/}.gz"
Write all of the blob sums to a file:

user@host:~$ curl \
--silent \
--request 'GET' \
--header "Authorization: Bearer ${TOKEN}" \
'https://registry-1.docker.io/v2/library/ubuntu/manifests/latest' \
| jq -r '.fsLayers[].blobSum' > ubuntu-blobsums.txt
Download all of the layer blobs from the manifest:

user@host:~$ while read BLOBSUM; do
curl \
--silent \
--location \
--request 'GET' \
--header "Authorization: Bearer ${TOKEN}" \
"https://registry-1.docker.io/v2/library/ubuntu/blobs/${BLOBSUM}" \
> "${BLOBSUM/*:/}.gz"; \
done < blobsums.txt
Now I have a bunch of layer blobs and I need to recombine them into an image - I think.

Related Links:

Docker Community Forums: Docker Hub API retrieve images

Docker Community Forums: Manual download of Docker Hub images

Docker Issue #1016: Fetch docker images without docker command. e.g. with wget

ServerFault: Downloading docker image for transfer to non-internet-connected machine

StackOverflow: Downloading docker image for transfer to non-internet-connected machine

StackOverflow: How to download docker images without using pull command?

StackOverflow: Is there a way to download docker hub images without “docker pull” for a machine with out Internet access?

StackOverflow: Docker official registry (Docker Hub) URL

dockerdockerhub
Share
Improve this question
Follow
edited Mar 6, 2022 at 13:12
030's user avatar
030
13.1k1515 gold badges6767 silver badges168168 bronze badges
asked Nov 29, 2017 at 19:23
igal's user avatar
igal
1,40011 gold badge1010 silver badges1515 bronze badges
1
"More specifically, I want to download a Docker Image from Docker Hub on a machine in a restricted environment which does not (and cannot) have the Docker client software installed." => What's the point to have the images on this machine then ? (easier workaround is using a pivot host, one where you acn docker pull from dockerhub and docker save/ docker push to an internal registry after) – 
Tensibai
 Nov 30, 2017 at 11:06
@Tensibai To copy it to another machine that does have Docker but doesn't have internet access. – 
igal
 Nov 30, 2017 at 13:46
1
Did you had a look at the docker pull code? It sounds the way to go to build something like this from basic http calls – 
Tensibai
 Nov 30, 2017 at 19:04
@Tensibai I think I figured it out. I also think I got a solution from the Docker community. I'll come back and post the solution later today. – 
igal
 Nov 30, 2017 at 20:57
@Tensibai I posted a solution with a shell script that solves the problem. – 
igal
 Dec 3, 2017 at 15:04
Show 2 more comments
8 Answers
Sorted by:

Highest score (default)
50

It turned out that the Moby Project has a shell script on the Moby Github which can download images from Docker Hub in a format that can be imported into Docker:

download-frozen-image-v2.sh
The usage syntax for the script is given by the following:

download-frozen-image-v2.sh target_dir image[:tag][@digest] ...
The image can then be imported with tar and docker load:

tar -cC 'target_dir' . | docker load
To verify that the script works as expected, I downloaded an Ubuntu image from Docker Hub and loaded it into Docker:

user@host:~$ bash download-frozen-image-v2.sh ubuntu ubuntu:latest
user@host:~$ tar -cC 'ubuntu' . | docker load
user@host:~$ docker run --rm -ti ubuntu bash
root@1dd5e62113b9:/#
In practice I would have to first copy the data from the internet client (which does not have Docker installed) to the target/destination machine (which does have Docker installed):

user@nodocker:~$ bash download-frozen-image-v2.sh ubuntu ubuntu:latest
user@nodocker:~$ tar -C 'ubuntu' -cf 'ubuntu.tar' .
user@nodocker:~$ scp ubuntu.tar user@hasdocker:~
and then load and use the image on the target host:

user@hasdocker:~ docker load ubuntu.tar
user@hasdocker:~ docker run --rm -ti ubuntu bash
root@1dd5e62113b9:/#
Share
Improve this answer
Follow
edited Mar 8, 2022 at 10:47
030's user avatar
030
13.1k1515 gold badges6767 silver badges168168 bronze badges
answered Dec 3, 2017 at 14:56
igal's user avatar
igal
1,40011 gold badge1010 silver badges1515 bronze badges
1
The machine with internet connectivity does not and cannot have Docker installed. but you apply docker load – 
030
 Dec 3, 2017 at 15:11
@030 Just to test/demonstrate that the script works and that the download image data can be imported into Docker. In practice I would first have to copy the data to a machine with Docker installed. – 
igal
 Dec 3, 2017 at 15:13
Perhaps you could add that part for clarification – 
030
 Dec 3, 2017 at 15:13
2
@030 I added an example session illustrating what the workflow would look like in practice. – 
igal
 Dec 3, 2017 at 15:20
Add a comment
18

There is a tool called Skopeo which can retrieve Docker images from a repository and save them in several formats.

For example:

Download the image and save the layers as a tarball: skopeo copy docker://ubuntu docker-archive:/tmp/ubuntu.tar:ubuntu

Transfer /tmp/ubuntu.tar to another machine if desired.

Load the image on a Docker instance which does not have internet connection: docker load --input /tmp/ubuntu.tar

It is available in CentOS 7 repo with the package name skopeo. There are no Debian or Ubuntu packages at this time (but it is easy to compile).

Share
Improve this answer
Follow
answered Nov 20, 2018 at 17:20
snap's user avatar
snap
28122 silver badges44 bronze badges
FWIW there are deb packages now: github.com/containers/skopeo/blob/master/install.md – 
Jeremy Davis
 Sep 18, 2020 at 23:05
Add a comment
5

thanks for motivation. I made a powershell version of it. Check it out... With it you can move in dockerhub containers to a restricted docker networks with a windows desktop and an ssh-scp tool to docker machine without root or administrator rights

https://gitlab.com/Jancsoj78/dockerless_docker_downloader a new hacker tool :)

$image = "ubuntu"
$tag = "latest"
$imageuri = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/"+$image+":pull"
$taguri = "https://registry-1.docker.io/v2/library/"+$image+"/manifests/"+$tag
$bloburi = "https://registry-1.docker.io/v2/library/"+$image+"/blobs/sha256:"

#token request
$token = Invoke-WebRequest -Uri $imageuri | ConvertFrom-Json | Select -expand token

#pull image manifest
$blobs = $($(Invoke-Webrequest -Headers @{Authorization="Bearer $token"} -Method GET -Uri $taguri | ConvertFrom-Json | Select -expand fsLayers ) -replace "sha256:" -replace "@{blobSum=" -replace "}")

#download blobs
for ($i=0; $i -lt $blobs.length; $i++) {
    $blobelement =$blobs[$i]

    Invoke-Webrequest -Headers @{Authorization="Bearer $token"} -Method GET -Uri $bloburi$blobelement -OutFile blobtmp

    $source = "blobtmp"
    $newfile = "$blobelement.gz"

#overwrite
Copy-Item $source $newfile -Force -Recurse
#source blobs
ls *.gz
}
#postprocess
echo "copy these .gz to your docker machine"
echo "docker import .gz backward one by one"
echo "lastone with ubuntu:latest"
echo "after docker export and reimport to make a simple layer image"
Share
Improve this answer
Follow
edited Mar 22, 2019 at 19:46
answered Mar 20, 2019 at 16:37
Jancsó József's user avatar
Jancsó József
5111 silver badge33 bronze badges
Add a comment
3

Here is an adapted python script, thus having an OS independant solution: docker-drag

Use it like that, and it will create a TAR archive that you will be able to import using docker load :

python docker_pull.py hello-world
python docker_pull.py alpine:3.9
python docker_pull.py kalilinux/kali-linux-docker
Share
Improve this answer
Follow
edited Apr 9, 2019 at 13:17
answered Apr 9, 2019 at 13:13
Dutfaz's user avatar
Dutfaz
3122 bronze badges
2
If you close your github account there's nothing left, if you're ok with sharing it, keep the link but paste the script here also please. You can edit your answer, paste your code and then select it and type ctrl+K or the {} (code) button in the editor top bar to format it. – 
Tensibai
 Apr 9, 2019 at 13:16
I would love to paste the code here but it is 100 lines long and I don't think it will be readable. Nevertheless, you can fork the code to save your own copy of the script. – 
Dutfaz
 Apr 9, 2019 at 13:19 
That's not for me, that to have an answer which is self sustaining, if the link break, do you really think this may help someone reading this answer in a few months ? (btw the maximum size for an answer is 30k characters) – 
Tensibai
 Apr 9, 2019 at 13:39 
You could put this in pip. I find it very helpful. – 
Anoyz
 Apr 18, 2021 at 18:24
Add a comment
1

To me it is not completely clear what you are trying to achieve and why the attempts are not a solution for the problem. If I would need to solve this issue I would like @Tensibai and other Q&As indicated, do a docker pull first on a system with internet connectivity, save the docker image, copy it to the machine without internet connectivity, load the image and run it.

Demonstration

There are no images on system A:

userA@systemA ~ $ docker images
REPOSITORY        TAG               IMAGE ID          CREATED             SIZE
userA@systemA ~ $
Pull an image from dockerhub:

userA@systemA ~ $
docker pull nginx
Using default tag: latest
latest: Pulling from library/nginx
bc95e04b23c0: Pull complete 
f3186e650f4e: Pull complete 
9ac7d6621708: Pull complete 
Digest: sha256:b81f317384d7388708a498555c28a7cce778a8f291d90021208b3eba3fe74887
Status: Downloaded newer image for nginx:latest
userA@systemA ~ $ docker images
REPOSITORY        TAG               IMAGE ID            CREATED             SIZE
nginx             latest            9e7424e5dbae        10 days ago         108MB
Save docker image:

userA@systemA ~ $ docker save nginx -o nginx.tar
Copy docker image to systemB and load it.

userB@systemB ~ $ docker load -i nginx.tar
cec7521cdf36: Loading layer  58.44MB/58.44MB
350d50e58b6c: Loading layer  53.76MB/53.76MB
63c39cd4a775: Loading layer  3.584kB/3.584kB
Loaded image: nginx:latest
userB@systemB ~ $ docker images
REPOSITORY        TAG               IMAGE ID            CREATED             SIZE
nginx             latest            9e7424e5dbae        10 days ago         108MB
Share
Improve this answer
Follow
edited Dec 3, 2017 at 13:35
answered Dec 3, 2017 at 13:26
030's user avatar
030
13.1k1515 gold badges6767 silver badges168168 bronze badges
2
The machine with internet connectivity does not and cannot have Docker installed. The question is asking for a way to download an image without using the Docker client. See my solution. – 
igal
 Dec 3, 2017 at 15:03
Add a comment
1

I didn't really understand Jancsó's way of postprocessing, so I've spent some time to modify his script and here's what I came with:

https://github.com/meetyourturik/dockerless-docker-downloader

upd: apparently, 'a link only answer...' is something bad, so here's a whole script:

# Workaround for SelfSigned Cert an force TLS 1.2
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# use 'library/' prefix for 'official' images like postgres 
$image = "atlassian/jira-software" 
$tag = "8.13.2" 

$imageuri = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${image}:pull" 
$taguri = "https://registry-1.docker.io/v2/${image}/manifests/${tag}"
$bloburi = "https://registry-1.docker.io/v2/${image}/blobs/" 

# generating folder to save image files 
$path = "$image$tag" -replace '[\\/":*?<>|]'
if (!(test-path $path)) { 
    New-Item -ItemType Directory -Force -Path $path 
} 

# token request 
$token = Invoke-WebRequest -Uri $imageuri | ConvertFrom-Json | Select -expand token 

# getting image manifest 
$headers = @{} 
$headers.add("Authorization", "Bearer $token") 
# this header is needed to get manifest in correct format: https://docs.docker.com/registry/spec/manifest-v2-2/ 
$headers.add("Accept", "application/vnd.docker.distribution.manifest.v2+json") 
$manifest = Invoke-Webrequest -Headers $headers -Method GET -Uri $taguri | ConvertFrom-Json 

# downloading config json 
$configSha = $manifest | Select -expand config | Select -expand digest 
$config = ".\$path\config.json" 
Invoke-Webrequest -Headers @{Authorization="Bearer $token"} -Method GET -Uri $bloburi$configSha -OutFile $config 

# generating manifest.json 
$manifestJson = @{} 
$manifestJson.add("Config", "config.json") 
$manifestJson.add("RepoTags",@("${image}:${tag}")) 

# downloading layers 
$layers = $manifest | Select -expand layers | Select -expand digest 
$blobtmp = ".\$path\blobtmp" 

#downloading blobs 
$layersJson = @() 
foreach ($blobelement in $layers) { 
    # making so name doesnt start with 'sha256:' 
    $fileName = "$blobelement.gz" -replace 'sha256:' 
    $newfile = ".\$path\$fileName" 
    $layersJson += @($fileName) 

    # token expired after 5 minutes, so requesting new one for every blob just in case 
    $token = Invoke-WebRequest -Uri $imageuri | ConvertFrom-Json | Select -expand token 
    
    Invoke-Webrequest -Headers @{Authorization="Bearer $token"} -Method GET -Uri $bloburi$blobelement -OutFile $blobtmp 
    
    Copy-Item $blobtmp $newfile -Force -Recurse 
} 

# removing temporary blob 
Remove-Item $blobtmp 

# saving manifest.json 
$manifestJson.add("Layers", $layersJson) 
ConvertTo-Json -Depth 5 -InputObject @($manifestJson) | Out-File -Encoding ascii ".\$path\manifest.json" 

# postprocessing
echo "copy generated folder to your docker machine" 
echo "tar -cvf imagename.tar *" 
echo "docker load < imagename.tar"
after sctipt downloads blobs and generates config and manifest jsons download it to docker machine and execute two following commands:

tar -cvf imagename.tar *
docker load < imagename.tar
first creates an archive, 2nd uploads image archive to docker

Share
Improve this answer
Follow
edited Jul 24, 2021 at 9:44
answered Jul 22, 2021 at 19:23
ilya turov's user avatar
ilya turov
1122 bronze badges
Add a comment
0

Another tool that could be used to download docker images is P2IWD.

Share
Improve this answer
Follow
answered Mar 6, 2022 at 13:11
030's user avatar
030
13.1k1515 gold badges6767 silver badges168168 bronze badges
There doesn’t appear to be any code in that repository. – 
igal
 Mar 6, 2022 at 13:24
@igal version 0.1.0 has been released. It is capable to download docker images from a Nexus3 server and to upload them to another one. – 
030
 Mar 6, 2022 at 22:11
Add a comment
-1

If your company has nexus or a similar repository, they may already have set up nexus to pull in what you need. You could try adding your repo's host/ip in front of the relative docker hub path.

Examples:

docker pull nexus.example.com:18443/nginx
docker pull nexus.example.com:18443/selenium/node-chrome
docker pull nexus.example.com:18443/postgres:9.4
Share
Improve this answer
Follow
