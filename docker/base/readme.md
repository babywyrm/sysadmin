


##
#
https://stackoverflow.com/questions/58018422/how-to-find-out-the-base-image-for-a-docker-image
#
##


I have a docker image and I would like to find out from which image it has been created. Of course there are multiple layers, but I'd like to find out the last image (the FROM statement in the dockerfile for this image)?

I try to use docker image history and docker image inspect but I can't find this information in there.

I tried to use the following command but it gives me a error message

alias dfimage="sudo docker run -v /var/run/docker.sock:/var/run/docker.sock --rm xyz/mm:9e945ff"
dfimage febae8978318
This is the error message I'm getting

container_linux.go:235: starting container process caused "exec: \"febae8978318\": executable file not found in $PATH"
/usr/bin/docker-current: Error response from daemon: oci runtime error: container_linux.go:235: starting container process caused "exec: \"febae8978318\": executable file not found in $PATH".
docker
Share
Improve this question
Follow
edited Sep 20, 2019 at 13:10
asked Sep 19, 2019 at 20:17
HHH's user avatar
HHH
5,8951818 gold badges8989 silver badges162162 bronze badges
Answer is here: stackoverflow.com/a/53841690/3691891 – 
Arkadiusz Drabczyk
 Sep 19, 2019 at 20:19
Add a comment
4 Answers
Sorted by:

Highest score (default)

29


Easy way is to use

docker image history deno
This above command will give you output like this

enter image description here

Then just look at the IMAGE column and take that image ID which a24bb4013296 which is just above the first <missing>

Then just do the

For Linux

docker image ls | grep a24bb4013296
For Windows

docker image ls | findstr a24bb4013296
This will give you the base image name

enter image description here

Share
Improve this answer
Follow
edited Aug 12, 2020 at 8:55
answered Jul 18, 2020 at 11:49
Dashrath Mundkar's user avatar
Dashrath Mundkar
7,09822 gold badges2626 silver badges4040 bronze badges
19
I think for this to work you need to build the image yourself. At least after docker 1.10 those are intermediate layers you don't get when pulling the image from repository. See stackoverflow.com/a/35312577/5519328 – 
Petri Ryhänen
 Oct 8, 2020 at 7:49
8
yup I just tried this and it all shows as missing – 
KillerSnail
 Mar 11, 2021 at 4:58
As I recall this used to work but no longer does. – 
Jason
 Dec 2, 2021 at 2:12
2
Why I see missing in the IMAGE column, like this: <missing> 9 months ago – 
John Xiao
 Jun 1, 2022 at 7:44 
Add a comment

14


The information doesn't really exist, exactly. An image will contain the layers of its parent(s) but there's no easy way to reverse layer digests back to a FROM statement, unless you happen to have (or are able to figure out) the image that contains those layers.

If you have the parent image(s) on-hand (or can find them), you can infer which image(s) your image used for its FROM statement (or ancestry) by cross-referencing the layers.

Theoretical example
Suppose your image, FOO, contains the layers 1 2 3 4 5 6. If you have another image, BAR on your system containing layers 1 2 3, you could infer that image BAR is an ancestor of image FOO -- I.E. that FROM BAR would have been used at some point in its hierarchy.

Suppose further that you have another image, BAZ which contains the layers 1 2 3 4 5. You could infer that image BAZ has image BAR in its ancestry and that image FOO inherits from image BAZ (and therefore indirectly from BAR).

From this, information you could infer the dockerfiles for these images might have looked something like this:

# Dockerfile of image BAR
FROM scratch
# layers 1 2 and 3
COPY ./one /
COPY ./two /
COPY ./three /
# Dockerfile of Image BAZ
FROM BAR
RUN echo "this makes layer 4" > /four
RUN echo "this makes layer 5" > /five
# Dockerfile of image FOO
FROM BAZ
RUN echo "this makes layer 6" > /six
You could get the exact commands by looking at docker image history for each image.

One important thing to keep in mind here, however, is that docker tags are mutable; maintainers make new images and move the tags to those images. So if you built an image with FROM python:3.8.1 today, it won't contain the same layers as if you had built an image with that same FROM line a few weeks ago. You'll need the SHA256 digest to be sure you're using the exact same image.

Practical Example, local images
Now that we understand the theory behind identifying images and their bases, let's put it to practice with a real-world example.

Note: because the tags I use will change over time (see above RE: tag mutability), I'll be using the SHA256 digest to pull the images in this example so it can be reproduced by viewers of this answer.

Let's say we have a particular image and we want to find its base(s). We'll use the official maven image here.

First, we'll take a look at its layers.

# maven:3.6-jdk-11-slim at time of writing, on my platform
IMAGE="docker.io/maven@sha256:55f1c145a04e01706233d68fe0b6b20bf76f765ab32f3fe6e29c8ef933917af6"
docker pull $IMAGE
docker image inspect $IMAGE | jq -r '.[].RootFS.Layers[]'
This will output the layers:

sha256:6e06900bc10223217b4c78081a857866f674c462e4f90593b01894da56df336d
sha256:eda2f4da9b1e70500ac340d40ee039ef3877e8be13b9a24cd345406bf6693412
sha256:6bdb7b3c3e226bdfaa911ba72a95fca13c3979cd150061d570cf569e93037ce6
sha256:ce217e530345060ca0973807a3288560e1e15cf1a4eeec44d6aa594a926c92dc
sha256:f256c980a7d17a00f57fd42a19f6323fcc2341fa46eba128def04824cafa5afa
sha256:446b1af848de2dcb92bbd229ca6ecaabf2f48dab323c19f90d02622e09a8fa67
sha256:10652cf89eaeb5b5d8e0875a6b1867b5cf92c509a9555d3f57d87fab605115a3
sha256:d9a4cf86bf01eb170242ca3b0ce456159fd3fddc9c4d4256208a9d19bae096ca
Now, from here, we can try to find other images that have a (strict) subset of these layers. Assuming you have the images on-hand, you can find them by cross-referencing the layers of images you have on disk, for example, using docker image inspect.

In this case, I just happen to know what these images are and have them on-hand (I'll discuss later what you might do if you don't have the images on-hand) so we'll go ahead and pull those images and take a look at the layers.

If you want to follow along:

# openjdk:11.0.10-jdk-slim at time of writing, on my platform
OPENJDK='docker.io/openjdk@sha256:fe6a46a26ff7d6c31b258e07b3d53f0c42fe68f55f646cc39d60d0b17cbc827b'

# debian:buster-20210329-slim at time of writing on my platform
DEBIAN='docker.io/debian@sha256:088be7d6017ad3ae98325f47707112e1f61687c371be1865e55d5e5531ca97fd'

docker pull $OPENJDK
docker pull $DEBIAN
If we inspect these images and compare them against the layers we saw in the output of docker image inspect for the maven image, we can confirm that the layers from openjdk and debian are present in our original maven image.

$ docker image inspect $DEBIAN | jq -r '.[].RootFS.Layers[]'
sha256:6e06900bc10223217b4c78081a857866f674c462e4f90593b01894da56df336d

$ docker image inspect $OPENJDK | jq -r '.[].RootFS.Layers[]'
sha256:6e06900bc10223217b4c78081a857866f674c462e4f90593b01894da56df336d
sha256:eda2f4da9b1e70500ac340d40ee039ef3877e8be13b9a24cd345406bf6693412
sha256:6bdb7b3c3e226bdfaa911ba72a95fca13c3979cd150061d570cf569e93037ce6
sha256:ce217e530345060ca0973807a3288560e1e15cf1a4eeec44d6aa594a926c92dc
As stated, because these 5 layers are a strict subset of the 8 layers from the maven image, we can conclude the openjdk and debian images are, at least, both in the ancestry path of the maven image.

We can further infer that the last 3 layers most likely come from the maven image itself (or, potentially, some unknown image).

Caveats, when you don't have images locally
Now, of course the above only works because I happen to have all the images on-hand. So, you'd either need to have the images or be able to locate them by the layer digests.

You might still be able to figure this out using information that may be available from registries like Docker Hub or your own private repositories.

For official images, the docker-library/repo-info contains historical information about the official images, including the layer digests for the various tags cataloged over the last several years. You could use this, for example, as a source of layer information.

If you can imagine this like a database of layer digests, you could infer ancestry of at least these official images.

"Distribution" (remote) digests vs "Content" (local) digests
An important caveat to note is that, when you inspect an image for its layer digests locally, you are getting the content digest of the layers. If you are looking at layer digests in a registry manifest (like what appears in the docker-library/repo-info project) you get the compressed distribution digest and won't be able to compare the layer digests with content.

So you can compare digests local <--> local OR remote <--> remote only.

Example, using remote images
Suppose I want to do this same thing, but I want to associate images in a remote repository and find its base(s). We can do the same thing by looking at the layers in the remote manifest.

You can find references how to do this for your particular registry, as described in this answer for dockerhub.

Using the same images from the example above, we would find that the distribution layer digests also match in the same way.

$ get-remote-layers $IMAGE
sha256:6fcf2156bc23db75595b822b865fbc962ed6f4521dec8cae509e66742a6a5ad3
sha256:96fde6667c188c81fcddee021ccbb3e054ebe83350fd4609e17a3d37f0ec7f9d
sha256:74d17759dd2a1b51afc740fadd96f655260689a2087308e40d1865a0098c5fae
sha256:bbe8ebb5d0a64d265558901c7c6c66e1d09f664da57cdb2e5f69ba52a7109d31
sha256:b2edaadd7dd62cfe7f551b902244ee67b84bc5c0b6538b9480ac9ca97a0a4986
sha256:0fca65d33e353bdfdd5edd8d4c8ab5efde52c078bd25e2dcf454f995e5420725
sha256:d6d771d0512387eee1e419a965b929a9a3b0365cf1935b3719d60bf9feffcf63
sha256:dee8cd26669373102db07820072127c46bbfdad340a586ee9dfe60ae933eac2b

$ get-remote-layers $DEBIAN
sha256:6fcf2156bc23db75595b822b865fbc962ed6f4521dec8cae509e66742a6a5ad3

$ get-remote-layers $OPENJDK
sha256:6fcf2156bc23db75595b822b865fbc962ed6f4521dec8cae509e66742a6a5ad3
sha256:96fde6667c188c81fcddee021ccbb3e054ebe83350fd4609e17a3d37f0ec7f9d
sha256:74d17759dd2a1b51afc740fadd96f655260689a2087308e40d1865a0098c5fae
sha256:bbe8ebb5d0a64d265558901c7c6c66e1d09f664da57cdb2e5f69ba52a7109d31
One other caveat with distribution digests in repositories is that you can only compare digests of the same manifest schema version. So, if an image was pushed with manifest v1 it won't have the same digest pushed again with manifest v2.

TL;DR
Images contain the layers of their ancestor image(s). Therefore, if an image A contains a strict subset of image B layers, you know that image B is a descendent of image A.

You can use this property of Docker images to determine the base images from which your images were derived.

Share
Improve this answer
Follow
edited Sep 9, 2022 at 17:59
answered Jun 10, 2021 at 20:11
sytech's user avatar
sytech
24.1k33 gold badges3939 silver badges7777 bronze badges
Where is get-remote-layers defined? – 
Jason
 Dec 2, 2021 at 4:25
@Jason is may be dependent on the registry you use. For Dockerhub, the linked answer has a working implementation for retrieving the manifest from a remote repo. The layer digests are in the manifest. – 
sytech
 Dec 2, 2021 at 10:11
From what I've observed, Layers array present in manifest.json in a docker tarball always have the last layer from base image missing in the child image. – 
Hritik
 Jan 27 at 10:16
Add a comment

10


You can use method suggested in this answer: https://stackoverflow.com/a/53841690/3691891

First, pull chenzj/dfimage:

docker pull chenzj/dfimage
Get ID of your image:

docker images | grep <IMAGE_NAME> | awk '{print $3}'
Replace <IMAGE_NAME> with the name of your image. Use this ID as the parameter to chenzj/dfimage:

docker run -v /var/run/docker.sock:/var/run/docker.sock --rm chenzj/dfimage <IMAGE_ID>
If you find this too hard just pull the chenzj/dfimage image and then use the following docker-get-dockerfile.sh script:

#!/usr/bin/env sh

if [ "$#" -lt 1 ]
then
    printf "Image name needed\n" >&2
    exit 1
fi

image_id="$(docker images | grep "^$1 " | awk '{print $3}')"
if [ -z "$image_id" ]
then
    printf "Image not found\n" >&2
    exit 2
fi

docker run -v /var/run/docker.sock:/var/run/docker.sock --rm chenzj/dfimage "$image_id"
You need to pass image name as the parameter. Example usage:

$ ./docker-get-dockerfile.sh alpine
FROM alpine:latest
ADD file:fe64057fbb83dccb960efabbf1cd8777920ef279a7fa8dbca0a8801c651bdf7c in /
CMD ["/bin/sh"]
Share
Improve this answer
Follow
answered Sep 20, 2019 at 13:34
Arkadiusz Drabczyk's user avatar
Arkadiusz Drabczyk
11k22 gold badges2222 silver badges3636 bronze badges
8
This displays the image in question as the base image. – 
Rakesh Gupta
 Jul 10, 2020 at 18:16
2
When I did this, it showed the "FROM" as the image that I was trying to find the base of. I don't quite understand - FROM myimage - do lots of stuff - viola you have myimage?? – 
mjaggard
 Mar 30, 2021 at 15:24
I'm sure this method used to work back in 2019, something might have changed since then. – 
Arkadiusz Drabczyk
 Mar 30, 2021 at 15:28
The dfimage image doesn't work at all for me, it just hangs indefinitely – 
Speeddymon
 Apr 23, 2021 at 14:13
yeah for me as well it shows the same image is the base image... which is odd – 
xbmono
 Jul 7, 2021 at 0:12
Add a comment

-2


docker run image:tag cat /etc/*release*
Run a docker container from that image with the command above(change "image:tag" with your image name and tag). your container will print details you need to answer your question.

Share
Improve this answer
Follow
