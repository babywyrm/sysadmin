

##
#
https://stackoverflow.com/questions/43331418/aws-cli-ecr-list-images-get-newest
#
##


```
ws ecr describe-images --repository-name foo \
--query 'sort_by(imageDetails,& imagePushedAt)[*]'
```



Using AWS CLI, and jq if needed, I'm trying to get the tag of the newest image in a particular repo.

Let's call the repo foo, and say the latest image is tagged bar. What query do I use to return bar?

I got as far as

aws ecr list-images --repository-name foo
and then realized that the list-images documentation gives no reference to the date as a queryable field. Sticking the above in a terminal gives me keypairs with just the tag and digest, no date.

Is there still some way to get the "latest" image? Can I assume it'll always be the first, or the last in the returned output?

amazon-web-servicesamazon-ec2aws-cli
Share
Improve this question
Follow
edited Apr 11, 2017 at 10:16
Arafat Nalkhande's user avatar
Arafat Nalkhande
10.6k88 gold badges4040 silver badges6161 bronze badges
asked Apr 10, 2017 at 19:24
Alex's user avatar
Alex
2,31555 gold badges2626 silver badges4747 bronze badges
Add a comment
7 Answers
Sorted by:

Highest score (default)

63


You can use describe-images instead.

aws ecr describe-images --repository-name foo 
returns imagePushedAt which is a timestamp property which you can use to filter.

I dont have examples in my account to test with but something like following should work

aws ecr describe-images --repository-name foo \
--query 'sort_by(imageDetails,& imagePushedAt)[*]'
If you want another flavor of using sort method, you can review this post

Share
Improve this answer
Follow
edited May 23, 2017 at 11:54
Community's user avatar
CommunityBot
111 silver badge
answered Apr 10, 2017 at 20:08
Frederic Henri's user avatar
Frederic Henri
50k99 gold badges110110 silver badges135135 bronze badges
1
Thank you! Worth noting this works only on awscli 1.11+. – 
NabLa
 Jun 8, 2017 at 15:05
16
this one worked for me: aws ecr describe-images --output json --repository-name $DOCKER_IMAGE_NAME --query 'sort_by(imageDetails,& imagePushedAt)[-1].imageTags[0]' | jq . --raw-output. Without jq few repos were showing 2 images. – 
Varun Chandak
 Aug 12, 2018 at 7:49
not sure why but I am getting multiple image versions. Im using | tr '\t' '\n' | head to get the first version – 
prayagupa
 Aug 19, 2020 at 0:14
In my case this returned multiple versions, but that was because the image got tagged many times, when our builds resulted in the same image. – 
ZeeCoder
 Sep 1, 2020 at 13:46
1
This sorts ascending, giving the newest first. You can fix that by adding reverse(sort_by(... BUT, it still only sorts the first page of output when there's a long paginated list. So it doesn't work if you have a lot of entries. – 
Leopd
 Nov 13, 2021 at 0:28 
Show 1 more comment

Report this ad

29


To add to Frederic's answer, if you want the latest, you can use [-1]:

aws ecr describe-images --repository-name foo \
--query 'sort_by(imageDetails,& imagePushedAt)[-1].imageTags[0]'
Assuming you are using a singular tag on your images... otherwise you might need to use imageTags[*] and do a little more work to grab the tag you want.

Share
Improve this answer
Follow
answered Mar 21, 2018 at 17:58
Brett Green's user avatar
Brett Green
3,38611 gold badge2020 silver badges2929 bronze badges
aws ecr describe-images --repository-name gnk-stage-ar --query 'sort_by(imageDetails,& imagePushedAt)[-1].imageTags[0]' 1550 1553 latest 1558 1547 1511 new-13 1541 1545 1561 1563 1557 1534 1539 1562 1554 Its not printing the latest image number. but same command is working in ubuntu not in centos – 
GNK
 Dec 24, 2021 at 12:49 
1
Add --no-paginate if you have a lot of tags. – 
ixe013
 Jan 20 at 22:48
Add a comment

5


To get only latest image with out special character minor addition required for above answer.

aws ecr describe-images --repository-name foo --query 'sort_by(imageDetails,& imagePushedAt)[-1].imageTags[0]' --output text


Share
Improve this answer
Follow
edited Oct 15, 2018 at 7:08
answered Oct 15, 2018 at 7:03
Vinay Gowda's user avatar
Vinay Gowda
5111 silver badge22 bronze badges
Add a comment

Report this ad

5


List latest 3 images pushed to ECR

aws ecr describe-images --repository-name gvh \
--query 'sort_by(imageDetails,& imagePushedAt)[*].imageTags[0]' --output yaml \
| tail -n 3 | awk -F'- ' '{print $2}'
List first 3 images pushed to ECR

aws ecr describe-images --repository-name gvh \
--query 'sort_by(imageDetails,& imagePushedAt)[*].imageTags[0]' --output yaml \
| head -n 3 | awk -F'- ' '{print $2}'
Number '3' can be generalized in either head or tail command based on user requirement

Share
Improve this answer
Follow
edited May 22, 2021 at 16:38
answered Sep 28, 2020 at 22:37
Harsha G V's user avatar
Harsha G V
40711 gold badge55 silver badges1515 bronze badges
Add a comment

2


Without having to sort the results, you can filter them specifying the imageTag=latest on image-ids, like so:

aws ecr describe-images --repository-name foo --image-ids imageTag=latest --output text
This will return only one result with the newest image, which is the one tagged as latest

Share
Improve this answer
Follow
edited Mar 2, 2020 at 16:31
answered Mar 2, 2020 at 15:06
mjlescano's user avatar
mjlescano
83799 silver badges1313 bronze badges
Add a comment

2


Some of the provided solutions will fail because:

There is no image tagged with 'latest'.
There are multiple tags available, eg. [1.0.0, 1.0.9, 1.0.11]. With a sort_by this will return 1.0.9. Which is not the latest.
Because of this it's better to check for the image digest.

You can do so with this simple bash script:
```
#!/bin/bash -
#===============================================================================
#
#          FILE: get-latest-image-per-ecr-repo.sh
#
#         USAGE: ./get-latest-image-per-ecr-repo.sh aws-account-id
#
#       AUTHOR: Enri Peters (EP)
#       CREATED: 04/07/2022 12:59:15
#=======================================================================

set -o nounset       # Treat unset variables as an error

for repo in \
        $(aws ecr describe-repositories |\
        jq -r '.repositories[].repositoryArn' |\
        sort -u |\
        awk -F ":" '{print $6}' |\
        sed 's/repository\///')
do
        echo "$1.dkr.ecr.eu-west-1.amazonaws.com/${repo}@$(aws ecr describe-images\
        --repository-name ${repo}\
        --query 'sort_by(imageDetails,& imagePushedAt)[-1].imageDigest' |\
        tr -d '"')"
done > latest-image-per-ecr-repo-${1}.list
```
The output will be written to a file named latest-image-per-ecr-repo-awsaccountid.list.

An example of this output could be:

123456789123.dkr.ecr.eu-west-1.amazonaws.com/your-ecr-repository-name@sha256:fb839e843b5ea1081f4bdc5e2d493bee8cf8700458ffacc67c9a1e2130a6772a
...
...
With this you can do something like below to pull all the images to your machine.

#!/bin/bash -

for image in $(cat latest-image-per-ecr-repo-353131512553.list)
do
    docker pull $image
done
You will see that when you run docker images that none of the images are tagged. But you can 'fix' this by running these commands:

docker images --format "docker image tag {{.ID}} {{.Repository}}:latest" > tag-images.sh

chmod +x tag-images.sh

./tag-images.sh

Then they will all be tagged with latest on your machine.

Share
Improve this answer
Follow
edited Apr 11 at 12:20
answered Apr 7 at 15:09
Enri Peters's user avatar
Enri Peters
2133 bronze badges
Add a comment

1


To get the latest image tag use:-

aws ecr describe-images --repository-name foo --query 'imageDetails[*].imageTags[ * ]' --output text | sort -r | head -n 1
