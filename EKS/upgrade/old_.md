
##
#
https://www.reddit.com/r/kubernetes/comments/zd1psr/upgrading_eks_from_k8s_version_121_to_124/
#
##

Upgrading EKS from k8s version 1.21 to 1.24
We got an email from aws last weekend mentioning that 1.21 will be deprecated by February. I don't have much support on this so will be doing most of this alone (it's a startup so I'm the only devops person here).

I have been reading the aws documentation on how to upgrade to the new version but would also like to know what are the things to lookout for when upgrading.

Currently I'm thinking of creating a new eks cluster with the new version and with the new instances(arm based graviton instances instead our x64 instances that we are hosting currently) and slowly move all our stuff there over the next month, which seems a bit easier than upgrading as I can easily rollback if something goes wrong. How does one go about this change? Are there any tools that can help with the migration?

P.S, the cluster setup was done by another senior person who had moved to another company before I joined in March of this year. I'm new to devops as well and this is the first biggest task I am going to undertake.

Archived post. New comments cannot be posted and votes cannot be cast.

Upvote
9

Downvote
21
comments

Share
Share
Sort by:

Best
Log in to sort by top, controversial, or new
21 comments
[deleted]
[deleted]
•
8 mo. ago
I wouldn’t recommend doing that. You’d be jumping a fair number of versions and also switching the CPU architecture. I would break this problem into smaller pieces that are safer to work with.

Run Pluto against the old cluster to check for outdated APIs in your namespaces: https://github.com/FairwindsOps/pluto

check all of your third-party dependencies and make sure the versions you are on support 1.22

run through the AWS upgrade path for 1.22

Once you are through that you’ll have a really good familiarity with this cluster and what’s in there. My opinion is always to not force yourself to do an upgrade under the gun.

After that you can either upgrade it again up to 1.24 or whatever and swap out the nodes. You’ll have a much less stressful time with an upgraded cluster with minimal changes that you can attach a new node pool to and simply check it from there.



Upvote
20

Downvote

Reply
reply

Share
Share

u/karthikjusme avatar
karthikjusme
•
8 mo. ago
I understand. The only problem is, we have only one prod cluster that hosts all our production applications. And I cannot revert back in case of any issue in the upgrade process. That's the reason I wanted to move to a new cluster. I can create the same cluster on x64 architecture with 1.22 and maybe proceed from there. That seems a bit less risky.

Thank you for the pluto app suggestion. That would greatly help in finding out the outdated api's.

Is there a way to find all installed third party dependencies? Besides a handful of familiar api's, i am not sure which ones are installed.


Upvote
1

Downvote

Reply
reply

Share
Share


4 more replies
u/DPRegular avatar
DPRegular
•
8 mo. ago
This is not going to help you immediately, but you should bring this up with management. Not having the required expertise (people) to stay on top of ecosystem developments (eks upgrades) is a big risk to business continuity.


Upvote
8

Downvote

Reply
reply

Share
Share

u/MisterItcher avatar
MisterItcher
•
8 mo. ago
It would be way easier for you to deploy a completely new cluster at 1.24 and attempt to deploy all the manifests there one at a time, then cut over DNS.

Or, upgrade your non-prod stack one version at a time, fix deprecations as you go, promote those changes to prod, then upgrade your old cluster.



Upvote
5

Downvote

Reply
reply

Share
Share

u/karthikjusme avatar
karthikjusme
•
8 mo. ago
This is what I am planning as well. Create a new cluster ground up and know what are the things that are getting in there so that it'll be easier for me to proceed with the next set of upgrades if it's ever needed and also document it all. Current cluster was created by a very experienced person regarding which I have a good idea of what's in there but there are still some holes in that knowledge.

I am still planning, would probably make a checklist by the end of this week and start working on it soon later. Looking at all possibilities before diving in.


Upvote
1

Downvote

Reply
reply

Share
Share

pinpinbo
•
8 mo. ago
If you have little support, create a new 1.24 cluster and tell everyone to deploy there.

Find docs that shows changes in Kubernetes resources and give it to your developers.

Scare management into supporting you by saying the old cluster is end of life without security patches.


Upvote
2

Downvote

Reply
reply

Share
Share

u/karthikjusme avatar
karthikjusme
•
6 mo. ago
I decided to create a new cluster(1.24 directly) from scratch to understand everything that goes into the cluster and moved all our apps there so that it will be easier in the future to manage the cluster.

We were using kubernetes deployment files to deploy previously, moved everything to helm as part of the migration and also managed to fix several issues that I had with the previous cluster.

There was some downtime(20 mins during peak time due to my fuckup in the load balancer configuration), besides that there no major downtimes that affected our business as most of the movement was done at night.

This whole ordeal was complete within 2 weeks. Working on some Post migration things as of now.


Upvote
1

Downvote

Reply
reply

Share
Share

u/stozinho avatar
stozinho
•
8 mo. ago
Can you share any more information on deprecation of EKS 1.21 in February? I've searched but can't find an official AWS page on this. Thanks

Found it https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html#kubernetes-release-calendar



Upvote
1

Downvote

Reply
reply

Share
Share

u/karthikjusme avatar
karthikjusme
•
8 mo. ago
1.21 to 1.22 looks like a big change as there are removing many v1beta1 api versions.


Upvote
4

Downvote

Reply
reply

Share
Share


2 more replies
u/Mountain_Ad_1548 avatar
Mountain_Ad_1548
•
8 mo. ago
Interesting ideas here in this post


Upvote
1

Downvote

Reply
reply

Share
Share

Twizzleness
•
8 mo. ago
You should look into gitops in the future. I personally like flux but argocd is also fairly popular. The idea is that the git repo represents the desired state of the cluster. This allows you to account for all the third party things that might be installed.

When we did the 1.22 upgrade, we spun a new cluster, pointed the git repo at it and worked through the different things that were broken. This gave us a super easy rollback as well as ensured everything was installed correctly.

I know this doesn't help with the current issue but might help with some pain down the road.



Upvote
1

Downvote

Reply
reply

Share
Share

u/karthikjusme avatar
karthikjusme
•
8 mo. ago
I have already suggested moving to gitops and argocd to my boss and we are considering it, with my current schedule I don' t have time for a poc as of now. Yeah, it will come up down the road for me, maybe after a year. Currently just focusing on this upgrade and nothing else.


Upvote
1

Downvote

Reply
reply

Share
Share

u/R2ID6I avatar
R2ID6I
•
8 mo. ago
I upgraded our clusters to 1.24 on eks yesterday actually! It went pretty smoothly, my approach was to first upgrade docker desktop, run our manifests there, caught all the deprecated apis and made sure everything was working locally.

Then I moved on to our dev environment and did one incremental change at a time (don’t forget the eks addons!!). After each step I would do the same for staging and then prod.

There is also an additional addon that is needed from 1.23 for storage in aws (CSI something) that needed to be installed, this caused some downtime in dev env but was a easy fix.

Protip it to let each minor update sit for an hour or so to let the errors show them self, not all errors are apparent straight away



Upvote
1

Downvote

Reply
reply

Share
Share

u/karthikjusme avatar
karthikjusme
•
8 mo. ago
I am building a staging cluster as we speak. How do you transfer the manifests easily? I want to create a replica of some sort that we will continue to use but moving 50+ applications and additional services will be very time consuming.

How are you doing it?
