##
##
# https://github.com/authelia/authelia/issues/206
# https://github.com/authelia/authelia/issues/2365
##
##
   

Make Authelia available on Kubernetes using ingress-nginx #206
Closed
clems4ever opened this issue Jan 17, 2018 · 14 comments
Comments
@clems4ever
Member
clems4ever commented Jan 17, 2018

It would be great to have Authelia in a Kube cluster in only few commands (only one?).
Plus, in combination with kube-lego, certificates renewal can be handled automatically by the cluster.

https://github.com/kubernetes/ingress-nginx
Chemsmith and AndreaPravato reacted with thumbs up emoji
@clems4ever clems4ever added type/enhancement
Similar to a feature but less impactful
priority/2/high
High priority items
status/in-progress
Work is in progress
labels Jan 17, 2018
@clems4ever
Member Author
clems4ever commented Jan 24, 2018

FYI, I've made it working in my cluster with kube-lego for certificate renewal. I will publish configurations to show how to set it up. Hopefully I will package it with Helmet at some point.
w9n reacted with thumbs up emoji
@clems4ever
Member Author
clems4ever commented Mar 5, 2018 •

I made it work with branch called kube. There is a README in example/kubernetes directory. Please give your feedbacks if you follow the steps, it would be greatly appreciated.
@damomurf
damomurf commented Mar 15, 2018

So I’ve got Authelia working mostly fine under Nginx-ingress in Kubernetes without this.

The only thing not working are redirects after login. What did you have to change to get that to work?

I’d rather not replace the whole Nginx-ingress template, but use annotations for config if I can.
@clems4ever
Member Author
clems4ever commented Mar 16, 2018

Hello @damomurf , this statement might be missing in the nginx template:

auth_request_set    $redirect $upstream_http_redirect;

I'm really interested in your configuration though. Which version of nginx-ingress do you use and what is an example of ingress configuration working with Authelia? Can you please share it?
@clems4ever
Member Author
clems4ever commented Mar 16, 2018

If you want to see all the changes I've done for version 0.9.0-beta.19 of the nginx controller to make it work, you can diff -u the two files in example/kube/ingress-controller/configs. It gives this:

--- nginx.tmpl	2017-11-29 02:03:17.000000000 +0100
+++ configs/nginx.tmpl	2018-03-04 12:32:14.106051659 +0100
@@ -647,8 +647,10 @@
             proxy_set_header            X-Scheme                $pass_access_scheme;
             {{ end }}
 
-            proxy_set_header            Host                    {{ $location.ExternalAuth.Host }};
-            proxy_set_header            X-Original-URL          $scheme://$http_host$request_uri;
+            proxy_set_header            Host                    $http_host;                                  
+            proxy_set_header            X-Original-URI          $request_uri;                      
+            proxy_set_header            X-Real-IP               $remote_addr;                           
+            proxy_set_header            X-Forwarded-Proto       $scheme;
             proxy_set_header            X-Original-Method       $request_method;
             proxy_set_header            X-Auth-Request-Redirect $request_uri;
             proxy_set_header            X-Sent-From             "nginx-ingress-controller";
@@ -705,6 +707,12 @@
             # this location requires authentication
             auth_request        {{ $authPath }};
             auth_request_set    $auth_cookie $upstream_http_set_cookie;
+            auth_request_set    $redirect $upstream_http_redirect;                 
+            auth_request_set    $user $upstream_http_remote_user;                  
+            proxy_set_header    X-Forwarded-User $user;                            
+            auth_request_set    $groups $upstream_http_remote_groups;              
+            proxy_set_header    Remote-Groups $groups;
+            
             add_header          Set-Cookie $auth_cookie;
             {{- range $idx, $line := buildAuthResponseHeaders $location }}
             {{ $line }}

@damomurf
damomurf commented Mar 18, 2018

@clems4ever The ingress configuration I use is as follows:

apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: authelia-ingress
  namespace: default
  annotations:
    kubernetes.io/tls-acme: "true"
    kubernetes.io/ingress.class: "nginx"
    ingress.kubernetes.io/ssl-redirect: "true"
spec:
  rules:
  - host: login.domain
    http:
      paths:
      - backend:
          serviceName: authelia-service
          servicePort: 80
        path: /
  tls:
  - hosts:
    - login.domain
    secretName: authelia-tls

Everything works fine, except after logging in with Authelia, no redirect is sent to the originally requested URL. If there's already a valid session, everything works as expected.

I'm using the following docker image:
quay.io/kubernetes-ingress-controller/nginx-ingress-controller:0.9.0-beta.19

I might try with server-snippet annotations in the ingress and see if I can get them to add the auth_request_set variables?
@damomurf
damomurf commented Mar 18, 2018

Oh, and an Ingress requiring Authelia for auth looks like:

apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: prometheus-ingress
  annotations:
    kubernetes.io/tls-acme: "true"
    ingress.kubernetes.io/ssl-redirect: "true"
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/auth-signin: https://login.domain
    nginx.ingress.kubernetes.io/auth-url: https://login.domain/api/verify
spec: 
  tls:
  - secretName: prometheus-tls
    hosts:
    - prometheus.domain
  - secretName: alertmanager-tls
    hosts:
    - alertmanager.domain
  rules:
  - host: prometheus.domain
    http:
      paths:
      - path: /
        backend:
          serviceName: prometheus
          servicePort: 9090
  - host: alertmanager.domain
    http:
      paths:
      - path: /
        backend:
          serviceName: prometheus
          servicePort: 9093

@clems4ever
Member Author
clems4ever commented Mar 19, 2018 •

@damomurf , you can indeed try to add this header with annotations if possible. It would be awesome if it works.
But there is another thing I don't think would work without modification of the template: the forwarding of username and group to the backend app because I think there is no way to specify proxy_set_header statement using annotations.

Thank you for the configurations anyway and keep me posted if you find a solution for this redirect issue. Otherwise maybe I can change a bit Authelia to use any relevant header to do the redirection. I already had a look at the full generated nginx configuration and nothing was really usable to do the correct redirection.
@damomurf
damomurf commented Mar 20, 2018

@clems4ever I'm not entirely clear on why any headers are required to make the redirect functional? The originally requested url gets passed as a parameter to the auth-signin url via the "rd" request parameter (where you see Authelias signin prompt). I would have thought Authelia would be able to remember that and send back a redirect to that URL once authentication had completed?
@clems4ever
Member Author
clems4ever commented Apr 24, 2018

@damomurf , I'm currently modifying Authelia to take the "rd" query parameter into account. I have a working version locally in which I use v0.13.0 of ingress-nginx and I don't have a custom nginx template anymore :).
I'm fixing the tests before pushing the change. I'll keep you posted.
damomurf reacted with hooray emoji
@damomurf
damomurf commented Apr 24, 2018

Awesome, thanks @clems4ever. Let me know if I can help by testing it further if you need.
@clems4ever
Member Author
clems4ever commented May 2, 2018

It's now in master! All details are in the README under example/kube and in the new wiki I've written.
damomurf reacted with thumbs up emoji
@clems4ever clems4ever closed this as completed May 2, 2018
@Fangjunyou
Fangjunyou commented Oct 25, 2021

@clems4ever How can I find example/kube directory in master branch in which I only find example/compose directory?
@clems4ever
Member Author
clems4ever commented Oct 26, 2021

@Fangjunyou , please check https://www.authelia.com/docs/deployment/deployment-kubernetes.html
to join this conversation on GitHub. Already have an account? Sign in to comment
Assignees
No one assigned
Labels
priority/2/high
High priority items
status/in-progress
Work is in progress
type/enhancement
Similar to a feature but less impactful
Projects
None yet
Milestone
No milestone
Development



##
##


Skip to content

    Pricing

Sign in
Sign up
authelia /
authelia
Public

Code
Issues 76
Pull requests 24
Discussions
Actions
Projects 6
Security 2

    Insights

Cheatsheet - aws cloud deployment #2365
Closed
johndpope opened this issue Sep 10, 2021 · 5 comments
Comments
@johndpope
johndpope commented Sep 10, 2021 •

I spent some time investigating how to deploy local docker image to cloud.
There must others that could benefit from a concise list of steps to get this working in production.

image

https://aws.amazon.com/blogs/containers/deploy-applications-on-amazon-ecs-using-docker-compose/

This ticket is first crack -

Obviously -

    AWS + Docker / ECS / ECR
    Google Artifacts + Google KGE
    Microsoft's Azure Kubernetes Service (AKS)
    Cloud Ocean

it's trivial to get these + docker integrated by creating a new context
eg.
https://docs.docker.com/cloud/ecs-integration/

There's a few more steps though
https://github.com/authelia/authelia/blob/master/examples/compose/lite/docker-compose.yml

For example - this local docker image won't cut it for cloud deployment.
Need to specify an image from ecr or google artifacts.

services:
  go:
    build:
      context: .
      dockerfile: ./go/Dockerfile

  java:

Becomes (image is located in the cloud - use ecr to upload)

services:
  go:    
      image: "1234.dkr.ecr.us-east-2.amazonaws.com/repository:tag"

There's quite a few steps here to get working / we can introduce an override file that could specifiy pre-baked cloud hosted files???
https://medium.com/it-dead-inside/making-sense-of-docker-compose-overrides-efb757460d64

Or user can provide them.

For AWS - there's going to be a series of steps needed to deploy

Install AWS CLI
setting up user / region
Creating IAM user / programmatic access
Granting permissions IAM credentials. (this is quite wide open

    Attached directly (can't exceed 10)
    AmazonEC2FullAccess
    AutoScalingFullAccess
    ElasticLoadBalancingFullAccess
    CloudWatchFullAccess
    AWSCloudMapFullAccess
    AmazonECS_FullAccess
    AmazonRoute53FullAccess
    AWS managed policy
    AWSCloudFormationFullAccess
    (create policy for ECR - grant all / give access)

creating repository to host images
https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-create.html

https://docs.docker.com/cloud/ecs-integration/

Get your AWS user credentials
aws --profile default sts get-caller-identity

LOGIN to ECR
aws ecr get-login-password --region REGION | docker login --username AWS --password-stdin ACCOUNT-ID.dkr.ecr.REGION.amazonaws.com\n

docker context create ecs myecscontext
follow steps and fill in stuff

docker images
docker tag IMAGEID IMAGETAGNAME
docker context use myecscontext
docker push IMAGETAGNAME
docker compose up

[+] Running 23/23
 ⠿ quickstart                     CreateComplete                                                                                                                                                                                         352.2s
 ⠿ DefaultNetwork                 CreateComplete                                                                                                                                                                                           5.0s
 ⠿ CloudMap                       CreateComplete                                                                                                                                                                                          47.0s
 ⠿ QuickstartNetwork              CreateComplete                                                                                                                                                                                           6.0s
 ⠿ LogGroup                       CreateComplete                                                                                                                                                                                           3.0s
 ⠿ GoTaskExecutionRole            CreateComplete                                                                                                                                                                                          15.0s
 ⠿ Cluster                        CreateComplete                                                                                                                                                                                           6.0s
 ⠿ GoTCP8000TargetGroup           CreateComplete                                                                                                                                                                                           1.0s
 ⠿ LoadBalancer                   CreateComplete                                                                                                                                                                                         153.0s
 ⠿ FrontendTCP3000TargetGroup     CreateComplete                                                                                                                                                                                           1.0s
 ⠿ FrontendTaskExecutionRole      CreateComplete                                                                                                                                                                                          15.0s
 ⠿ DefaultNetworkIngress          CreateComplete                                                                                                                                                                                           1.1s
 ⠿ Quickstart3000Ingress          CreateComplete                                                                                                                                                                                           2.0s
 ⠿ QuickstartNetworkIngress       CreateComplete                                                                                                                                                                                           0.9s
 ⠿ Quickstart8000Ingress          CreateComplete                                                                                                                                                                                           0.9s
 ⠿ GoTaskDefinition               CreateComplete                                                                                                                                                                                           3.0s
 ⠿ FrontendTaskDefinition         CreateComplete                                                                                                                                                                                           3.0s
 ⠿ GoServiceDiscoveryEntry        CreateComplete                                                                                                                                                                                           2.0s
 ⠿ FrontendServiceDiscoveryEntry  CreateComplete                                                                                                                                                                                           3.0s
 ⠿ GoTCP8000Listener              CreateComplete                                                                                                                                                                                           3.6s
 ⠿ FrontendTCP3000Listener        CreateComplete                                                                                                                                                                                           3.6s
 ⠿ FrontendService                CreateComplete                                                                                                                                                                                          83.8s
 ⠿ GoService                      CreateComplete

docker compose down
[+] Running 5/7
[+] Running 23/23            DeleteInProgress User Initiated                                                                                                                                                                             188.2s
 ⠿ quickstart                     DeleteComplete                                                                                                                                                                                         508.3s
 ⠿ QuickstartNetworkIngress       DeleteComplete                                                                                                                                                                                           1.0s
 ⠿ Quickstart3000Ingress          DeleteComplete                                                                                                                                                                                           1.0s
 ⠿ DefaultNetworkIngress          DeleteComplete                                                                                                                                                                                           1.0s
 ⠿ GoService                      DeleteComplete                                                                                                                                                                                         378.0s
 ⠿ Quickstart8000Ingress          DeleteComplete                                                                                                                                                                                           1.0s
 ⠿ DefaultNetwork                 DeleteComplete                                                                                                                                                                                           2.0s
 ⠿ GoServiceDiscoveryEntry        DeleteComplete                                                                                                                                                                                           2.0s
 ⠿ GoTCP8000Listener              DeleteComplete                                                                                                                                                                                           2.0s
 ⠿ FrontendService                DeleteComplete                                                                                                                                                                                          77.0s
 ⠿ GoTaskDefinition               DeleteComplete                                                                                                                                                                                           2.0s
 ⠿ GoTCP8000TargetGroup           DeleteComplete                                                                                                                                                                                           0.0s
 ⠿ GoTaskExecutionRole            DeleteComplete                                                                                                                                                                                           2.0s
 ⠿ QuickstartNetwork              DeleteComplete                                                                                                                                                                                           2.3s
 ⠿ FrontendTaskDefinition         DeleteComplete                                                                                                                                                                                           3.3s
 ⠿ FrontendTCP3000Listener        DeleteComplete                                                                                                                                                                                           3.3s
 ⠿ FrontendServiceDiscoveryEntry  DeleteComplete                                                                                                                                                                                           2.3s
 ⠿ Cluster                        DeleteComplete                                                                                                                                                                                           2.3s
 ⠿ CloudMap                       DeleteComplete                                                                                                                                                                                          46.0s
 ⠿ LogGroup                       DeleteComplete                                                                                                                                                                                           2.0s
 ⠿ FrontendTCP3000TargetGroup     DeleteComplete                                                                                                                                                                                           1.0s
 ⠿ LoadBalancer                   DeleteComplete                                                                                                                                                                                           1.0s
 ⠿ FrontendTaskExecutionRole      DeleteComplete

related
docker/docs#13502

Screen Shot 2021-09-11 at 11 29 48 am

Screen Shot 2021-09-11 at 11 29 37 am

view logs of docker image
Screen Shot 2021-09-11 at 11 34 21 am

get the external ip address - this will allow access to service - if you're targeting specific port - append.
cluster-service

ssh into container....????
@johndpope
Author
johndpope commented Sep 11, 2021 •

UPDATE

surprisingly - this is the only docker yaml file on github that references the x-aws-policies / sort of useful??
https://github.com/yike5460/superset/blob/0ef1033957083861afe7241bbfdf6280e4b76807/docker-compose.yml

the problem with using docker compose to deploy containers - it's missing some house keeping around getting the outputs from one machine to become inputs with another machine (though service discovery is supposed to help here).

Also need help to get the SSL configured - AWS has this out of the box this kind of thing out of the box
https://github.com/Scout24/aws-cf-verified-ssl-certificate

it's possible to dump out cloud formation from the given docker compose yaml -
docker compose convert ->
https://gist.github.com/johndpope/f36f9ae8e45335e7fa9b6ecc1dd2d191

from there - some fine tuning can be done....
@johndpope johndpope mentioned this issue Sep 11, 2021
for review - DO NOT MERGE plaid/quickstart#253
Open
@nightah
Member
nightah commented Sep 11, 2021

So I'm not really sure what all this noise is about but you don't have to deploy Authelia with a docker-compose.

There are several options available to you to deploy Authelia from baremetal, to packaged options for specific OSes or Docker/k8s via our helm chart.
@johndpope
Author
johndpope commented Sep 11, 2021

Ill take another look at bare metal option.
The docs for kubernetes needs updating.
I realize that’s been drafted in another repo.

It seems ‘docker context’ unifies kubernetes / so potentially no need for helm chart?
https://docs.docker.com/engine/context/working-with-contexts/
this allows for deploying to cloud from docker compose.
I like the simplicity of docker and was successful deploying to aws ecs today with a bit of perseverance. all this guff above maybe able to be simplified to one additional file in the docker sample
Ecs-Param.yaml

https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cmd-ecs-cli-compose-create.html
@johndpope johndpope mentioned this issue Sep 13, 2021
golang is out of date - need to run / can't build image plaid/quickstart#251
Closed
@nightah
Member
nightah commented Nov 11, 2021

I'm going to close this issue off because I believe we have documented examples which allows you to deploy to AWS (Docker, Baremetal etc).

If you have a specific question or issue you need help with please lodge a new issue.
@nightah nightah closed this as completed Nov 11, 2021
@johndpope
Author
johndpope commented Nov 11, 2021

found this - https://www.authelia.com/docs/deployment/deployment-ha.html


##
##
##

