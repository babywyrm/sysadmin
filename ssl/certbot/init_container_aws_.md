Certbot as an init container for AWS ECS
by Konstantin Troshin | 26. July 2022 |

#
##
##

https://content.fme.de/en/blog/certbot-init-container-aws-ecs

##
##
#

Share
 

Encryption in transit has become a security standard for most network-based applications and is requested by the majority of our customers for all applications we help them to build or manage. Most of the modern applications support TLS out of the box but require the certificate and the corresponding private key to be provided externally. In some cases (for example, for intranet apps), self-signed certificates (or certificates signed by an internal CA) are sufficient, but if the application is internet-facing and needs to be used without additional steps on the client side, a certificate signed by a commonly trusted certificate authority (CA) is required. For AWS-based applications (as you may have guessed from the title, AWS are a main focus of this post), AWS Certificate Manager (ACM) can be used in combination with a load balancer to provide an amazon-signed certificate. This simple and efficient method is not applicable, however, if the certificate and the corresponding private key need to be provided to the application directly instead of an AWS-managed load balancer. This can be the case if the application is using TLS in combination with its own protocol which would make TLS termination on the load balancer impossible. Let’s Encrypt is an open CA that provides trusted certificates which can be acquired by using a tool that supports the ACME protocol. In this case, the certificate and private key can then be provided to the application directly and used also for custom TLS-based protocols. Certbot is one of such tools and can be used to obtain the TLS credentials.

 



The use case
Recently, I have been asked to provide a publically accessible Neo4j database to use for development purposes. Since a Neo4j installation is available as a docker container, I chose to use AWS ECS to run it (a Kubernetes-based solution such as EKS would be quite an overkill for such a simple use case). To start things up, I deployed a Network Load Balancer (NLB) with three listeners and the corresponding target groups for ports 7474 (HTTP), 7473 (HTTPS), and 7687 (bolt). To improve security of the database, I decided to activate TLS for the bolt and HTTPS endpoints. Neo4j provides support for both out of the box, but requires the certificates to be provided externally. My initial approach was to use TLS listeners in combination with an Amazon-signed ACM certificate and TLS target groups to talk to the Neo4j container. I used openssl to create a self-signed certificate and provided it via an ECS mount point to Neo4j. This worked just fine for the HTTPS endpoint but did not for bolt which is, however, crucial for the Neo4j clients. It has become clear that TLS termination would not work for this use case and that I needed to use TCP listeners and target groups and to provide the publically facing certificate directly to Neo4j. Since the request of the customer included a wish that the database can be easily accessed by the clients without much configuration on their side, I also wanted this certificate to be publically trusted. In many of our k8s-based projects, we use cert-manager which can directly obtain Let’s Encrypt (LE) certificates, which brought me to the idea of using LE for my current task. Thinking about k8s and init containers, I also remembered reading some stuff about container dependencies in ECS, so I came to an idea of using a certbot docker container as such an “init container” for my Neo4j database. The schematic architecture is depicted below and includes an EC2 ECS host on which three containers should run: first the certbot container is started that can request the certificate for the corresponding domain. Once the certificate and the private key are there, the certbot container exits successfully upon which the second container (copier) is started. This container just needs a shell (I decided to use debian:latest for this purpose) and its purpose is to copy the certificate and the private key into the folders and under the file names Neo4j expects. Upon the successful exit of this container, the Neo4j container is finally started.
 
 

 
 
To achieve the correct order of the containers, AWS ECS supports the dependsOn attribute – a list of ContainerDependency objects that in turn consist of containerName and condition. The condition attribute allows to specify whether the previous container should have started (START), exited (COMPLETE), ran successfully (SUCCESS) or is passing docker health checks (HEALTHY). In the present use case, SUCCESS is the correct condition, since both certificate retrieval and copy are crucial for the Neo4j container to work properly (the copier container is called debian here):
 
 

 
 
A small challenge for the architecture above is to ensure that certbot can solve the HTTP challenge of Let’s encrypt which is a part of the ACME protocol (this is needed to verify that the domain for which the certificate is requested is indeed controlled by us). The problem here is that if targets of type instance are used with the load balancer (which makes sense for an ECS EC2 host), health checks are mandatory. On the other hand, since certbot is running only for a short time, it itself cannot be used for health checks on port 80. Also, LE expects the domain to be already routable to certbot requesting the certificate which means that a typical registration delay that load balancers have is not acceptable in this case. As a result, the instance should be registered at the corresponding target group of the NLB and already healthy before the certbot container is even started. To address this issue, I decided to use a simple trick based on a small handshaker app. This app provides a golang-based http server listening on a specified port that simply replies “OK” to any request and can be deployed as a scratch-based docker container (or a binary). Since the app cannot block the port 80 (which is required by certbot once it is ready to accept the HTTP challenge), I configured the corresponding target group (TG80) to forward to port 80 but health check on another port (6666) which I then assigned to handshaker. To ensure the correct timing, I included starting the app into the user data script of the ECS EC2 instance and made terraform (with which the whole infrastructure is built) to register the auto scaling group that deploys these instances at TG80.
 
certbot-listing2-1
 
 
As expected, shortly after terraform apply, the instance was registered at TG80 and became healthy. After this, I used aws cli to scale the ECS service to 1 task (I usually initially deploy the ECS services with the task count of 0, so that the whole infrastructure such as load balancers, instances, Route53 entries, etc. is available before the containers are even started).
To my delight, certbot successfully requested the certificate, passed the HTTP challenge and stored the results in a shared folder mounted via a mount point. After this, the following script ran in the copier container followed by the successful start of Neo4j.

 

 
Alternatives
Of course, the described approach is not the only way to get a certificate from LE and provide it to a Neo4j container (or another application). Some of the simple alternatives I can immediately think of would be:

 Run certbot directly on the EC2 host instead of a container
Use k8s/k3s/k0s in combination with cert-manager
Build a custom container that has certbot inside of it
That being said, I think that the init container approach shows a way of using ECS similar to k8s pods and can be successfully applied to other ECS-based solutions. Also, it allows to use the upstream containers which makes upgrades seamless as opposed to the “one custom container” approach. In case you wonder, how the hell I could run a custom bash script within an upstream debian container – I just used a mount point to mount a folder from the host that has been created and filled by the user data script during the EC2 deployment.


 
Scaling
In the current example, I used an auto scaling group with just one instance in it, which allows all the mount points to be folders on this instance. Of course, the local folder solution would not scale well. In this case, however, EFS can be used instead, so that the certificate and the key would be requested just once by one of the certbots (certbot exits automatically if a valid certificate is already present), but can then be used by all of the corresponding Neo4j containers. All other services used in the infrastructure above (NLB, NAT Gateway, ECS) support horizontal scaling, so that a solution based on this approach can be scaled out with ease.
 
Conclusions
In conclusion, AWS ECS provides a nice option to include k8s-like “init containers” by using container dependencies and non-essential containers. Those can be employed for a variety of purposes including generation of TLS certificates with a certbot container. The TLS credentials can be then immediately provided to an application running in the essential container on the same host resulting in a publically trusted secured app.
GET IN TOUCH WITH ME TO LEARN MORE
