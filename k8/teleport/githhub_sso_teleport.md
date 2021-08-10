#########################
#########################

https://goteleport.com/resources/guides/github-sso-provider-kubernetes-ssh/

#########################
#########################

Using GitHub as an SSO provider for SSH and Kubernetes with Teleport
Video Length: 8:38

Using GitHub as an SSO provider for SSH and Kubernetes
This video explains how to configure Github to be a single sign-on (SSO) provider for SSH and Kubernetes access.

Once you have completed this tutorial you will be able to:

Authenticate with GitHub users into Teleport in Web and CLI
Map teams within a GitHub organization to logins and K8s usage within Teleport, this enables role-based access control (RBAC) using Github Teams.
Configure OAuth settings with GitHub org
Configure GitHub auth connector within Teleport
Set GitHub as the default auth connector
More detailed instructions are available in the Teleport Admin Guide

Details Using GitHub as an SSO provider for SSH and Kubernetes
(transcript)

Steven: Welcome to this “How to Use Teleport” video for how to use GitHub as the single sign-on authenticator with Teleport. Teleport is a simple secure access solution that developers use to remotely manage their cloud or edge environments through SSH or Kubernetes.

Authenticate with GitHub Users into Teleport in Web and CLI
Steven: Let’s step through how we’re going to configure GitHub for single sign-on with Teleport. We’re going to be matching specific GitHub teams to SSH logins such as root users access. We’re going to be matching GitHub teams for the Kubernetes usage, whether matched to groups or users. Now, in terms of the example today, we’ll have two teams. First is the “oncall” team that has a “monitor” SSH login access and the Kubernetes “oncall” Kubernetes group. And we have another “oncalladminsteam”, that has “root” access and the Kubernetes group “system:masters”. Now, to use that, we’re going to have two users. One is the “exampleoncall” user, which’ll only be in the “oncall” team. It just has the “monitor” SSH access. Then the “exampleoncalladmin” is in both teams, and then thus has both login access for “monitor” and “root”, and also is in both the “oncall” Kubernetes group as well as the “system:masters” group after authenticating.

Map Teams Within a GitHub Organization to Logins and K8s Usage within Teleport
Steven: Our first step is going to be configuring the GitHub organization for authentication. You want to have an organization configured, that has one or more teams, with members assigned to those teams, based on the type of usage they’ll have. We recommend turning on the two-factor authentication option, to provide you added security beyond just passwords.

Configure OAuth Settings with GitHub Org
Steven: Next, we’ll be configuring the Teleport OAuth Application, which is the communication protocol used for security between Teleport and GitHub. You can see here, our GitHub organization “AcmeExample” that has two members, that’ll be part of the teams. Here, we can go to our Settings for organization. We’ll first go to Security and turn on the two-factor authentication. Two-factor authentication is not required, but we do recommend it for added security. Next, we’ll go to the OAuth setting for apps. We have to register an application. We’re going to name it “Teleport”. Next, we’ll provide the homepage URL of our Teleport instance. Next, we’ll be providing a callback URL that is used, once the authentication process is executed on GitHub. Now that we’ve completed that, we can register the application. We can see we have a Client ID and Secret. We’ll want to take note of those values, and we’ll use them in our GitHub YAML file. Next, you can see the same information we provided when we registered.

Configure GitHub Auth Connector Within Teleport
Steven: Now that the GitHub organization has been configured, we can configure within Teleport. We’ll be configuring the GitHub authentication or Auth Connector. That’ll be within a GitHub YAML file. We’ll be setting that same Client ID and Client Secret, providing the callback URL. We’ll also be setting the logins in Kubernetes, allowed for the specific GitHub teams within that organization. One tip is to make sure to use lowercase team names in the connector, not camel case. Lastly, we’ll be adding that Auth Connector to Teleport via tctl. You can also directly add it via the web as another option. Now, let’s take a look at the YAML file. You can see we’ve set the Client ID, Secret and callback URL. You can see we’ve mapped the organization and teams, the specific login and Kubernetes access.

Set GitHub as the Default Auth Connector
Steven: And now that we have our file completed, we can use the tctl command to create it, and it will confirm that it has been created. Now that we have the GitHub Auth Connector configured, we can set GitHub as the default authentication. You simply edit the Teleport YAML, to set the authentication configuration. You also want to make sure that you’re using a signed SSL certificate, so that the GitHub can communicate back to the Teleport instance. Once that is done, you’ll simply restart Teleport and GitHub is now your default authentication mechanism. So you can see what’s in the Teleport YAML file. We’re going to add an option to the Auth Service. We’re going to say, the GitHub authentication. We’re going to list the type as “github”, and that enforces GitHub as the default authentication. After saving this, just simply restart your Teleport service.

The Resulting Authentication and Action
Steven: Now that we’ve finished configuration, let’s take a look at the authentication and action. We’ll be able to see the GitHub login option shown on the web, and it’ll also be used from their command line interaction. So let’s first look at login in the web, and then login via tsh. So now, if we go to the Teleport web homepage, we can select GitHub. We enter our “exampleoncall” user and their password. We’ll also enter in the two-factor authentication, as now required. This’ll take us back to Teleport, and we have access to our cluster. We can see our four nodes, and this user has a “monitor” login they can use. So it’s like that. And now we’ve opened up an SSH session, and we can access parts of the database, as allowed for this user.

Steven: Now moving to the command line, we’re going to log in with the other user, the “exampleadminoncall” user. Enter in the username and password into GitHub. Again, enter the two-factor authentication. Verify that. We can now see our status in the command line, what logins we have access to. So let’s go open up a “root” login to the builder node. Again, we have an SSH session. We can run various commands. Now, in addition to SSH access, we also have our Kubernetes access. So let’s take a look at interacting with that. Remember, this user has the “system:masters” group access. So we can take a look at the default deployments. Can look at the pods in the default namespace. And we’re going to go ahead and delete one of these pods, which just the “system:masters group” is allowed to do. And that pod will automatically be recreated. Can see, it was just created. Let’s go ahead and open up an exec session into that pod. And now, just like an SSH session, we have access, and we can run commands.

Recap
Steven: So let’s review what we’ve done today. We’ve authenticated with GitHub users into Teleport, in web and command line interfaces. We’ve mapped teams within the GitHub organization, to logins and Kubernetes usage within Teleport. We’ve configured the OAuth settings within GitHub organization, that allows Teleport to authenticate against that organization. We’ve configured a GitHub Auth Connector within Teleport, that tells it the logins in Kubernetes mappings. We’ve set that GitHub as the default OAuth Connector for all users. And lastly, the steps that I’ve completed here are available within the Teleport Admin Guide. We thank you for joining us for this video, and we hope that you visit our site and review our latest information.
