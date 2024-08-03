Run your own OAuth2 Server

##
#
https://www.ory.sh/run-oauth2-server-open-source-api-security/
#
##

Photo of Aeneas Rekkas
Aeneas Rekkas
Founder, CTO
March 12, 2024
In this guide, you will set up a hardened OpenID Certified™ OAuth2 Server and OpenID Connect Provider (OIDC / OP) using open-source technology Ory Hydra on the Ory Network.

This five-minute guide is for you if

you want to use OAuth2 for API security; or
you want to open up your API to third-party developers like GitHub; or
you want to become an identity provider like Google, Facebook, or Twitter; or
you need to federate (delegate) authentication or authorization.
What is OAuth2 and OpenID Connect again?
The easiest way to explain OAuth2 and OpenID Connect is with an example. CircleCI is a service that integrates with GitHub similar to GitHub Actions. When you connect CircleCI to GitHub, CircleCI asks you (the user) to grant read/write permissions to GitHub repositories. Here, CircleCI is the OAuth2 client. The user performs an OAuth2 Flow to grant CircleCI access to repositories on GitHub. GitHub will ask you what repositories you want to grant access to and if it is ok to grant other data (access to your email address, profile picture, ...) CircleCI has requested:

CircleCI uses OAuth2 to access GitHub repositories.

In this case, GitHub is the OAuth2 server. Ory OAuth2 & OpenID Connect (Ory Hydra) enables you to be the same! When executing a similar OAuth2 flow with Ory, you get a similar user experience:

A typical OAuth2 flow when using Ory.

For a more technical and in-depth overview of the protocols and related terminologies - such as OAuth2 Server, OAuth2 Client, OpenID Connect Provider - head over to these excellent articles:

DigitalOcean: An Introduction to OAuth 2
Aaron Parecki: OAuth2 Simplified
Ory Hydra: A OAuth2 and OpenID Connect Provider written in Golang
Ory Hydra is an OAuth2 Server and OpenID Certified™ OpenID Connect Provider written in Go. It powers the Ory OAuth2 & OpenID APIs on the Ory Network.

Compared to other OAuth2 and OpenID Connect Providers it does not implement its own user database and management (for user login, user registration, password reset, 2fa, ...), but uses the Login and Consent Flow to delegate rendering the Login UI ("Please enter your email and password") and Consent UI ("Should application MyDropboxDownload be allowed to access all your private Dropbox Documents?") to an external application.

When using Ory Hydra on the Ory Network, it automatically integrates with Ory Identities, meaning that you do not need to implement your own Login and Consent UIs.

Ory Hydra can be integrated with any identity service (your own thing, IdentityServer, Azure AD, ...) and you have full control over the OAuth2 user consent flow as well! An example application for an OAuth2 Login and Consent app is available at github.com/ory/hydra-login-consent-node.

Ory releases hundreds of open-source projects under the Apache 2.0 license. The services we use in this tutorial are available on GitHub:

Ory Hydra GitHub Card

Ory Kratos GitHub Card

Perform OAuth2 & OpenID Connect flows
Now that the introduction is out of the way, let's get started! To make this guide as easy to reproduce as possible, we will use the Ory Command Line Interface (Ory CLI) to run Ory Hydra on the Ory Network.

For advanced users and hackers there is a second guide in this article explaining how to run Ory Hydra on your local machine using Docker.

To manage Ory resources and configuration we install the Ory CLI.

macOS
Install the Ory CLI on macOS using Homebrew:

# Or with Homebrew installed
brew install ory/tap/cli
Linux
Install the Ory CLI on Linuxoid systems using curl and bash:

bash <(curl https://raw.githubusercontent.com/ory/meta/master/install.sh) -b . ory
sudo mv ./ory /usr/local/bin/
Windows
To install the CLI on Windows, use scoop. Run:

scoop bucket add ory https://github.com/ory/scoop.git
scoop install ory
Create Ory Network project
Once the Ory CLI is installed and working, create a new Ory Network project. The CLI might ask you to sign in or create a free account

ory create project \
  --name "Ory Hydra 2.0 Example"
and responds with project metadata

Project created successfully!
ID    170de7c2-eef8-4405-b884-b0e9692eefb3
SLUG  elastic-goldstine-1n7d31aph0
STATE running
NAME  Ory Hydra 2.0 Example
which we use to set the environment variable project_id:

project_id="{set to the id from output}"
# Example:
# project_id="170de7c2-eef8-4405-b884-b0e9692eefb3"
That's all you need, your OAuth2 and OpenID Connect server is now available on the Ory Network at:

https://<slug>.projects.oryapis.com/.well-known/openid-configuration
# Example:
#
# https://elastic-goldstine-1n7d31aph0.projects.oryapis.com/.well-known/openid-configuration
OAuth2 Client Credentials Grant & Machine-to-Machine
The easiest OAuth2 flow to try out is the Client Credentials Flow. To perform the flow we

create an OAuth 2.0 Client;
perform the OAuth 2.0 Client Credentials Flow;
Receive an OAuth 2.0 Access Token.
Validate the OAuth 2.0 Access Token.
The OAuth2 Client Credentials grant is often used for machine-to-machine authentication.

Create OAuth2 Client for Client Credentials Flow
Let's create an OAuth2 client capable of performing the OAuth2 client credentials grant:

ory create oauth2-client --project $project_id \
    --name "Client Credentials Demo" \
    --grant-type client_credentials
Flag --grant-type client_credentials allows the OAuth 2.0 Client to perform the OAuth 2.0 Client Credentials grant. The CLI will respond with something similar to:

CLIENT ID       a9dff982-bbf0-44d4-9c96-a9ed54fa9bee
CLIENT SECRET   bDZcNyaeh7otTb-JBOC67Scdgz
GRANT TYPES     client_credentials
RESPONSE TYPES  code
SCOPE           offline_access offline openid
AUDIENCE
REDIRECT URIS
Next we copy and paste the OAuth2 Client ID and Secret into the environment variables:

client_id="{set to client id from output}"
client_secret="{set to client secret from output}"
# Example:
# client_id="a9dff982-bbf0-44d4-9c96-a9ed54fa9bee"
# client_secret="bDZcNyaeh7otTb-JBOC67Scdgz"
Perform OAuth2 Client Credentials Flow
Let's exchange the OAuth2 Client ID and Client Secret

ory perform client-credentials --project $project_id \
  --client-id=$client_id \
  --client-secret=$client_secret
to receive an OAuth2 Access Token

ACCESS TOKEN    ory_at_gTj6pxe_5SVTiTVrz-cEjxEaGFeWi2pb3TFiK8oLDnQ.3ZADwoHpJcPT-QE9ZwMawpiBM7XhaGCTEmgWh-Hl_6I
REFRESH TOKEN   <empty>
ID TOKEN        <empty>
EXPIRY          2022-10-28 12:44:54 +0200 CEST
and finally set it as environment variable access_token:

access_token="{set to access token from output}"
# Example:
# access_token="ory_at_gTj6pxe_5SVTiTVrz-cEjxEaGFeWi2pb3TFiK8oLDnQ.3ZADwoHpJcPT-QE9ZwMawpiBM7XhaGCTEmgWh-Hl_6I"
Introspect and validate OAuth2 Access Token
Validate OAuth2 access tokens using OAuth2 Token Introspection. The Ory CLI offers a simple command to perform the API call

ory introspect token --project $project_id \
  $access_token
which responds with OAuth2 Access Token metadata:

ACTIVE  true
SUBJECT   a9dff982-bbf0-44d4-9c96-a9ed54fa9bee
CLIENT ID  a9dff982-bbf0-44d4-9c96-a9ed54fa9bee
SCOPE
EXPIRY  2022-10-28 12:44:54 +0200 CEST
TOKEN USE  access_token
Ory OAuth2 & OpenID (and Ory Hydra) issues opaque Access Tokens to greatly reduce attack vectors per default but also supports Access Tokens formatted as JSON Web Tokens (JWT). The payload and expiry of all OAuth2 and OpenID Connect tokens is adjustable. For more information on this head over to the developer documentation.

By the way, you can also format the output in the Ory CLI in a variety of formats, for example human-readable JSON
```
ory introspect token --project $project_id \
  --format json-pretty \
  $access_token
resulting in output:

{
  "active": true,
  "client_id": "a9dff982-bbf0-44d4-9c96-a9ed54fa9bee",
  "exp": 1666953894,
  "iat": 1666950294,
  "iss": "https://elastic-goldstine-1n7d31aph0.projects.oryapis.com",
  "nbf": 1666950294,
  "sub": "a9dff982-bbf0-44d4-9c96-a9ed54fa9bee",
  "token_type": "Bearer",
  "token_use": "access_token"
}
```

Perform OAuth2 Authorization Code Flow and OpenID Connect
The OAuth2 Authorization Code Grant is the most common OAuth2 grant. It is used to authenticate users and authorize access to resources. The Ory CLI has a demo command to help you perform your first OAuth2 Authorization Code Grant using Ory. In a real-world application, this OAuth2 flow is not initiated by the Ory CLI but instead with code in an app.

Create OAuth2 Client for Authorization Code Flow
Similar to the OAuth2 Client Credentials flow, we create an OAuth2 client capable of performing the OAuth2 authorization code flow
```
ory create oauth2-client --project $project_id \
  --name "Authorize Code with OpenID Connect Demo" \
  --grant-type authorization_code,refresh_token \
  --response-type code \
  --redirect-uri http://127.0.0.1:4446/callback
```
resulting in output:
```
CLIENT ID       d2e066cd-060d-44c9-92c1-1e73cbd6016e
CLIENT SECRET   kMARNy2ZMv-ZoNsufkzDfZgK.C
GRANT TYPES      authorization_code, refresh_token
RESPONSE TYPES code
SCOPE           offline_access offline openid
AUDIENCE
REDIRECT URIS   http://127.0.0.1:4446/callback
Set its OAuth2 Client ID and Client Secret as environment variables:

code_client_id="{set to client id from output}"
code_client_secret="{set to client secret from output}"
# Example:
# code_client_id="d2e066cd-060d-44c9-92c1-1e73cbd6016e"
# code_client_secret="kMARNy2ZMv-ZoNsufkzDfZgK.C"
Perform OAuth2 Authorization Code Flow
Everything is set up! Let's perform the OAuth2 Authorization Code Flow. We use the Ory CLI which sets up a demo webserver on your local machine with an OAuth2 callback endpoint and a link that starts the OAuth2 flow:

ory perform authorization-code \
  --project $project_id \
  --client-id $code_client_id \
  --client-secret $code_client_secret
```


If the browser does not open the URL, navigate to http://127.0.0.1:4446/ yourself, hit Sign Up and create a new user. Once signed up, accept all the permissions in the consent screen and hit "Allow":

OAuth2 Authorization Consent UI

Ory OAuth2 & OpenID APIs (and Ory Hydra) are not an Identity Management solution. Instead, they require an existing Identity Management system.

OAuth2 providers such as Keycloak, OpenAM, or IdentityServer are usually full-stack enterprise identity and access management solutions. They come with complex deployment dependencies, technologies not particularly suited for cloud-native environments, and subtle, but annoying limitations at scale. Ory solves OAuth2 and OpenID Connect as a dedicated service, allowing it to be integrated with any application stack.

To authenticate users, Ory Hydra defines the OAuth2 Login & Consent APIs. A demo OAuth2 Login & Consent app is available at GitHub. On the Ory Network the OAuth2 Login and Consent flow is implemented already using Ory Identities and the Ory Account experience.

For a short explanation of the different stages of the flow check out the following video which uses the demo OAuth2 Login & Consent app:


Once you click "allow", the Ory CLI will now show you the access token, refresh token and ID token:

ACCESS TOKEN ory_at_GVG1AhpykEgTHBvsgzT4T4u7Xz6VzCw9zDZllX4y_94.Szlmx_66Sj51---BrjL8muA-8tUeSf43G8zfalQgiSQ
REFRESH TOKEN  ory_rt_jz1982pL7-glrOd1_PeTyNTWGyacBF3WlELqVi0btiQ.7G9gj_HS_JHaI8NwaZXimTpWJYXGowiz8gg-_B2Aq7E
ID TOKEN     eyJhbGciOiJSUzI1NiIsImtpZCI6IjkyMzVmNTMzLWY4YWItNDc2Yi04N2I4LWRhZTNhZTZlYTQ4YyIsInR5cCI6IkpXVCJ9.eyJhbXIiOlsicGFzc3dvcmQiXSwiYXRfaGFzaCI6ImdueWFUNVVHV0FxVU9RbUdfeVBFUHciLCJhdWQiOlsiZDJlMDY2Y2QtMDYwZC00NGM5LTkyYzEtMWU3M2NiZDYwMTZlIl0sImF1dGhfdGltZSI6MTY2Njk1MjQzNSwiZXhwIjoxNjY2OTU2MDM4LCJpYXQiOjE2NjY5NTI0MzgsImlzcyI6Imh0dHBzOi8vZWxhc3RpYy1nb2xkc3RpbmUtMW43ZDMxYXBoMC5wcm9qZWN0cy5vcnlhcGlzLmNvbSIsImp0aSI6ImY2M2Y0MDAxLWVkYTUtNDY1NC1hMGJmLWE0MWMzZjZkYzgwNCIsIm5vbmNlIjoic3pvb3JlbmxkeXZxZGpqYnV5c3ZwbGdyIiwicmF0IjoxNjY2OTUyNDI4LCJzaWQiOiI1NTgyNTkyYy1kMDU1LTQ4M2MtODIyNi02MzkzY2M5MjQzYmIiLCJzdWIiOiI4ZjYyN2UzMi04ZGE4LTQwMTMtOTg0ZC0zODUxOTZiNmVkOWQifQ.CdJAqDHuADBDRqeXpuHf-0Ud9ReUN0LhMMycQnEknKzUOimB0_J-jF-G1feNaJ6Uckg7jZKmi31mpaZv-SL9JSMBUG-9Mkwu7L3Lj5ehWoDYG2uik9GYMaCek0aMpeLp1lRcCCDRgmO963HaRO-CYtR6F2ADSZfxXTOZFOxVrwEMSs9GLxOTpmG_DhDLkOKgQm5iN8kLKGatme5hY8kC4RtgYAvbbQMxhtLqiAFM7mG6PwTvOF32G4kFVL5jkBFbICYfUxcdXDVd8LBgRXKFvvtGBiUBNhsZYvOLlDPrPI9zYJRWcTiOy6qlAtzFXAN9kqOeSQAc9kzwba0cOszcBkt1FbjcdHVZbAqkTBOvZmIsSPjMzGGj0jAy2DYa0w6ScPRdHjQPCtmTUgs2lfuTwzGrrsY3hADUmVH7ECUKLcAy-pHyjNTwpzcXhHv37a3TlHnuLxCNq_ThZLoycJrg6Nl2XGC5LCJsKDx5-gKdzz-AHVl_tc4ggPjueLny0tQUAVhoZPor7S06nDxwReTcfN18V8bKc-y6FDAK6S_O8nnenE2Lc-KSc0f7avqQOFeEahu2AAWxFzuKBjkxTDy-IUmRmxIAUcDCV6X2VdjVn6yGYD1SMx4YWdbVGe4mLo3z-V_-8gcVQzZwcdVjGjjVh-yrH0g_mbKzBmLrI1RhEfE
EXPIRY      2022-10-28 13:20:39 +0200 CEST
Using ory introspect token you can inspect this access token too

code_access_token="{INSERT-ACCESS-TOKEN-FROM-CODE-FLOW-HERE}"
ory introspect token --project $project_id \
  --format json-pretty \
  $code_access_token
resulting in the following JSON:

{
  "active": true,
  "client_id": "d2e066cd-060d-44c9-92c1-1e73cbd6016e",
  "exp": 1666962209,
  "iat": 1666958609,
  "iss": "https://elastic-goldstine-1n7d31aph0.projects.oryapis.com",
  "nbf": 1666958609,
  "scope": "offline openid",
  "sub": "6ac05266-0e70-4b7b-beb9-963e1c6440bf",
  "token_type": "Bearer",
  "token_use": "access_token"
}
Awesome, you performed all the essential OAuth2 Flows! Want to learn more? Head over to the documentation.

Keep reading if you want to learn how to use Ory open-source software in Docker to reproduce the same results.

Run Ory OAuth2 & OpenID Connect on Docker
Ory develops its software as open source and provides binaries and Docker images. Running Ory software yourself is great for experimenting, developing, and contributing to open source!

Running Ory software yourself requires advanced skills in terms of software operations and security. To replicate this guide please use a Unix-family operating systems with Docker installed.

All Ory technology follows architecture principles that work best on container orchestration systems such as Kubernetes, CloudFoundry, OpenShift, and similar projects. While it is possible to run the Ory stack on a RaspberryPI, the integration with the Docker and Container ecosystem is best documented and supported. Ory's architecture is designed along several guiding principles:

Minimal dependencies (no system dependencies; might need a database backend)
Runs everywhere (Linux, macOS, FreeBSD, Windows; AMD64, i386, ARMv5, ...)
Scales without effort (no memcached, etcd, required, ...)
Minimize room for human and network errors
All Ory software is a single dependency-free binary that you can download at the project's respective GitHub repository (Ory Hydra, Ory Keto, Ory Kratos). The binaries run on bare metal machines, RaspberryPIs, ARM, Intel, Windows - you name it! Because this guide requires PostgreSQL and NodeJS (for the UI), we will use Docker to set up the examples.

Prepare Docker Deployment
Before we head into it, you need to make sure that there are no conflicts with existing docker containers or other open ports. Please make sure that ports 9000, 9001, 9010, 9020 are open.

For Linux

sudo ss -atuln | grep '9000\|9001\|9010\|9020'
For Apple MacOS (/bin/bash and /bin/zsh)

sudo netstat -atuln | grep '9000\|9001\|9010\|9020'
Note 'netstat' on the MAC does not support all options used in Linux and Windows. The 'lsof' command (\$ man -k lsof) augments some of netstat missing functionality.

For Microsoft Windows 10, use the following command:

netstat -an | findstr /r "9000 9001 9010 9020"
If the result of the command lists open ports, you must kill the command that listens on that port first. Next, you should check if any existing Ory Hydra Docker container is running. If there is one, you should kill that Docker container.

docker ps | grep 'hydra'
docker kill hydra
docker kill --signal=HUP hydra
For Microsoft Windows use

docker ps | findstr "hydra"
Create a Docker Network
Initially, a network must be created that attaches all Docker containers so the containers can talk to one another.

docker network create hydraguide
The result will be something like this:

641a26284ff2f8ee4580988371b91923d6711e20aa964ebbdf5b2e4b4f2592b8
The next section explains how to set up the PostgreSQL database system.

Install and Run PostgreSQL in Docker
This docker command starts postgres container ory-hydra-example--postgres and sets up a database called hydra with user hydra and password secret.

Note: Some code listings use \ at the end of the line. Shells like bash concatenate these to one line.
```
docker run --network hydraguide \
  --name ory-hydra-example--postgres \
  -e POSTGRES_USER=hydra \
  -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=hydra \
  -d postgres:9.6
```

By the way, we do not recommend deploying databases using Docker in production. Use a managed solution like Amazon RDS or Google Cloud SQL. Even small instances will be able to serve large traffic numbers, check out some of the benchmarks.

Configure the Ory Hydra OAuth2 Server and OpenID Connect Provider
The system secret is used to encrypt data at rest, and to sign tokens and authorize codes. Once a database is initialized with a system secret, that secret must be used to access the database.

## Linux / macOS ##
#
# The system secret can only be set against a fresh database. This
# secret is used to encrypt the database and needs to be set to the same value every time the process (re-)starts.
# You can use /dev/urandom to generate a secret. But make sure that the secret must be the same anytime you define it.
# You could, for example, store the value somewhere.

export SECRETS_SYSTEM=$(export LC_CTYPE=C; cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

## Other systems ##
#
# While systems like Windows support creating random secrets, we will just use a fixed one for this example.
# Keep in mind that this assumes that you're running some type of linux-ish shell:
#
#   export SECRETS_SYSTEM=this_needs_to_be_the_same_always_and_also_very_$3cuR3-._
Define the Data Source Name (DSN)
The database URL must point to the Postgres container that was created above. The database will be used to persist and query data. Ory Hydra prevents data leaks as only token signatures are stored in the database. For a valid token, both payload and signature are required.

export DSN=postgres://hydra:secret@ory-hydra-example--postgres:5432/hydra?sslmode=disable
The result will be something like:

postgres://hydra:secret@ory-hydra-example--postgres:5432/hydra?sslmode=disable
Run SQL Migrations
Next, the following hydra migrate sql command initializes the database. It pulls the latest Docker Image for Ory Hydra and runs a container that executes the hydra migrate sql command.

docker run -it --rm \
  --network hydraguide \
  oryd/hydra:v2.0.1 \
  migrate sql --yes $DSN
For safety's sake, SQL migrations do not run without explicit instructions This is the case for new and existing databases.

Run the Ory Hydra OAuth2 Server and OpenID Connect Provider
Besides setting the system secret (SECRETS_SYSTEM), the database URL (DSN ), the public URL (URLS_SELF_ISSUER) of the server, the user login endpoint ( URLS_LOGIN) and the user consent endpoint (URLS_CONSENT) are passed using environment variables.

Both user login and consent URLs point to one or two web service(s) that will be explained and set up in the next sections. For now, it connects Ory Hydra to an identity management system that handles user registration, profile management, and user login.

In this example, Ory Hydra runs HTTP instead of HTTPS. This simplifies the application. In a production scenario, HTTPS and more secure values would be used.

There are two exposed ports in this case: 9000 and 9001. The former (9000) serves API requests coming from the public internet e.g.: /oauth2/auth /oauth2/token while the latter (9001) serves administrative API requests that should not be available, without administrator intention, to the public internet.

docker run -d \
  --name ory-hydra-example--hydra \
  --network hydraguide \
  -p 9000:4444 \
  -p 9001:4445 \
  -e SECRETS_SYSTEM=$SECRETS_SYSTEM \
  -e DSN=$DSN \
  -e URLS_SELF_ISSUER=http://127.0.0.1:9000/ \
  -e URLS_CONSENT=http://127.0.0.1:9020/consent \
  -e URLS_LOGIN=http://127.0.0.1:9020/login \
  oryd/hydra:v2.0.1 serve all --dev
Is it alive?
This is easy to answer, just check the docker logs! Or run this curl command which should reply with {"status":"ok"}:

curl http://127.0.0.1:9001/health/ready
{"status":"ok"}
docker logs ory-hydra-example--hydra

[...]

time="2017-06-29T21:26:34Z" level=info msg="Setting up http server on :4444"
Ory Hydra CLI
When running Ory Hydra outside of the Ory Network, use the hydra CLI to interact with the Ory Hydra server. You can download the Ory Hydra CLI from GitHub. Please make sure that the version of the CLI matches the version of the Ory Hydra server!

For simplicity, we will use the Ory Hydra CLI included in the Docker container. To see the available commands, run the help command.

docker run --rm -it oryd/hydra:v2.0.1 \
  help
This command produces an overview of the CLI as follows:

Run and manage Ory Hydra

Usage:
  hydra [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  create      Create resources
  delete      Delete resources
  get         Get resources
  help        Help about any command
  import      Import resources
  introspect  Introspect resources
  janitor     This command cleans up stale database rows.
  list        List resources
  migrate     Various migration helpers
  perform     Perform OAuth 2.0 Flows
  revoke      Revoke resources
  serve       Parent command for starting public and administrative HTTP/2 APIs
  update      Update resources
  version     Display this binary's version, build time and git hash of this build

Flags:
  -h, --help   help for hydra

Use "hydra [command] --help" for more information about a command.
Performing the OAuth2 Client Credentials Flow
To create an OAuth2 Client with a locally running Ory Hydra server, we use the same command arguments as with the Ory CLI with two modifications:

- ory --project $project_id
+ docker run --rm -it --network hydraguide oryd/hydra:v2.0.1 \
    create oauth2-client \
+     --endpoint http://ory-hydra-example--hydra:4445 \
      --grant-type client_credentials
Instead of using the Ory CLI, we use the Ory Hydra CLI and add the --endpoint flag to specify the administrative API endpoint of the Ory Hydra server

docker run --rm -it --network hydraguide oryd/hydra:v2.0.1 \
  create oauth2-client \
    --endpoint http://ory-hydra-example--hydra:4445 \
    --grant-type client_credentials
which outputs the OAuth2 Client details:

CLIENT ID       33b32af0-4722-4508-980f-2027dfc49c16
CLIENT SECRET   eh-d_leHfsmxWNkgAJwF8Z3UT5
GRANT TYPES     client_credentials
RESPONSE TYPES  code
SCOPE           offline_access offline openid
AUDIENCE
REDIRECT URIS
Performing the client credentials grant using the Ory Hydra CLI

docker run --rm -it --network hydraguide oryd/hydra:v2.0.1 \
  perform client-credentials \
    --client-id {INSERT-CLIENT-ID_HERE} \
    --client-secret "{INSERT-CLIENT-SECRET-HERE}" \
    --endpoint http://ory-hydra-example--hydra:4444
to receive an OAuth2 access token:

ACCESS TOKEN    ory_at__s-lJ8wMAhiJHGk8NU1cP_qSRjjY8MJH9rwBWXXbcnU.Jw7wT-VTm4T2eFgubqiaTPNeWiJV9-2-gd0vjz82H_A
REFRESH TOKEN   <empty>
ID TOKEN        <empty>
EXPIRY          2022-10-28 11:56:14 +0000 UTC
And finally validating it using hydra introspect token

docker run --rm -it --network hydraguide oryd/hydra:v2.0.1 \
  introspect token \
  --endpoint http://ory-hydra-example--hydra:4445 \
    "{INSERT-ACCESS-TOKEN-HERE}"
to receive the OAuth2 access token metadata:

ACTIVE    true
SUBJECT   33b32af0-4722-4508-980f-2027dfc49c16
CLIENT ID 33b32af0-4722-4508-980f-2027dfc49c16
SCOPE
EXPIRY    2022-10-28 11:56:14 +0000 UTC
TOKEN USE access_token
Perform OAuth2 Authorization Code Flow on Docker
When running Ory Hydra in Docker, you need a running OAuth2 Login and Consent app. In this example, we will use the demo application from Github and run it in Docker:

docker run -d \
  --name ory-hydra-example--consent \
  -p 9020:3000 \
  --network hydraguide \
  -e HYDRA_ADMIN_URL=http://ory-hydra-example--hydra:4445 \
  -e NODE_TLS_REJECT_UNAUTHORIZED=0 \
  oryd/hydra-login-consent-node:v1.10.2
Once the container is running, we perform the same flow as on the Ory Network, but using the Ory Hydra CLI:

docker run --rm -it --network hydraguide oryd/hydra:v2.0.1 \
  create oauth2-client \
    --endpoint http://ory-hydra-example--hydra:4445 \
    --name "Authorize Code with OpenID Connect Demo" \
    --grant-type authorization_code,refresh_token \
    --response-type code \
    --redirect-uri http://127.0.0.1:4446/callback
code_client_id="{set to client id from output}"
code_client_secret="{set to client secret from output}"

docker run --rm -it --network hydraguide oryd/hydra:v2.0.1 \
  perform authorization-code \
    --endpoint http://ory-hydra-example--hydra:4445 \
    --client-id $code_client_id \
    --client-secret $code_client_secret
Your browser will show a simple screen asking you to authorize the application. If you remember the CircleCI example from the beginning of the article, this would be the "Log In with GitHub" button.

Consent App showing the login screen

After clicking "Authorize application" you will be asked to log in. The screen you are seeing is provided by the exemplary User Login & Consent app ("ory-hydra-example--consent"). The contents of these screens are under your control and you can use any technology you like to implement them. As already noted, the exemplary application has just one user. In a real-world scenario, you could probably sign up for a new account or use a social login provider (e.g. Google, Facebook) to sign in.

Consent App showing the login screen

The consent screen is the second important screen shown by the User Login & Consent app. It asks the end user for permission to authorize. If a user has privacy concerns, they could not grant access to personal details. Since the example only requests very basic permissions, all can be granted without concern.

Consent App asking the user to grant the requested scopes to the application

Once logged in and authorized, Ory Hydra will issue an access token, an refresh refresh (if scope offline was granted), and an ID token (if scope openid was granted).

Continue using your OAuth2 Server
That's it, this article shows how to have a running OAuth2 server with an exemplary identity provider, and perform an OAuth2 request. Using the token from the last request and passing it to hydra token introspect as explained in earlier OAuth2 Client Credentials flow provides further details about the token properties.

Ory Hydra is an Apache 2.0 licensed Go server solving OAuth2, OpenID Connect and API security in general. It secures millions of requests per day and has a vibrant and welcoming online community.

Check out Ory Hydra at Github and the other Ory API Security products.
