##
#
https://gist.github.com/jimathyp/181528d9193fba00005330991c6de79e
#
##

aws-vault
=========

WIP

- [Intro](#intro)
- [Installation](#installation)
- [Setup](#setup)
- [Environment variables](#[environment-variables])
- [Errors](#errors)
  * [Key ring not available](#aws-vault-error-specified-keyring-backend-not-available)
  * [Error execing process](#aws-vault-error-exec-error-execing-process-cannot-allocate-memory)
  * [Failed to get credentials](#aws-vault-error-login-failed-to-get-credentials)
  * [Failed to get credentials](#aws-vault-error-login-failed-to-get-credentials-for)
- [Example config](#example-awsconfig)
- [Discussion](#discussion)
- [config file](#config-file)
- [Discussion on role usage](#discussion-on-role-usage)
- [config](#config-file-1) 

Intro
-----

https://github.com/99designs/aws-vault

aws-vault is a command line tool used to:
- run a process using AWS credentials
- provide a login link to use to login into the AWS console (via browser). It can also open the browser directly.

Links on usage
- https://github.com/FernandoMiguel/aws-vault-quick-guide
- https://hands-on.cloud/how-to-securly-manage-connections-to-multiple-aws-accounts/
        

----
## Installation

v6.3.1
```
URL=https://github.com/99designs/aws-vault/releases/download/v6.3.1/aws-vault-linux-amd64
curl -O -L $URL
chmod +x aws-vault-linux-amd64
sudo mv aws-vault-linux-amd64 /usr/local/bin/aws-vault
```

- The curl option `-L` means follow redirects. `-O` means to save to a local filename the same as the remote file

Check that aws-vault is available (`aws-vault`) as it should be on the PATH (`which aws-vault` and `echo $PATH`)

----
## Setup

- login to base account as user
- create access key, note access key and secret access key
- run

        #mkdir ~/.awsvault/
        echo "export AWS_VAULT_FILE_PASSPHRASE=yourpass" > ~/.awsvault/awsvault
        chmod 400 ~/.aws/awsvault
        # aws-vault add <profile_name> --backend=file

in .bash_profile  add:
    
    source ~/.awsvault/awsvault

then run 

    source ~/.bash_profile

To add a login; add credentials for the base user (but cannot login using aws-vault as this user directly. These creds are used by roles we add later)

    aws-vault add <name> --backend=file

enter access and secret access when asked and set a passphrase for the local cred file

NB: not sure backend=file is necessary, since we export AWS_VAULT_BACKEND=file later

-----
## Environment variables

When running in `aws-vault exec <profile_name>` these environment variables are added to the shell:

    AWS_REGION
    AWS_DEFAULT_REGION
    AWS_VAULT
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_SESSION_TOKEN
    AWS_SECURITY_TOKEN
    AWS_CREDENTIAL_FILE
    AWS_DEFAULT_PROFILE
    AWS_PROFILE
    AWS_SDK_LOAD_CONFIG
    AWS_SESSION_EXPIRATION


----
## Errors


### aws-vault: error: Specified keyring backend not available

Add to ~/.bash_profile

    export AWS_VAULT_BACKEND=file
    
### aws-vault: error: exec: Error execing process: cannot allocate memory

    $ aws-vault exec <profile_name> -- aws s3 ls 
    aws-vault: error: exec: Error execing process: cannot allocate memory

Had a memory leak in another process.

### aws-vault: error: login: Failed to get credentials

    aws-vault: error: login: Failed to get credentials for <awsvault_profile>: AccessDenied: User:
    arn:aws:iam::<aws_account>:user/<aws_user_name> is not authorized to perform: sts:GetFederationToken
    on resource: arn:aws:sts::<aws_account>:federated-user/<aws_username> with an explicit deny

"Other AWS STS API operations that return temporary credentials do not support MFA. ... For GetFederationToken, MFA is not necessarily associated with a specific user."

GetFederationToken api call which is used for profiles without role_arn does not support MFA

- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html
- aws-vault login doesn't use mfa for profiles without role_arn #564 https://github.com/99designs/aws-vault/issues/564

Fix:
- Login with user with iam:CreateRole permission
- Create policy
- "Assume-XRole"
```
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Condition": {
                    "Bool": {
                        "aws:MultiFactorAuthPresent": "true"
                    }
                },
                "Action": "sts:AssumeRole",
                "Resource": [
                    "arn:aws:iam::<account>:role/<rolename>"            ],
                "Effect": "Allow",
                "Sid": "AssumeRole"
            }
        ]
    }
```

- Create Role 'AssumeAdmin'
  - IAM, create role
  - another aws account (use same account)
  - require MFA
  - attach policy created above
    
- Create role 'Admin'
  - another aws account (this one)
  - require MFA
  - Add role Adminaccess
    
- Create Group
  - Add user to group
  - add permissions: assumerole
    
- aws-vault: now to add that role. Don't use 'aws-vault add <profile-name>' as this adds to the aws-vault cred store and you need an access key for that (we have a user - which we have an access key, and we want to use that user to assume a role which has no access key)
- edit the standard aws config file ~/.aws/config
- see https://github.com/99designs/aws-vault#roles-and-mfa
```
    [profile foo-admin]
    source_profile = jonsmith
    role_arn = arn:aws:iam::22222222222:role/Administrator
    mfa_serial = arn:aws:iam::111111111111:mfa/jonsmith
```
    
## aws-vault: error: login: Failed to get credentials for...

    aws-vault: error: login: Failed to get credentials for <role>: AccessDenied: User:
    arn:aws:iam::<account>:user/<user> is not authorized to perform: sts:AssumeRole on resource:
        arn:aws:iam::<account>:role/<role from config>

- Add MFA serial
- make sure group has the assume admin policy attached
    
    
## STS Token expired
- https://aws.amazon.com/premiumsupport/knowledge-center/sts-iam-token-expired/
    
----
## Example .aws/config

     [profile user-account]
 
     [profile otheraccount-somerole]
     source_profile = user_account
     role_arn = some_arn
     mfa_serial = user_mfa_arn
    
    
The config file is the same as used for the aws-cli - see https://docs.aws.amazon.com/cli/latest/topic/config-vars.html

When using aws-vault to login using a role, the name in the top right console will be "<role-name>/<time in nanoseconds>@..."

where role name comes from the `role_arn=arn:aws:iam::<account>:role/<role-name>` line.
    
To make it clearer which account/what role you are using I add the following the to the `~/.aws/config`

        role_session_name=some_name

----        
## Discussion
        
- https://www.reddit.com/r/aws/comments/a006op/what_security_risks_are_exposed_when_allowing/
        
aws-vault - federation. Main point of federation is centralization of identity and privileges. Only one identity that counts as you. Can federate to other identities, but cannot federate using those identities elsewhere.
        
Can switch to the service account, but the service account cannot switch to anything else
        
- https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html

Returns a set of temporary security credentials (consisting of an access key ID, a secret access key, and a security token) for a federated user. 

----
## config file

- https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
        
Add region
        
        [default]
        region = us-east-1
        
the config file is not specific to aws-vault. It is also used by the aws-cli. 
        
 Other options include
 
        output=text
        output=json
        include_profile=some_other

Can use the .aws/credential (or config) file to tell application how to get aws credentials for a profile

        [admin]
        credential_process = aws-vault exec admin --no-session --json
        
        # or
        credential_process = ~/bin/call-aws-vault.sh my_new_profile

or create add SSM parameter and create script call-aws-vault.sh (https://hands-on.cloud/how-to-securly-manage-connections-to-multiple-aws-accounts/)
        
        mkdir -p $HOME/bin
        cat > $HOME/bin/call-aws-vault.sh <<- EOF
        #!/usr/bin/env bash

        export PROFILE=$1
        export AWS_VAULT_FILE_PASSPHRASE=$(aws ssm get-parameters --profile default --names '/laptop/aws-vault/password' --with-decryption --query 'Parameters[0].Value' --output text)

        aws-vault exec -j $PROFILE
        EOF

        chmod +x $HOME/bin/call-aws-vault.sh

        
   
        
Can mean we can run a command without aws-vault prepended, eg:
        
        aws --profile admin s3 ls
  
#### credential_source 

credential_source can be Environment, Ec2InstanceMetadata, EcsContainer (https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html)

#### Specifying a role session name for easier auditing
        
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html#cli-configure-role-session-name

session_name

        [profile namedsessionrole]
        role_arn = arn:aws:iam::234567890123:role/SomeRole
        source_profile = default
        role_session_name = Session_Maria_Garcia
        
This results in the role session having the following ARN.

        arn:aws:iam::234567890123:assumed-role/SomeRole/Session_Maria_Garcia

Before, in top right of console you would have:
        
        role_name/1623032412770877500
        
        
- https://www.seniorlinuxadmin.co.uk/aws-vault.html
  
        
## Discussion on role usage

- https://aws.amazon.com/blogs/security/how-to-use-a-single-iam-user-to-easily-access-all-your-accounts-by-using-the-aws-cli/
- https://hands-on.cloud/how-to-securly-manage-connections-to-multiple-aws-accounts/
- https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html
    
- all IAM users are in one account
- provide access to other accounts by allowing them to assume roles (sts:AssumeROle) in thoise accounts
    
End result, don't need a ~/.aws/credentials file (all in aws-vault)
    
Check if you can assume role
    
    aws sts get-caller-identify
    aws sts get-caller-identity --profile another_account_role
    
## config file

https://docs.aws.amazon.com/cli/latest/topic/config-vars.html
        
aws-vault uses the ~/.aws/config file. aaws-vault v6 also recognizes a include_profile option (v5 = parent_profile) (not recognized by the aws-cli) where the included profile is used as  a code fragment (rather than as a parent profile as for source_profile).
        
Using this, this is how you can have common mfa_serial for each profile (otherwise when using source_profile, mfa_serial must be listed in each profile). 
    
# aws cli
        
- env vars https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
        
     
        
## Issues
        
### Region in config file not being recognized. 
        
When running code commit create repo. Not sure on this one. It works for listing bucket in a region. 
Fixed. Region must be under [default] profile not only [source_profile]
        
        
        
        
## Session durations

aws-vault uses Amazon's STS service to generate temporary credentials via the GetSessionToken or AssumeRole API calls. These expire in a short period of time, so the risk of leaking credentials is reduced.
        
        
----

https://aws.amazon.com/console/faq-console/#session_expire
        
Q: When does my session expire?

For security purposes, a login session will expire 12 hours after you sign in to the AWS Management Console with your AWS or IAM account credentials. To resume your work after the session expires, choose Click login to continue and log in again. The duration of federated sessions varies depending on the federation API (GetFederationToken or AssumeRole) and the administrator’s preference. Please go to our Security Blog to learn more about building a secure delegation solution to grant temporary access to your AWS account.
        
----

https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html

AssumeRole* API operation - SessionDuration from 900-43200 seconds (15 min - 12h)

GetFederationToken API - DurationSeconds from 900-129600 sec (36 h)
        
Difference between the lifetime of the federation endpoint URL (15 min) and the duration of the temporary credential session associated with the URL. ie. you have 15 min to login, once you do, you have the duration you specified (starting from when it was created). 

----

https://aws.amazon.com/blogs/security/understanding-the-api-options-for-securely-delegating-access-to-your-aws-account/
        
Comes down to where you want to maintain the policies associated with your federated users:
    
- in organization: use GetFederationToken. 
- in AWS: use AssumeRole. 
        
----
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html
Temporary security credentials in IAM

Regions. STS is a global service, but you can choose to use regional endpoints to reduce latency. But the credentials work globally.
    
use cases:
- Identity federation
- Roles for cross-account access.
  Can define user identities in one account, and use those identities to access resources in other accounts. This is the 'delegation' approach to temporary access. https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html
- Roles for EC2
- Other AWS services

  
        
### Open link
        
Using WSL with Windows Terminal, Ctrl Click on the link aws-vault login link will open a browser window.
        
'wslview' is a fake WSL browser that will open windows's default browser
        
Can just change default browser in windows settings
        
A BROWSER envrionment variable can be used to open browser of your choice (export BROWSER=..., add to bash_profile etc)
        
        
## AWS Vault SSO

- https://ubertasconsulting.com/2021/06/08/security-simplifying-and-securing-your-access-key-management-with-aws-sso/
        
        
