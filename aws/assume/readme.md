
##
##
##

https://github.com/marketplace/actions/configure-aws-credentials-by-assuming-roles

##
##

##
Configure AWS Credentials by Assuming Roles
Usage
At first, create an IAM role for your repository. The role's trust policy must allow an AWS account 053160724612 to assume the role and check external id:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::053160724612:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "your-name/your-repo"
        }
      }
    }
  ]
}
And then, add the following step to your workflow:

- name: Configure AWS Credentials
  uses: fuller-inc/actions-aws-assume-role@v1
  with:
    aws-region: us-east-2
    role-to-assume: arn:aws:iam::123456789012:role/GitHubRepoRole-us-east-2
Session tagging
You can enable session tagging by adding role-session-tagging: true.

- uses: fuller-inc/actions-aws-assume-role@v1
  with:
    aws-region: us-east-2
    role-to-assume: arn:aws:iam::123456789012:role/GitHubRepoRole-us-east-2
    role-session-tagging: true
The session will have the name "GitHubActions" and be tagged with the following tags:

Key	Value
GitHub	"Actions"
Repository	GITHUB_REPOSITORY
Workflow	GITHUB_WORKFLOW
RunId	GITHUB_RUN_ID
Actor	GITHUB_ACTOR
Branch	GITHUB_REF
Commit	GITHUB_SHA
Note: all tag values must conform to the requirements. Particularly, GITHUB_WORKFLOW will be truncated if it's too long. If GITHUB_ACTOR or GITHUB_WORKFLOW contain invalid characters, the characters will be replaced with an '_'.

The role's trust policy need extra permission sts:TagSession for session tagging:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::053160724612:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "your-name/your-repo"
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::053160724612:root"
      },
      "Action": "sts:TagSession"
    }
  ]
}
Use the node id of the repository
You can use the global node id of the repository instead of its name as ExternalId. By adding use-node-id: true, the action sends the node id (e.g. R_kgDOFMsDjw) as ExternalId.

- uses: fuller-inc/actions-aws-assume-role@v1
  with:
    aws-region: us-east-2
    role-to-assume: arn:aws:iam::123456789012:role/GitHubRepoRole-us-east-2
    use-node-id: true
To get the node id, call Get a repository REST API.

# with curl command
curl -i -u username:token -H "X-Github-Next-Global-ID: 1" "https://api.github.com/repos/{owner}/{repo}"

# with GitHub CLI
gh api "repos/{owner}/{repo}" -H "X-Github-Next-Global-ID: 1" --jq ".node_id"
You'll get a response that includes the node_id of the repository:

{
  "id": 348849039,
  "node_id": "R_kgDOFMsDjw",
  "name": "actions-aws-assume-role",
  "full_name": "fuller-inc/actions-aws-assume-role",
  "private": false,
  "owner": {
    "login": "(... snip ...)"
  }
}
In this example, the node_id value is R_kgDOFMsDjw. The role's trust policy looks like this:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::053160724612:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "R_kgDOFMsDjw"
        }
      }
    }
  ]
}
For more information about global node IDs, see Using global node IDs.

Migrate your node id to the next format
If you get the following warning, you need to migrate your node IDs to the next format.

It looks that you use legacy node IDs. You need to migrate them. See https://github.com/fuller-inc/actions-aws-assume-role#migrate-your-node-id-to-the-next-format for more detail.

Because GitHub is now rolling out the new GraphQL global ID format.

To get the next IDs, call Get a repository REST API with X-Github-Next-Global-ID: 1 header. If you use curl or gh (GitHub CLI), add the -H "X-Github-Next-Global-ID: 1" option.

# with curl command
curl -i -u username:token -H "X-Github-Next-Global-ID: 1" "https://api.github.com/repos/{owner}/{repo}"

# with GitHub CLI
gh api "repos/{owner}/{repo}" -H "X-Github-Next-Global-ID: 1" --jq ".node_id"
Your role's trust policy looks like this:

 {
   "Version": "2012-10-17",
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": {
         "AWS": "arn:aws:iam::053160724612:root"
       },
       "Action": "sts:AssumeRole",
       "Condition": {
         "StringEquals": {
-          "sts:ExternalId": "MDEwOlJlcG9zaXRvcnkzNDg4NDkwMzk="
+          "sts:ExternalId": "R_kgDOFMsDjw"
         }
       }
     }
   ]
 }
See Migrating GraphQL global node IDs and GraphQL global ID migration update for more detail.

About security hardening with OpenID Connect
The action also supports OpenID Connect (OIDC).

Additional session tags "Audience" and "Subject" are available
All session tags are signed by GitHub OIDC Provider. You can use them in the Condition element in your IAM JSON policy
Example workflow:

jobs:
  deploy:
    runs-on: ubuntu-latest
    # These permissions are needed to interact with GitHub's OIDC Token endpoint.
    permissions:
      id-token: write
      statuses: write
      contents: read

    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - uses: fuller-inc/actions-aws-assume-role@v1
        with:
          aws-region: us-east-2
          role-to-assume: arn:aws:iam::123456789012:role/GitHubRepoRole-us-east-2
Key	Value
Audience	aud of the token
Subject	sub of the token
Environment	environment of the token
GitHub	"Actions"
Repository	GITHUB_REPOSITORY
Workflow	GITHUB_WORKFLOW
RunId	GITHUB_RUN_ID
Actor	GITHUB_ACTOR
Branch	GITHUB_REF
Commit	GITHUB_SHA
How to Work
How to Work

Request a new credential
The fuller-inc/actions-aws-assume-role action sends the GITHUB_TOKEN and requests a new credential to the credential provider. It works on AWS Lambda owned by @fuller-inc.
Check Permission of GitHub Repository
The Lambda function checks the permission of the repository. GITHUB_TOKEN must have the write permission of the repository and be generated by GitHub Action bot.
Request AssumeRole to an IAM Role on your AWS account
Check Permission of the IAM Role
The AWS IAM Service checks the role's trust policy.
Return the Credential
Configure the Credential to the workflow
Caution
You can use the credential provider for free, but note that it works on my personal AWS Account.
Your AWS Account ID, the name of your IAM Role, and the name of your GitHub Repository will be logged by AWS CloudTrail on my AWS Account.
If you enable tagging session, GITHUB_WORKFLOW, GITHUB_RUN_ID, GITHUB_ACTOR, GITHUB_REF, and GITHUB_SHA are also logged.
If you want to use this action on your private repository, I recommend building your own credential provider. You can find its source code on the provider directory
