
##
#
https://git.rossabaker.com/actions/renovate-action/src/commit/efb2b988387baa7f663a5d3adaef727dccb99b30
#
##



Options
Options can be passed using the inputs of this action or the corresponding environment variables.
When both are passed, the input takes precedence over the environment variable. For the available environment variables see the Renovate Self-Hosted Configuration and Self-Hosting docs.

configurationFile
Configuration file to configure Renovate. The supported configurations files can be one of the configuration files listed in the Renovate Docs for Configuration Options or a JavaScript file that exports a configuration object. For both of these options, an example can be found in the example directory.

The configurations that can be done in this file consists of two parts, as listed below. Refer to the links to the Renovate Docs for all options.

Self-Hosted Configuration Options
Configuration Options
The branchPrefix option is important to configure and should be configured to a value other than the default to prevent interference with e.g. the Renovate GitHub App.

If you want to use this with just the single configuration file, make sure to include the following two configuration lines. This disables the requirement of a configuration file for the repository and disables onboarding.

  onboarding: false,
  requireConfig: false,
token
Generate a personal access token, with the repo:public_repo scope for only public repositories or the repo scope for public and private repositories, and add it to Secrets (repository settings) as RENOVATE_TOKEN. You can also create a token without a specific scope, which gives read-only access to public repositories, for testing. This token is only used by Renovate, see the token configuration, and gives it access to the repositories. The name of the secret can be anything as long as it matches the argument given to the token option.

Note that the GITHUB_TOKEN secret can't be used for authenticating Renovate.

Example
This example uses a personal access token and will run every 15 minutes. 
The personal access token is configured as a GitHub secret named RENOVATE_TOKEN. This example uses the example/config.js file as configuration. 
You can also see a live example of this action in my github-renovate repository, which also includes a more advanced configuration for updating GitHub Action workflows.

Remark Update the action version to the most current, see here for latest release.

```
name: Renovate
on:
  schedule:
    # The "*" (#42, asterisk) character has special semantics in YAML, so this
    # string has to be quoted.
    - cron: '0/15 * * * *'
jobs:
  renovate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2.0.0
      - name: Self-hosted Renovate
        uses: renovatebot/github-action@v21.30.0
        with:
          configurationFile: example/renovate-config.js
          token: ${{ secrets.RENOVATE_TOKEN }}
```
Example with GitHub App
Instead of using a Personal Access Token (PAT) that is tied to a particular user you can use a GitHub App where permissions can be even better tuned. Create a new app and give it the following permissions:

Permission	Level
Contents	Read & write
Metadata	Read-only
Pull requests	Read & write
Store the app ID as a secret with name APP_ID and generate a new private key for the app and add it as a secret to the repository as APP_PEM in the repository where the action will run from. Note that APP_PEM needs to be base64 encoded. You can encode your private key file like this from the terminal:

cat your_app_key.pem | base64 -w 0 && echo
Going forward we will be using the machine-learning-apps/actions-app-token action in order to exchange the GitHub App certificate for an access token that renovate can use.

The final workflow will look like this:

```
name: Renovate
on:
  schedule:
    # The "*" (#42, asterisk) character has special semantics in YAML, so this
    # string has to be quoted.
    - cron: '0/15 * * * *'
jobs:
  renovate:
    runs-on: ubuntu-latest
    steps:
      - name: Get token
        id: get_token
        uses: machine-learning-apps/actions-app-token@master
        with:
          APP_PEM: ${{ secrets.APP_PEM }}
          APP_ID: ${{ secrets.APP_ID }}

      - name: Checkout
        uses: actions/checkout@v2.0.0

      - name: Self-hosted Renovate
        uses: renovatebot/github-action@v21.30.0
        with:
          configurationFile: example/renovate-config.js
          token: 'x-access-token:${{ steps.get_token.outputs.app_token }}'

```



DEMO



```
name: Trigger Renovate

on:
  workflow_dispatch:  # Allows for manual trigger
  schedule:
    - cron: "0 0 * * *"  # Optional: Run daily at midnight

jobs:
  renovate:
    runs-on: ubuntu-22.04
    container:
      image: ubuntu:jammy
    steps:
      - name: Set up environment
        run: |
          apt-get update && apt-get install -y git curl gnupg2 lsb-release ca-certificates
          curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
          apt-get install -y nodejs
          apt-get install -y python3 python3-pip python3-venv
          apt-get install -y ruby-full

      - name: Checkout repository
        uses: actions/checkout@v3

      - name: Install Renovate
        run: npm install -g renovate

      - name: Run Renovate
        env:
          RENOVATE_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          LOG_LEVEL: debug
          RENOVATE_REPOSITORIES: "babywyrm/demo"  # Specify the repository
        run: renovate --autodiscover=false
```



DEMO

```
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: renovate-runner
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      repository: babywyrm/demo
```

##
##


 ```     
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: renovate-runner
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      repository: babywyrm/demo
      labels:
        - self-hosted
        - hot-new-new  # lolol 



