###
###

https://github.com/marketplace/actions/terraform-security-scan
<br>
https://aquasecurity.github.io/tfsec/v1.8.0/getting-started/configuration/github-actions/github-action/
<br>
https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin-code-security/get-started/connect-your-repositories/add-github-actions
<br>

###
###

GitHub Action
Terraform security scan
v3.0.3
Latest version
⚠️ tfsec has it's own github action now, which will certainly follow more the evolution of this amazing tool. When I discovered tfsec, there was no github actions, and this is the reason why this one exists. Now that they have their own, there is not more need to have multiple repo for that. You can find it here: aquasecurity/tfsec-pr-commenter-action ⚠️

Master CI

Terraform security check action
This action runs https://github.com/tfsec/tfsec on $GITHUB_WORKSPACE. This is a security check on your terraform repository.

The action requires the https://github.com/actions/checkout before to download the content of your repo inside the docker.

Inputs
tfsec_actions_comment - (Optional) Whether or not to comment on GitHub pull requests. Defaults to true.
tfsec_actions_working_dir - (Optional) Terraform working directory location. Defaults to '.'.
tfsec_exclude - (Optional) Provide checks via , without space to exclude from run. No default
tfsec_version - (Optional) Specify the version of tfsec to install. Defaults to the latest
tfsec_output_format - (Optional) The output format: default, json, csv, checkstyle, junit, sarif (check tfsec for an extensive list)
tfsec_output_file - (Optional) The name of the output file
Outputs
None

Example usage
steps:
  - uses: actions/checkout@v2
  - uses: triat/terraform-security-scan@v3
The above example uses a tagged version (v3), you can also opt to use any of the released version.

To allow the action to add a comment to a PR when it fails you need to append the GITHUB_TOKEN variable to the tfsec action:

  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
Full example:

jobs:
  tfsec:
    name: tfsec
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
      - name: Terraform security scan
        uses: triat/terraform-security-scan@v3.0.0
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
