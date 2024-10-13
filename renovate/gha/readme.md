Maintenance free Renovate using GitHub Actions workflows
Sebastiaan van Steenis
Sebastiaan van Steenis

##
#
https://medium.com/@superseb/maintenance-free-renovate-using-github-actions-workflows-d91d32ad854a
#
##





By now, most of you have heard about automatic dependency updates in your repositories. 
I am not going to talk about why you should use Dependabot, 
Renovate or some other solution (I might in another post).
In this post, I will be going over how to implement Renovate using GitHub Actions workflows in a way that will actually save you and your teams time, while staying up-to-date.

The overview
For this setup, I will be using the “GitHub Action” variant of “Running Renovate”. Obviously, the way you decide to run Renovate is completely up to you, and should be decided by your team’s requirements. In this case, having no external dependency (as in the hosted version), and being in complete control of the solution were the biggest deciders for me.

This setup will give you:

A basic Renovate config that will be used as Shareable Config Preset which will not overwhelm your development teams but will also make the teams benefit from each others improvements. More on that in the “The Renovate part” below.
A fully controllable and re-usable GitHub Actions workflow, reducing the amount of pull requests per repository that uses the workflow and having the control to ad-hoc or schedule running Renovate. More on that in the “The GitHub Actions part” below.
For completeness, I will build up to the end solution to show you what decisions were made and why.

Repositories that are used in this post are;

https://github.com/superseb-demos/renovate-allinone-demo

https://github.com/superseb-demos/renovate-preset-demo

https://github.com/superseb-demos/renovate-workflow-preset-demo

https://github.com/superseb-demos/renovate-config

The Renovate part
Renovate is controlled by a configuration, I will use .github/renovate.json for this example. All the possibles filename options are described on Renovate Docs: Configuration Options.

There are a ton of configuration options for Renovate, I would recommend going through the docs and learn about them. And there will probably be some requirements from your side that you need to fulfill.

Here is an example configuration, I will describe what is what line by line;

baseBranches: What branches to look for updates, extremely convenient functionality when you use multiple branches
rebaseWhen : To reduce PR rebases, only rebase when the PR is conflicted
labels: What labels to add to the created PRs ( dependencies is sort of a default for dependency updates)
automergeStrategy: What type of merge to use when a PR is automatically merged (obviously personal preference)
prHourlyLimit: Only create 2 PRs per hour, this is mostly for initial runs as there can be a lot of PRs being created which could overwhelm your CI system.
{
  "baseBranches": ["main"],
  "rebaseWhen": "conflicted",
  "labels": ["dependencies"],
  "automergeStrategy": "merge-commit",
  "prHourlyLimit": 2
}
This pretty basic config will make sure that the configured branches will be checked for updates, the default behavior is that all the (package) managers that Renovate supports will check for default patterns and use the logic to find updates. See more info on the (package) managers on Renovate Docs: Managers. The downside is that you (and/or your teams) will get notified of PRs created for everything the (package) managers can find which is usually unnecessary for the team as they shouldn’t really care about these PRs, it should just be updated.

The following configuration file adds packageRules , which can be used to control what happens to certain packages. In this example, we add rules that allows Renovate to automatically merge PRs that contain a version bump of a patch version (for example, alpine:3.16.2 to alpine:3.16.3 ). The schedule only allows Renovate to create the PRs in the weekend, making sure that the development teams do not notifications on Docker image bumps. By default, Renovate will combine minor and patch which doesn’t work well with this example so we also add separateMinorPatchto make sure we get separate PRs for minor and patch updates.

In this example, we added the same rule for GitHub Actions workflows updates as these are important to keep up-to-date but not important enough to worry your development teams (at least,not the minor/patch ones).

{
  "baseBranches": ["main"],
  "rebaseWhen": "conflicted",
  "labels": ["dependencies"],
  "automergeStrategy": "merge-commit",
  "packageRules": [
   {
      "matchManagers": ["dockerfile"],
      "matchPackagePatterns": ["alpine"],
      "separateMinorPatch": true
    },
    {
      "matchManagers": ["dockerfile"],
      "matchPackagePatterns": ["alpine"],
      "matchUpdateTypes": ["patch"],
      "automerge": true,
      "schedule": ["every weekend after 4am"]
    },
    {
      "matchManagers": ["github-actions"],
      "matchUpdateTypes": ["minor", "patch"],
      "automerge": true,
      "pinDigests": true,
      "schedule": ["every weekend after 4am"]
    }
  ]
}
You can view this configuration in https://github.com/superseb-demos/renovate-allinone-demo, including the used Dockerfile and the resulting pull requests created by Renovate.

Of course, this is the simplest example of Renovate. I will share a few more examples that helped me a lot a bit further below, but for now I want to focus on the low maintenance setup. As you have seen, we now have a very simplistic configuration file for Renovate. As the file lives in each repository that uses it, teams have full control over it and can make changes however they want.

However, there are a few downsides to this. For these basics, you could assume that they would be generic for all development teams. In the given example, this would mean that each team needs the same configuration file. This is not a really a problem, but it becomes a problem as soon as the configuration changes. You either need to manually update all the configuration files, each team needs to update them or you automate it in a solution. There is a way to centralize the configuration, it is called Config Presets.

To use this, you need a repository where you can put the configuration and then refer to this in the repositories that want to use this preset. As the default name for this repository is renovate-config , I will be using this but it can be named whatever you want. You can move your current configuration into this repository, but it should be renamed to default.json instead of renovate.json which is what we used for the previous repository.


What is great about this, is that you can now have a centralized configuration, where all repositories that are extending from this configuration are benefiting from changes made. You can view this configuration in https://github.com/superseb-demos/renovate-preset-demo

In this example, it is looking for .github/default.json in the default branch (main) but to avoid pushing a configuration change to all your repositories with one merge, you can create another branch and configure the repositories to extend from there. This way, you can make changes in main and after testing, merge those into a separate branch (for example, release). Pointing to a different branch can be done using the # sign after the repository name. For this example and the release branch, it would be:

{
  "extends": ["github>superseb-demos/renovate-config#release"]
}
See More tips and tricks below for more explanation and tips and tricks.

Note: in most of the example repositories, I’ve added “ignoreTests”: true, because automerge will not work without tests. And I don’t want to waste GitHub Actions resources by adding a dummy workflow.

The GitHub Actions part
Now that we have a solid process to manage Renovate configuration, let’s talk about how we are going to execute it. For this I will be using GitHub Actions. A workflow will give us full control about how we run it, either on a schedule or ad-hoc if needed. We won’t go into detail on how to configure the authentication (either a Personal Access Token (PAT) or GitHub App) but you can find all details for that in the documentation and in the source repository. For this post, I will be using a GitHub App and it will create tokens on each workflow run.

As you can basically copy and paste the workflow from the the source repository, let me talk through my version.

The inputs allow for my most commonly used changes when running the workflow. As shown in the Renovate part, we use schedules to update certain versions but I want to keep the option to override these schedules (in case you want to update versions as soon as possible). I will use the environment variable RENOVATE_FORCE to override the schedule. The other input is to configure the log level, it allows everyone to enable more logging when you want to debug. This is controlled by the environment variable LOG_LEVEL .
I added a schedule to run twice each morning (GitHub Actions uses UTC by default), so that pull requests can be created and merged on the same day.
I added concurrency to make sure only one Renovate run is executed at a time, to avoid conflicting workflow runs.
Validating the configuration is still not 100%, there is a renovate-config-validator command in the Docker container
but I would like to keep the version of the container equal to the GitHub Action which is currently unsolved 
(if there is ever a breaking change in config, all of the workflows will start failing on validation while it’s probably still valid for the version it is using). 
So I added just a JSON validate step using jq for now.

```
name: Renovate
on:
  # Allows manual/automated ad-hoc trigger
  workflow_dispatch:
    inputs:
      logLevel:
        description: "Override default log level"
        required: false
        default: "info"
        type: string
      overrideSchedule:
        description: "Override all schedules"
        required: false
        default: "false"
        type: string
  # Run twice in the early morning for initial and follow up steps (create pull request and merge)
  schedule:
    - cron: '30 4,6 * * *'
concurrency: renovate
jobs:
  renovate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@755da8c3cf115ac066823e79a1e1788f8940201b # v3.2.0
      # Don't waste time starting Renovate if JSON is invalid
      - name: Validate Renovate JSON
        run: jq type .github/renovate.json
      - name: Get token
        id: get_token
        uses: tibdex/github-app-token@021a2405c7f990db57f5eae5397423dcc554159c # v1.7.0
        with:
          app_id: ${{ secrets.DEMO_RENOVATE_APP_ID }}
          installation_id: ${{ secrets.DEMO_RENOVATE_INSTALL_ID }}
          private_key: ${{ secrets.DEMO_RENOVATE_PRIVATE_KEY }}
      - name: Self-hosted Renovate
        uses: renovatebot/github-action@8343fa1c8d38f3d030aa8332773b737f7e2fa591 # v34.82.0
        env:
          # Repository taken from variable to keep configuration file generic
          RENOVATE_REPOSITORIES: ${{ github.repository }}
          # Onboarding not needed for self hosted
          RENOVATE_ONBOARDING: "false"
          # Username for GitHub authentication (should match GitHub App name + [bot])
          RENOVATE_USERNAME: "superseb-demo-renovate[bot]"
          # Git commit author used, must match GitHub App
          RENOVATE_GIT_AUTHOR: "superseb-demo-renovate <121964725+superseb-demo-renovate[bot]@users.noreply.github.com>"
          # Use GitHub API to create commits (this allows for signed commits from GitHub App)
          RENOVATE_PLATFORM_COMMIT: "true"
          # Override schedule if set
          RENOVATE_FORCE: ${{ github.event.inputs.overrideSchedule == 'true' && '{''schedule'':null}' || '' }}
          LOG_LEVEL: ${{ inputs.logLevel || 'info' }}
        with:
          configurationFile: .github/renovate.json
          token: '${{ steps.get_token.outputs.token }}'
```
With this in place, 
you will get scheduled workflow runs and you can run it ad-hoc if needed. 
It allows to configure the log level and you can override Renovate schedules if needed. 
But, as you can probably imagine by reading the Renovate part, this is again a configuration file that
needs to be placed in each repository and needs to be changed in all of the repositories when a change happens.

To avoid this, we can use reusable workflows. 
You can read more about this in the GitHub documentation.
To “convert” our current workflow to a reusable workflow, we need to change workflow_dispatch (which allows to run the workflow ad-hoc) to workflow_call and remove the schedule. 
For convenience, we can place this in the same repository as the Renovate preset. (renovate-config). You can place this file in .github/workflows/renovate.yml .
This is the path we can also reference when we want to call this workflow. See the “converted” workflow to a reusable workflow below:
```
name: Renovate
on:
  workflow_call:
    inputs:
      logLevel:
        description: "Override default log level"
        required: false
        default: "info"
        type: string
      overrideSchedule:
        description: "Override all schedules"
        required: false
        default: "false"
        type: string
concurrency: renovate
jobs:
  renovate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@755da8c3cf115ac066823e79a1e1788f8940201b # v3.2.0
      # Don't waste time starting Renovate if JSON is invalid
      - name: Validate Renovate JSON
        run: jq type .github/renovate.json
      - name: Get token
        id: get_token
        uses: tibdex/github-app-token@021a2405c7f990db57f5eae5397423dcc554159c # v1.7.0
        with:
          app_id: ${{ secrets.DEMO_RENOVATE_APP_ID }}
          installation_id: ${{ secrets.DEMO_RENOVATE_INSTALL_ID }}
          private_key: ${{ secrets.DEMO_RENOVATE_PRIVATE_KEY }}
      - name: Self-hosted Renovate
        uses: renovatebot/github-action@8343fa1c8d38f3d030aa8332773b737f7e2fa591 # v34.82.0
        env:
          # Repository taken from variable to keep configuration file generic
          RENOVATE_REPOSITORIES: ${{ github.repository }}
          # Onboarding not needed for self hosted
          RENOVATE_ONBOARDING: "false"
          # Username for GitHub authentication (should match GitHub App name + [bot])
          RENOVATE_USERNAME: "superseb-demo-renovate[bot]"
          # Git commit author used, must match GitHub App
          RENOVATE_GIT_AUTHOR: "superseb-demo-renovate <121964725+superseb-demo-renovate[bot]@users.noreply.github.com>"
          # Use GitHub API to create commits (this allows for signed commits from GitHub App)
          RENOVATE_PLATFORM_COMMIT: "true"
          # Override schedule if set
          RENOVATE_FORCE: ${{ github.event.inputs.overrideSchedule == 'true' && '{''schedule'':null}' || '' }}
          LOG_LEVEL: ${{ inputs.logLevel || 'info' }}
        with:
          configurationFile: .github/renovate.json
          token: '${{ steps.get_token.outputs.token }}'
```
With the reusable workflow in place,
I can change our repository workflow for renovate to use it.
This still requires the inputs and schedule, but now we use call-workflow and reference the reusable workflow as $repository/$path@$branch as can be seen below. 
The only other configuration that we need to add here is secrets: inherit , which allows the secrets to be reused within the same GitHub organization.
```
name: Renovate

on:
  workflow_dispatch:
    inputs:
      logLevel:
        description: "Override default log level"
        required: false
        default: "info"
        type: string
      overrideSchedule:
        description: "Override all schedules"
        required: false
        default: "false"
        type: string
  schedule:
    - cron: '30 4,6 * * *'

jobs:
  call-workflow:
    uses: superseb-demos/renovate-config/.github/workflows/renovate.yml@main
    with:
      logLevel: ${{ inputs.logLevel || 'info' }}
      overrideSchedule: ${{ github.event.inputs.overrideSchedule == 'true' && '{''schedule'':null}' || '' }}
    secrets: inherit
```


All of this configuration can be found in https://github.com/superseb-demos/renovate-workflow-preset-demo.


More tips and tricks
These are just miscellaneous things that I found/looked up while I was playing with this setup, it might benefit you as well.

Self documenting configuration

Renovate supports a description field where you can describe what the configuration is used for, this helps everyone reading the configuration to figure out what it is for, or why a specific decision was made. Another option is to use JSON5, which allows comments in JSON.

Find examples

Besides pretty extensive documentation with examples, there are also a lot of Renovate users which uses it publicly on GitHub. So GitHub Search is a good place to find some examples, but also the Renovate GitHub Discussions is a good source to find answers. Also look in Renovate’s own repositories to find good examples, like https://github.com/renovatebot/helm-charts/blob/main/renovate.json.

There are also a lot of default presets that you can use: https://docs.renovatebot.com/presets-default/

Grouping updates

Having pull requests created automatically is great, but you can make it more efficient when you group similar updates together. This not only reduces the “review load” for pull requests as there are just less pull requests to review, but also helps in the case where someone merges one pull request but forgets about the other, leaving the code-base with one updated reference and not the other. See https://docs.renovatebot.com/configuration-options/#groupname for more information.

Digest pinning

One of the best features in Renovate that I found is digest pinning. This allows, for example, to have the Docker tags updated but also pinned to it’s digest. The diff for the alpine Docker image would look like this;
```
-FROM alpine:3.16.2@sha256:1304f174557314a7ed9eddb4eab12fed12cb0cd9809e4c28f29af86979a3c870
+FROM alpine:3.16.3@sha256:3d426b0bfc361d6e8303f51459f17782b219dece42a1c7fe463b6014b189c86d
```
For GitHub Actions, it would look like this;
```
-       uses: actions/checkout@755da8c3cf115ac066823e79a1e1788f8940201b # v3.2.0
+       uses: actions/checkout@ac593985615ec2ede58e132d2e21d2b1cbd6127c # v3.3.0
```
Check each package manager for what is supported, but digest pinning is a major security win. And you don’t have to sacrifice readability this way.

See https://docs.renovatebot.com/docker/#digest-pinning for more information.

Custom version tags

Some components/tooling have very specific versioning schemes, sometimes this messes up the semver logic to determine if there is an update. If you need to modify the tag before it can be used, take a look at the extractVersion documentation: https://docs.renovatebot.com/configuration-options/#extractversion

Configure what versions to allow

If you want to limit what versions you want to update to, you can (amongst probably a dozen other options to do this) use allowedVersions or matchUpdateTypes to disable certain updates.
```
{
    "matchDepNames": ["alpine"],
    "matchUpdateTypes": ["major", "minor"],
    "enabled": false
}
```
Closing thoughts
The idea of this post is to not only learn some parts of Renovate and GitHub Actions, but also to show how you can change an implementation to need less maintenance over time. The use case for automating versions bumps is obvious, the work is not fun and why do it manually if it can be automated?

I hope you learned something about Renovate and GitHub Actions in this post, I will be posting more as I have a few more ideas how to create reports on the GitHub Actions workflow runs and how to control them centrally in case you want to. More steps towards a maintenance free setup, so keep an eye out for that.

Let me know if you have any questions!

Dependency Management
Automation
