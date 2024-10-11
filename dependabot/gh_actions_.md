
##
#
https://www.hacksoft.io/blog/managing-dependencies-with-github-dependabot-and-actions
#
https://dev.to/davorg/dependabot-and-github-actions-3lai
#
https://stackoverflow.com/questions/74996263/enable-github-dependabot-updates-for-actions-used-in-composite-actions
#
https://discourse.julialang.org/t/ci-on-github/112471/7
##



The problem
The problem here is at the 4th step.

We want dependencies to always be up to date with our default branch.

This is something that we can easily forget to do, since it needs to be done by hand.

Wouldn't it be nice if we can keep dependencies equal with the default branch without doing any extra manual actions?
GitHub Actions

Here is how we solved this. GitHub Actions is the tool that we're searching for!

    Heads up 👀 We have additional GitHub Actions related articles - GitHub Actions in action - Setting up Django and Postgres and Optimize Django build to run faster on GitHub Actions

Create a new workflow

To set up a new GitHub action, we need to add a new .yml file (we name it rebase_dependencies.yml) to our .github directory. It should be located in the workflows folder.

your_repository/
|-- .github/
|   |-- workflows/
|   |   | -- rebase_dependencies.yml
|   |-- dependabot.yml

Here is the content of your file:

```
name: Automatic Rebase
on:
  push:
    branches:
      - master
jobs:
  rebase:
    name: Rebase `dependencies` with `master`
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0 # otherwise, you will fail to push refs to dest repo
          ref: dependencies
      - run: |
          git config user.name github-actions
          git config user.email github-actions@github.com
          git rebase origin/master
          git push origin dependencies --force
```

Here is what this configuration means in simple words:

    When there is a new commit pushed to our default branch.
    Checkout to the dependencies branch
    Rebase it with latest from our default branch.
    Push it to the origin. We need --force because of the rebase

    It's fine if you prefer to use --force-with-lease to prevent from some unexpected outcomes.

    If you don't want to use the built-in github-actions user, you can add a new PAT and configure the action to work with the user that's associated with it.

You can refer to the docs of the actions/checkout base action if you want to change it to fit your needs. Here are the docs of GitHub Actions as well.

To assert that everything is fine with our new workflow, we can go to the Actions tab in the GitHub Repository. The name of the workflow ("Automatic Rebase") should be visible in the left sidebar:
