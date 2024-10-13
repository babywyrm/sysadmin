
##
#
https://codepad.co/blog/renovate-vs-dependabot-dependency-and-vulnerability-management/
#
https://www.augmentedmind.de/2023/09/03/renovate-bot-advanced-tips-part-1/
#
https://www.augmentedmind.de/2023/07/30/renovate-bot-cheat-sheet/
#
https://github.com/renovatebot/github-action
#
##


![Screenshot 2024-10-13 at 3 12 31 PM](https://github.com/user-attachments/assets/e7f1c6ff-fc50-4bb4-a527-fff5fe0b1dda)




Renovate Bot: 3 advanced tips and tricks – Part I
2023-09-03 by Marius

![Screenshot 2024-10-13 at 3 06 05 PM](https://github.com/user-attachments/assets/a7c13ff2-6ce9-4461-aeb8-9e347b4c1a16)


This is part one of a two-part series that provides tips for advanced Renovate Bot users. Part 1 explains some important, basic concepts, illustrates how Renovate approaches creating and updating PRs as a flow chart, and goes into details about Renovate’s “post upgrade tasks” feature.
Table Of Contents
Introduction to Renovate Bot

Renovate (Bot) is a CLI tool that regularly scans your Git repositories for outdated dependencies. If it finds any, it automatically creates a pull request (PR) that updates the dependency. I highly recommend my Renovate Bot introduction article to get you started with the basics, and my cheat sheet article for the first steps regarding your configuration tuning.

This article targets Renovate users who already work with Renovate for a few days or weeks, and would like to know more about some of Renovate’s capabilities. It contains several lessons I learnt over the course of several years of using Renovate.
Tip 1: Check your understanding of basic concepts

    Understand which configuration options exist:
        Global configuration options: are configured by admins (e.g. you, if you self-host Renovate). They tell Renovate what to do for every repository. See the documentation for the complete list of options. I highly recommend you use the config.js file. It is easier to read than using environment variables or CLI arguments, and it lets you set secrets from environment variables (instead of hard-coding them as plain-text in a config.json file). The global configuration may also contain repository-specific configuration options (see next point).
        Repository-specific configuration options, stored in the renovate.json file in the repositories visited by Renovate, documented here. Most of the config options listed there may be placed on the root level of the renovate.json file, or in deeper levels, unless the config option has a parent defined explicitly (which is e.g. the case for packageRules or hostRules). For instance, you may place the description config option on any level in your JSON file, e.g. to document a configuration option.
        For each visited repository, Renovate performs a merge of the global and the repository-specific configuration automatically. As you would expect, options you set in the repository-specific configuration take precedence over global options.
    Understand the difference between managers and data sources:
        (Package) Managers (docs) are basically file parsers that find (pinned) dependencies in your repository. Each manager knows which files to look for (e.g. requirements.txt for pip_requirements), and can parse their internal structure, to identify dependencies.
        Data sources (docs) are basically (HTTP) clients that find the newest version for a specific dependency (that a manager found) in some (remote) repository (e.g. npmjs.org). A data source knows how to handle the API of that repository.
        Most managers use one specific data source. Some managers (e.g. helmfile) may use multiple data sources. Conversely, any specific data source may be used by one or more managers.

Tip 2: Handling of existing or missing PRs and branches

The following simplified pseudo-code and diagram explains what Renovate does when visiting your repository. Note that for the sake of simplicity, some advanced configuration options (e.g. scheduling) are not covered:
Renovate Bot Branch and PR handling

In more words:

    1) Renovate builds a list of all dependency updates it found in your repository, according to your renovate.json configuration (e.g. dropping those dependencies for which a packageRule sets the enabled: false option)
    2) If you configured the groupName option in one or more packageRules objects: Renovate aggregates the dependency updates found in step 1 to a smaller list of updates. The name of the dependency changes to <groupName>.
    3) For each dependency update:
        If Renovate finds an exactly-matching PR and branch that Renovate created in the past, where both the dependency name and the new version match (Renovate uses simple pattern matching, e.g. PR titles have the form “update dependency <dependency name> to <new version>“):
            If the matched PR is still open:
                If all commits in the corresponding branch are owned by Renovate:
                    If you enabled automerge using a packageRule matching this dependency update, and there are CI/CD pipelines defined, which have (now) passed: Renovate merges the PR for you
                    Else: Renovate leaves the PR and branch as-is
                If at least one commit was made by someone other than Renovate: Renovate leaves the PR and branch as-is. It assumes that you pushed commits that fix the branch, e.g. failing tests. Renovate avoids rebasing the branch, as this could mean that your commits are lost. Even if you configured automerge for this dependency update (and tests are now successful), Renovate will not merge this PR. It hands over all responsibility for that PR and branch to you.
            Else (the matched PR was closed by you, or merged): Renovate ignores this dependency. Renovate will only create a new PR+branch if the dependency’s new version is even newer than the version of the currently-matched PR/branch
        Else if Renovate finds a PR+branch that matches only regarding the dependency name, not the dependency version, which may be e.g. older in the PR:
            If the matched PR is still open:
                If all commits in the branch are owned by Renovate: Renovate “recycles” the matched outdated PR, by rebasing the corresponding branch, creating a new commit that contains the new version number of the dependency. Renovate also updates the PR’s title to contain the new version.
                If at least one commit was made by someone other than Renovate: Renovate leaves the PR and branch as-is. It assumes that you are fixing the branch, e.g. after tests have failed, and avoids rebasing the branch, as this could mean that your commits are lost.
            Else (the matched PR was closed by you, or merged): Renovate creates a new PR+branch for the dependency update
        Else (no matching PR was found): Renovate creates a new PR+branch for the dependency update
    4) For each PR in the repository not matched in step 3 that Renovate identifies as one of its own (considering the Git commit identity + SCM username):
        Renovate renames the PR title, by appending the string “ – autoclosed”
        Renovate closes the PR and deletes the corresponding branch

Typical reasons for step 4 are:

    You changed the Renovate config since the last run of Renovate. For instance, Renovate would auto-close PRs that Renovate used to find for NPM-related updates, because you added an object {"matchDatasources": ["npm"], “enabled”: false} to your packageRules object since the last time Renovate ran. Or maybe you added a new groupName package rule that bundles multiple dependencies whose PRs are now obsolete.
    A dependency is no longer found in your repository, e.g. if you removed a dependency from your package.json and yarn.lock file.
    Renovate was unable to find the newest version of a pinned dependency, because the registry was (temporarily) unreachable (e.g. because it was down, credentials have become invalid, etc.)

Make sure to also read https://docs.renovatebot.com/key-concepts/pull-requests/ for additional details.
Tip 3: Post upgrade tasks

If you are self-hosting a Renovate instance, you can use Renovate’s post upgrade tasks feature. A post upgrade task is an arbitrary shell command that Renovate runs right before creating the commit for the branch that updates the dependency. If the shell command modifies any files in your Git repository, you can (optionally) have Renovate commit them, along with the file Renovate would have committed anyway (where it updated the version number of the affected dependency).

Here are a few real-world examples where post upgrade tasks are useful:

    Sending a notification to some external system, e.g. via email or Slack
    Download source files of the dependency. For instance, suppose you use Renovate to update third party components installed via Helm into your Kubernetes cluster (e.g. Ingress NGINX). To increase the confidence that a new Helm chart version really does not break anything, the best way is to diff the old vs. new version of the Helm chart (particularly the values.yaml and the files in the chart’s templates folder). With a post upgrade task command such as “helm pull <chart URL or repo/chartname> --untar --untardir upstream-chart-info” you can tell Renovate to pull the Helm chart’s source and commit it into a dedicated folder (here: “upstream-chart-info“).
    Run a templating engine that generates files: especially in larger infrastructures, a platform engineering team might no longer write all those manifests that contain pinned dependencies (e.g. YAML files) by hand, but have them generated (e.g. with Terraform’s local_file, Cue, or Dhall) from a central file, because this facilitates the maintainability. Suppose these generated files are also committed to Git and that you have written a Regular Expression Manager to find updates in that central file (more details about regex managers in part 2 of this series). In such a scenario, it makes sense to have Renovate run the generation (templating engine) automatically in an post upgrade task.

While you could also define and run such automation tasks via other means, e.g. in a separate CI/CD job, the downside is that if such jobs modify the Git branches created by Renovate (with a committer identity different to the one used by Renovate), Renovate would no longer update the corresponding PRs and branches, because it (incorrectly) assumes that a user made some (manual) changes. A post upgrade task avoids this problem.

Using secrets in post upgrade tasks

Renovate runs the command of a post upgrade task in a new sub-shell that lacks any of the (Bash) environment variables you might have configured in the shell that runs Renovate in your self-hosted setup. If the command you define in a postUpgradeTasks object requires secrets/credentials, you need to use Renovate’s secrets feature: in your global configuration (config.js), you define a secrets object (with one or more key-value-pairs), which you then reference using the syntax {{ secrets.NAME_OF_SECRET }} inside your renovate.json in the command of your postUpgradeTasks object.
Conclusion

I hope the tips presented in this article help you get more out of Renovate. Especially tip #2 should help everyone on your team who is wondering when Renovate creates, deletes or updates PRs. Check out part 2 of this series, which is packed with even more tips.
Categories Renovate Bot, CI/CD, Development
Backup Docker volumes (and restore them) – done right
