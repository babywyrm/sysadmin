
##
#
https://falco.org/blog/falco-plugin-github/
#
##


Extended...

```
# Rule: Detect GitHub Actions Running Known Crypto Miners
- rule: Github Action with Miners
  desc: >
    A GitHub Action containing known crypto miners was executed.
    This rule checks the workflow run event for patterns matching miner binaries.
  condition: > 
    github.type=workflow_run 
    and github.workflow.has_miners=true
  output: > 
    Crypto miners were detected in a GitHub Action workflow.
    (repository=%github.repo repo_owner=%github.owner org=%github.org
    user=%github.user file=%github.workflow.filename workflow_name=%github.workflow.name
    url=%github.workflow.url)
  priority: CRITICAL
  source: github
  # Notes:
  # - `github.workflow.has_miners` scans the workflow definition file for known miner patterns.
  # - Extend miner patterns in the external configuration for flexibility.

# Rule: Detect Secrets Pushed to Public Repositories
- rule: Secret Pushed to Public Repository
  desc: >
    Detects when secrets (e.g., AWS keys, GitHub tokens) are committed to public repositories.
    Scans the diff of a push event for patterns indicating sensitive data.
  condition: >
    github.type=push 
    and github.repo.public=true
    and github.diff.has_secrets=true
  output: > 
    Secrets were committed to a public repository!
    (repository=%github.repo repo_owner=%github.owner org=%github.org 
    user=%github.user secret_types=%github.diff.committed_secrets.desc 
    files=%github.diff.committed_secrets.files lines=%github.diff.committed_secrets.lines 
    url=%github.diff.committed_secrets.links)
  priority: CRITICAL
  source: github
  # Notes:
  # - `github.diff.has_secrets` scans the diff for patterns of common secrets.
  # - Extend secret patterns via external configurations or plugins.
  # - Ensure `github.repo.public` explicitly checks visibility to reduce false positives.

# Rule: Repository Visibility Changed to Public
- rule: Private Repository Became Public
  desc: >
    Detects when a private GitHub repository becomes public, which could expose sensitive data.
  condition: >
    github.type=repository 
    and github.action=publicized
  output: > 
    A repository was made public:
    (repository=%github.repo repo_owner=%github.owner org=%github.org 
    user=%github.user timestamp=%time)
  priority: HIGH
  source: github
  # Notes:
  # - Triggers on the `publicized` action under the repository event type.
  # - This rule ensures no private repositories are accidentally exposed.

# Rule: Detect Repository Star Unusually High
- rule: Unusual Repository Stars
  desc: >
    Detects an unusual spike in repository stars, which could indicate a bot attack or unusual activity.
  condition: >
    github.type=repository 
    and github.repo.stars_delta > 100  # Adjust threshold as needed
  output: > 
    Repository experienced an unusual spike in stars:
    (repository=%github.repo repo_owner=%github.owner org=%github.org 
    stars_before=%github.repo.stars_before stars_after=%github.repo.stars_after 
    timestamp=%time)
  priority: MEDIUM
  source: github
  # Notes:
  # - `github.repo.stars_delta` calculates the change in stars during an event.
  # - Tune the threshold for your organization's typical traffic.

# Rule: Workflow Triggered by Suspicious External PR
- rule: Suspicious Workflow Triggered by PR
  desc: >
    Detects workflows triggered by pull requests from suspicious external users.
  condition: >
    github.type=pull_request 
    and github.pr.author_trust_level=low
    and github.workflow.triggered=true
  output: > 
    Workflow triggered by a suspicious pull request:
    (repository=%github.repo repo_owner=%github.owner org=%github.org 
    pr_url=%github.pr.url pr_author=%github.pr.author pr_author_trust_level=%github.pr.author_trust_level)
  priority: HIGH
  source: github
  # Notes:
  # - `github.pr.author_trust_level` categorizes PR authors based on their trustworthiness (e.g., bot accounts).
  # - Helps detect abuse by malicious actors submitting PRs to trigger workflows.

---

### Extensibility Considerations

1. **Custom Patterns**:
   - Store known miner patterns or sensitive data regex in an external file or centralized policy.
   - Load these patterns dynamically to adapt to new threats.

2. **Additional Fields**:
   - Leverage metadata like timestamps, IP addresses, or user agents for detailed monitoring.
   - Consider enriching `output` fields with contextual information (e.g., commit hashes).

3. **Tuning Priorities**:
   - Assign priorities based on the impact of a rule. For example:
     - CRITICAL: Miners, secrets, or publicized private repos.
     - HIGH: Suspicious PRs or large star spikes.
     - MEDIUM: Non-critical but unusual behavior (e.g., large commits).

4. **Error Handling**:
   - Add fallback logic in conditions for unexpected or malformed webhook events.

5. **Testing and Debugging**:
   - Use simulated GitHub webhooks for testing rules.
   - Implement logging for unmatched webhook events to fine-tune rules.


```
This set of rules provides a robust foundation for monitoring GitHub repositories while allowing for straightforward adaptation to emerging threats or organizational needs.

##
##

Using Falco to Protect Against the Three Biggest GitHub Security Risks
If you are reading this, your source code is likely your most important asset: not only it is at the base of the applications that power your business, but if you operate in the cloud, it’s also likely how you define and control your infrastructure. And, quite probably, your code is stored in one or more git repositories, hosted on GitHub.

As the home of such important assets, GitHub repositories should be at the top of your list of security priorities. However, based on my experience, many people fail to put in place even basic measures to protect source code repositories. This blog looks at three important threats to GitHub repos. You will learn what they are and how you can reliably detect them, as they happen, using the Falco open source security tool.

The three Biggest GitHub security risks
1. Pushing secrets into repos
If there was a competition for the worst thing that can happen to your team on GitHub, pushing secrets into repos would win first prize. No matter how disciplined one is with this, secrets (passwords, tokens, API keys, etc.) always find a way into repositories.

Case in point, I searched GitHub for “remove secret”. Among the results were 451K commits; the ones on top at the time of writing this article included examples like this one or this one. There are even research papers on how bad the phenomenon is!

Leaking secrets is of course a big deal when the repository is public, since hackers actively scan GitHub, hunting for any type of secrets that they can immediately take advantage of. However, secrets in private repositories are a major security threat as well, as they can be exploited for privilege escalation and lateral movement.

Protecting from secret leaks is not trivial for many reasons, such as:

in any team of non-negligible size, it is hard to control how each single member accesses git and what she commits. Even super useful tools like AWS’s git-secrets need to be installed on every client to be effective.
data cannot completely be deleted from git, so removed secrets still appear in the repository’s history.
This is why, despite the problem being well known, countless high-profile data breaches happened over the years because of secret leaks, including a very recent one at Toyota.

2. Crypto mining through GitHub Actions
GitHub Actions offer the ability to run arbitrary code in response to selected GitHub events (for example, merging a PR). They are a great way to extend code repositories with automation and integrations. GitHub Actions are executed by a computing pool provided by GitHub/Microsoft. Only problem: such a computing pool is also a juicy target for the bad guys trying to make a quick buck by mining bitcoin. This recent analysis by TrendMicro offers a good overview of the techniques used by attackers to deploy miners through GitHub Actions.

You might think that mining is mostly a problem for GitHub. They own preventing the bad guys from creating a huge number of repositories and abusing resources. However, this can quickly become your problem. For example, when someone uses a malicious action, importing it from an external source or the GitHub Marketplace. Note how malicious actors have been shown to inject mining actions into repositories by simply opening a PR. As shown here, in some cases the PR doesn’t even need to be approved for the action to run.

Running an action, according to the github pricing calculator, can cost you more than $300 per day, so a breach of this type can quickly cause your bill to explode.

3. Mistakenly publishing a private repository
Ahh, that feeling when you just realized that one of your team members has published the wrong repository (maybe one that includes your secrets!) and, by the time you find out, somebody has already forked it. I actually experienced that feeling once and, let me tell you, it’s very much not something I enjoyed.

Yes, GitHub gives you a warning and requires you to type the name of the repo. And yes, despite that, this still happens.

Detecting these three threats (and more!) using Falco
The three scenarios described above have one thing in common: they need to be detected quickly, very quickly, because the damage they cause grows exponentially with time. Fortunately, Falco can help! Falco is well known for its system calls-based runtime detection capabilities, and for its rich containers and Kubernetes support. Now, with the recently released GitHub plugin, Falco turns into a great tool to protect your code repositories. Falco was designed to work in real time, so it allows you to detect threats very quickly and respond accordingly.

How it works
Integrating Falco with GitHub is pretty straightforward, following the steps in the diagram below:

Diagram integrating Falco with GitHub

Falco is given a GitHub token. 
It uses the token to set up a webhook for each of the repositories that you specify. 
It then listens to every message sent by GitHub on those webhooks, filters and interprets the message’s data, and sends you meaningful alerts when something bad happens, in a matter of seconds. You can route these alerts to your favorite notification channels (email, Slack, a SIEM tool), or you can leverage them in a response engine to automatically remediate the issue.

Note Falco operates in true streaming fashion: it doesn’t copy, store or index any data. This makes it inexpensive, easy to run, and super responsive.

Unpacking Falco’s GitHub rules
Falco’s currently available GitHub rules can be found here. Here are, for example, the rules that detect the execution of an action with crypto miners:
```
- rule: Github action with miners
  desc: a github action containing crypto miners was executed
  condition: > 
    github.type=workflow_run and github.workflow.has_miners=true
  output: > 
    a github action containing crypto miners was executed
    (repository=%github.repo repo_owner=%github.owner org=%github.org
    user=%github.user file=%github.workflow.filename)
  priority: CRITICAL
  source: github
```

Note how the condition field filters for webhook messages of type workflow_run that point to the execution of miners. 
Github.workflow.has_miners is where the magic happens. It fetches the workflow’s definition file and scans it line by line, 
looking for patterns that identify the execution of one of the well known miner binaries.

For reference, here are the rules that detect the other two classes of threats described in this blog post:
```
- rule: Secret pushed into a public repository
  desc: A secret (AWS keys, github token...) was committed into a public repository
  condition: >
    github.type=push 
    and github.diff.has_secrets = true 
    and github.repo.public=true    
  output: > 
    One or more secrets were pushed into a private repository 
    (repository=%github.repo repo_owner=%github.owner org=%github.org 
    user=%github.user secret_types=%github.diff.committed_secrets.desc 
    file=%github.diff.committed_secrets.files 
    line=%github.diff.committed_secrets.lines 
    url=%github.diff.committed_secrets.links) 
  priority: CRITICAL
  source: github
- rule: Private Repository Becoming Public
  desc: Detect changing the visibility of a repository to public
  condition: > 
   github.type=repository and github.action=publicized
  output: > 
    A repository went from private to public 
    (repository=%github.repo repo_owner=%github.owner 
    org=%github.org user=%github.user) 
  priority: CRITICAL
  source: github
```


When the condition in one of the rules is met, Falco will send you a message formatted as specified by the output field, which includes a bunch of useful contexts. As you can see, these rules are very simple, which means it’s easy for you to customize them, or create new ones that fit your specific needs.

Where can you get started?
Instructions to get you up and running can be found in Falco’s plugins repository. The same page documents the list of fields you can use to create your own rules. If it all goes well, it will only take a few minutes for your repos to be protected, and for you to sleep well again!

As usual, if you have any feedback or need help, you can find us at any of the following locations.

Get started in Falco.org
Check out the Falco project on GitHub.
Get involved in the Falco community.
Meet the maintainers on the Falco Slack.
Follow @falco_org on Twitter.
