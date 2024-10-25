
##
#
https://utf9k.net/blog/renovate-golang-setup
#
##

Managing private Go repos with Renovate
July 23, 2024 · Around 11 minutes
🤔 I would probably change my mind if I started from scratch
As mentioned at the end of this post, most of this setup is a bit convoluted when compared to Renovate CE.

I don’t believe all of the options it has nowadays were available back when the setup below was configured but it may still be useful to someone who prefers a fully stateless setup.

I’m mainly pointing this out so you don’t start implementing things before reading the entire post.

Renovate is a handy tool for managing dependency updates, especially when you have many repositories. It supports a huge range of languages and allow for batching dependency updates together based on various rules.

Its main competition is Github’s own Dependabot but the rate of change is fairly slow compared to the break-neck pace of Renovate.

I’ll be assuming that you’re already interested in using Renovate however, and that you’re looking to self host it.

While I’ll be focusing on Go, most of this setup is language agnostic but with a few configuration bits to support Go in particular.

Picking a deployment
Personally, I found understanding the deployment options pretty confusing but there are essentially three options:

Renovate CLI: It’s a standalone CLI tool that can be installed on your host or run as a Docker image. It clones repositories onto disc (whether locally or a container volume) and uses locally installed language toolchains to perform upgrades. It’s also stateless.
Renovate Community Edition: Unlike the CLI, this is a long-lived server that can enqueue jobs received via webhook. It comes with a job scheduler but is stateful with all the hassle that includes.
Renovate Enterprise Edition: Same as the community edition but with more features and it costs enterprise bucks
The main axis of choice here are free/paid and stateless/stateful. There’s also the case that CE/EE receive updates every month or two, instead of multiple times a day like CLI.

The deployment I’ll be describing uses Renovate CLI via Docker but with some extra bootstrapping to make a pseudo-scheduler as well as webhook support.

Prerequisites
In order to get started, the main thing you’ll need is some form of service account for the platform of your choice.

You can read about the various options on the Renovate docs site..

For this case, I’ll be using a Github app as it offers the highest rate limit, compared to a personal access token.

Setting up our deployment
For Github usage, if you’re using a personal access token, you can just set RENOVATE_TOKEN as an environment variable for your container and call it a day.

Annoyingly, if we’re using a Github app, we need to do the magic ritual that exchanges our app credentials for an access token and there’s no way out of the box to do that with Renovate.

There are a few options suggested in the docs, which I believe is a new addition since I first set this all up but we’ll just throw together a bash script that’ll do the trick for us.

# <your-renovate-repo>/generate-jwt.sh
#!/usr/bin/env bash

# Adapted from https://gist.github.com/rajbos/8581083586b537029fe8ab796506bec3
```
set -euo pipefail # Do not set -x or we'll log out some secrets(!)

# Found under Github app settings
app_id=123456
install_id=123456
app_private_key="$RENOVATE_PRIVATE_KEY"

header='{
    "alg": "RS256",
    "typ": "JWT"
}'
payload_template='{}'

build_payload() {
        jq -c \
                --arg iat_str "$(date +%s)" \
                --arg app_id "${app_id}" \
        '
        ($iat_str | tonumber) as $iat
        | .iat = $iat
        | .exp = ($iat + 600)
        | .iss = ($app_id | tonumber)
        ' <<< "${payload_template}" | tr -d '\n'
}

b64enc() { openssl enc -base64 -A | tr '+/' '-_' | tr -d '='; }
json() { jq -c . | LC_CTYPE=C tr -d '\n'; }
rs256_sign() { openssl dgst -binary -sha256 -sign <(printf '%s\n' "$1"); }

algo=${1:-RS256}; algo=${algo^^}
payload=$(build_payload) || return
signed_content="$(json <<<"$header" | b64enc).$(json <<<"$payload" | b64enc)"
sig=$(printf %s "$signed_content" | rs256_sign "$app_private_key" | b64enc)
generated_jwt=$(printf '%s.%s\n' "${signed_content}" "${sig}")


# echo "Calling https://api.github.com/app/installations/$install_id/access_tokens"

tokens=$(curl -s -X POST \
    -H "Authorization: Bearer ${generated_jwt}" \
    -H "Accept: application/vnd.github.v3+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/app/installations/$install_id/access_tokens")

token=$(printf '%s' "$tokens" | jq ".token" | sed 's/"//g')

cat <<< "export RENOVATE_TOKEN=$token" > /tmp/renovate.key
```

Do note that this script is designed to be run inside of a container but I’ve used it locally on occasion for testing.

We’re going to use the provided Renovate docker image but we still need to wire up a custom entrypoint so our JWT is generated so let’s do that next.

# <your-renovate-repo>/bin/docker-entrypoint.sh

```
#!/usr/bin/env bash

set -eo pipefail

echo "Generating short-lived Github token for Renovate"

# Github app tokens are short lived, lasting for around an hour.
# As a result, we need to generate them on the fly.
# You may want to use a PAT locally however so we will honour any
# preset values for RENOVATE_TOKEN (via docker-compose)
if [[ -z "${RENOVATE_TOKEN}" ]]; then
    /usr/src/app/generate-jwt.sh
    # shellcheck source=/dev/null
    . /tmp/renovate.key
    rm /tmp/renovate.key
fi

if [[ -f "/usr/local/etc/env" && -z "${CONTAINERBASE_ENV+x}" ]]; then
    # shellcheck source=/dev/null
  . /usr/local/etc/env
fi

if [[ "${1:0:1}" = '-' ]]; then
  # assume $1 is renovate flag
  set -- renovate "$@"
fi

if [[ ! -x "$(command -v "${1}")" ]]; then
  # assume $1 is a repo
  set -- renovate "$@"
fi

exec dumb-init -- "$@"
```
Everything below the Renovate token is the remainder entrypoint that comes by default within the Renovate Docker image and we’ve just inserted our script to generate our shortlived JWT is all.

Building our core Renovate config
This is the central configuration file that defines most of the behaviours that we want Renovate to follow.

Customising this is up to you but here’s an example config to give you an idea:
```
// <your-renovate-repo>/config.js
module.exports = {
    addLabels: ["dependencies"], // adds a github label
    autodiscover: true, // scans github for repos
    autodiscoverFilter: ["sausagedoglikers/*"], // only checks for repos in the github repo called sausagedoglikers
    binarySource: "install", // default to installing language runtimes instead of 
    gitAuthor: "Renovate <appid+renovate[bot]@users.noreply.github.com>", // a fake github user for the bot to commit under
    hostRules: [
        {
            hostType: "gomod",
            matchHost: "https://github.com/", // prefer using https with a token over ssh to transparently pull go libraries from private repos (from renovate's pov) + avoids GOPRIVATE fiddling
            token: process.env.RENOVATE_TOKEN
        },
        {
            hostType: "github-tags",
            matchHost: "https://github.com/",
            token: process.env.RENOVATE_TOKEN
        }
    ],
    logFile: "/tmp/renovate.log"
    logFileLevel: "debug",
    onboarding: false, // automatically create prs instead of asking users to onboard
    platform: "github", // your platform of choice
    requireConfig: "required", // don't run on repos that don't have an explicit renovate.json config (unless onboarding is enabled)
    username: "renovate[bot]", // a fake username to commit under
}
```

Now all we need to do is package it up into a nice dockerised deployment.

# <your-renovate-repo>/Dockerfile
```
# You might pin this image. It's up to you since it uses a rolling release model with patches daily.
FROM renovate/renovate

# I don't actually know if this is needed anymore. One early variation involved passing in an SSH key directly
# which isn't needed anymore so this can probably be removed but I can't be bothered to test it out.
RUN git config --global --add safe.directory "*"

COPY config.js /usr/src/app/config.js

COPY generate-jwt.sh /usr/src/app/generate-jwt.sh

COPY bin/ /usr/local/bin
We’ll throw in a docker-compose.yml for good measure too so it can be run locally with minimal setup:

version: '3'
services:
  renovate:
    build: .
    environment:
      - RENOVATE_PRIVATE_KEY # Github key -> run `export RENOVATE_PRIVATE_KEY=$(cat renovate.priv.pem)` or whatever you named the file
      - RENOVATE_TOKEN # Generated at runtime
      - LOG_LEVEL
    volumes:
      - /tmp:/tmp:rw
```

With all this set up, we have a Dockerfile that should automatically scan all of our relevant Github repos when started and it’ll run until all repositories have been processed.

While this process is stateless, the generated pull requests containing dependencies do act as a type of state in themselves where existing PRs will be pushed to if further updates are found, rather than Renovate completely forgetting and making a new PR.

We’ll come back to the deployment process shortly to talk about different strategies of running the above.

Setting up repositories
Now that we have a deployment of Renovate that we can use, we need to take a quick detour to set up a Renovate configuration file in a repo.

The most common type of configuration is just having all of the settings defined directly in each repository, by way of a renovate.json file.

Here’s an example within the Renovate repo itself: renovate.json.

A nice middle ground between giving developers extension support, while being able to centrally manage presets is having lightweight pointers to your core Renovate repo like so:
```
// <some-repo>/renovate.json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "local>sausagedoglikers/<your-renovate-repo>//presets/default"
  ]
}

// <your-renovate-repo>/presets/default.json
{
    "$schema": "https://docs.renovatebot.com/renovate-schema.json",
    "extends": [
      ":automergeDisabled",
      ":disableDigestUpdates",
      ":separateMultipleMajorReleases",
      ":disableMajorUpdates"
    ],
    "enabledManagers": [
      "gomod"
    ]
    // the rest of your settings
}
```

I find that a nice balance is batching patch releases while splitting minor and above but this all depends on your risk appetite and adherence to semver of course.

For Go users, here’s an example config focused on splitting (and batching) different Go libraries into PRs:
```
{
    "$schema": "https://docs.renovatebot.com/renovate-schema.json",
    // extends etc etc...
    "packageRules": [
      {
        "enabled": false,
        "matchPackagePatterns": [
          ".*"
        ],
        "excludePackagePatterns": [
          "github.com/sausagedoglikers/.*" // only open prs for internal libraries to avoid mess and noise
        ]
      },
      {
        "enabled": false,
        "matchPackagePatterns": [
          "github.com/sausagedoglikers/fastrepo/.*" // disable fast moving libraries ie; ones with generated code that release many times a day
        ]
      },
      {
        "matchPackagePatterns": [
          "github.com/sausagedoglikers/.*"
        ],
        "schedule": [
          "every weekend" // for libraries that qualify, only open prs on weekends to reduce daily noise
        ]
      },
      {
        "groupName": "blah",
        "groupSlug": "blah",
        "matchPackagePatterns": [
          "github.com/sausagedoglikers/blah",
          "github.com/sausagedoglikers/blah/v2"
        ],
        "schedule": [
          "at any time" // anytime a version of the blah library is released, instantly open a pr instead of waiting (you might be rolling out a hotfix for example)
        ]
      },
      {
        "groupName": "all patch dependencies",
        "groupSlug": "all-patch",
        "matchPackagePatterns": [
          "github.com/sausagedoglikers/.*"
        ],
        "matchUpdateTypes": [
          "patch" // group all library updates that have a patch release upgrade together
        ]
      }
    ],
    "platformCommit": true // push via the github rest apis instead of trying to do an http/ssh commit (pretty important!)
  }
```


Actually running the thing
I won’t be going into huge detail here but one strategy that works well is running the container as a scheduled task.

The proper schedule really depends on how many repos you have, how many libraries are being upgraded and so on.

If you schedule the task too often, you might not finish running a full end to end upgrade.

If you take too long however, you might find that your generated token (ie; github app short lived token) ends up expiring.

You might want to look into repository caching if you start running into scans that run for too long.

Alternatively, running as a scheduled job might not be the way to go and you should look into the long-lived Renovate CE instead.

Adding reactivity
One element of Renovate that our setup doesn’t support is the ability to retry or rebase a PR.

You can see an example on this PR where there is a checkbox that would trigger a rebase in short time if it were ticked.

If you’re using Github, you might consider setting up a bit of infrastructure that receives webhooks on issue change, as ticking a checkbox is considered a particular type of event.

You can also listen for pushes and check that the contents involve changes to go.mod or whatever your relevant dependency file is for your tracked languages.

Once those events are received and parsed, you might then trigger off a one-off instance of the container we set up to run that’s scope to just the repository that had the update.

You can essentially invoke the container do that like so:
```
docker run -e RENOVATE_AUTODISCOVER=false RENOVATE_REPOSITORIES="['sausagedoglikers/mycoolrepo']" <renovate-container>
```
If you’re running in the cloud, you might invoke your cloud scheduler to spin up an instance of your renovate task with those environmental overrides applied on top.

Advice for new starters
Given all the above, if I were to start again today, I’d probably consider Renovate CE given it appears to do all of the Github app token generation for you, as well as having endpoints for queuing tasks.

All of the above does still work, and there are some nice benefits to the stateless model I think if you really do need it.

For most self-hosted cases, running a long-lived variant is probably fine.

It seems that a bunch of work has been done earlier this year to make some endpoints available in CE that were previously enterprise only as well.
