##
#
https://github.com/renovatebot/renovate/discussions/15366
#
##

How to access private npm registry with self-hosted bot #15366
 Answered by rarkins
alessandro-verdura-maersk asked this question in Request Help

alessandro-verdura-maersk
on Apr 28, 2022
Hello,
in our team we have set up a self-hosted renovate bot, and it's working pretty well, but I'm struggling to figure out how to make it access our private npm registry on Azure Artifacts.

What we would like ot have is to have this kind of set up working (based on Add hostRule to bots config):
```
// self-hosted bot config.js
module.exports = {
  // ...
  npmrcMerge: true,
  hostRules: [
    {
      hostType: 'npm',
      matchHost: 'https://<domain>/<path>/npm/',
      username: '__USER__',     // replaced with real value via GH action
      password: '__PASSWORD__', // replaced with real value via GH action
    }
  ],
};
// repository .github/renovate.json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:base"],
  "npmrcMerge": true,
  "packageRules": [
    // ...
  ]
}
```
# repository .npmrc
registry=https://<domain>/<path>/npm/registry/
always-auth=true
We would like this to work as we could store user and pwd in the bot's repo secrets and have then a GitHub action access them, something we could not do if we placed user and pwd in the repository config.

The above though doesn't work, and I tried so many different settings combinations (using token, using encrypted, placing the whole .npmrc string in the npmc property, etc) but with no avail. In the end I always get a "401 (Unauthorized)" on those private npm packages.

What I managed to get to work was to add an encrypted token to the repo config, but that's not our preferred setup because then we would have to do the encryption ourselves, store our own set of private and public keys, etc.

There must be something I'm missing, I'm sure!

Thanks a lot for your help!

Answered by rarkins
on Apr 29, 2022
You need to do this:

Settle on an approach which you think should be most likely to work
Provide logs/extensive details about the failures, including Renovate's debug logs prior to running npm
If you are trying dozens of different attempts, you may end up confusing yourself and us, so we need to settle on one.

I think that .nprmc with registry= line in the repo plus hostRules in config.js makes good sense.

View full answer 
Replies:1 comment · 3 replies

rarkins
on Apr 29, 2022
Maintainer
You need to do this:

Settle on an approach which you think should be most likely to work
Provide logs/extensive details about the failures, including Renovate's debug logs prior to running npm
If you are trying dozens of different attempts, you may end up confusing yourself and us, so we need to settle on one.

I think that .nprmc with registry= line in the repo plus hostRules in config.js makes good sense.

3 replies
@alessandro-verdura-maersk
alessandro-verdura-maersk
on Apr 29, 2022
Author
Thank you very much for your quick response!

So I did another test, this is my set up:

Self-hosted bot config.js
```
module.exports = {
  platform: 'github',
  logLevel: 'debug',
  onboardingConfig: {
    extends: ['config:base'],
  },
  repositories: ['<username>/renovate-bot-test'],
  branchPrefix: 'renovate/',
  username: '<username>',
  gitAuthor: '<author>',
  onboarding: true,
  printConfig: true,
  ignorePaths: [
    "**/node_modules/**",
    "**/bower_components/**",
    "**/vendor/**",
    "**/examples/**",
    "**/__tests__/**",
    "**/__fixtures__/**"
  ],
  npmrcMerge: true,
  hostRules: [
    {
      hostType: 'npm',
      matchHost: 'https://<domain>/<path>/npm/',
      username: '<npm-user>',
      password: '<base64-encoded-npm-password>',
    }
  ],
};
Repository .github/renovate.json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "dependencyDashboard": false,
  "prHourlyLimit": 10,
  "addLabels": ["dependencies"],
  "prCreation": "not-pending",
  "npmrcMerge": true,
  "packageRules": [
    // ....
  ],
  "extends": ["config:base"]
}

Repository .npmrc
registry=https://<domain>/<path>/registry/

always-auth=true
```

Please note that in my local machine I have this .npmrc in my /User/<username> folder, with the same password I put in the config.js, and I can successfully run npm i and fetch the private packages:
```
; begin auth token
//<domain>/<path>/npm/registry/:username=<npm-user>
//<domain>/<path>/npm/registry/:_password=<base64-encoded-npm-password>
//<domain>/<path>/npm/registry/:email=<npm-email>
//<domain>/<path>/npm/:username=<npm-user>
//<domain>/<path>/npm/:_password=<base64-encoded-npm-password>
//<domain>/<path>/npm/:email=<npm-email>
; end auth token
So anyway, this is the command that I run to test the bot locally (from https://jerrynsh.com/12-tips-to-self-host-renovate-bot/#how-to-run-renovate-locally):

docker run \                                                    
  --rm \
  -e LOG_LEVEL="debug" \
  -e RENOVATE_TOKEN="$RENOVATE_TOKEN" \
  -v "<local-path>/config.js:/usr/src/app/config.js" \
  renovate/renovate:"32.26.3" \
  --dry-run="true"
```
and in this gist you can see the sanitized output: https://gist.github.com/alessandro-verdura-maersk/2ac59e7baeba100d53bcdfb8f7b4998e

Thank you very much again!

@rarkins
rarkins
on Apr 29, 2022
Maintainer
The password in your hostRules should not be base64 encoded - Renovate will do that for you before inserting it into the .npmrc.

@alessandro-verdura-maersk
alessandro-verdura-maersk
on Apr 29, 2022
Author
The password in your hostRules should not be base64 encoded

🤦 That was it! It seems to be working fine on my test repo! Thank you very much for the great support!

