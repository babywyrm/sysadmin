

Upstream Sync Job


	- Runs before 2 AM.
	- Pulls upstream_images.yaml, extra_images.yaml, or any YAML in images/ from external sources into the monorepo.
2. 
Renovate Scan (2–4 AM)


	- Finds all matching files via fileMatch.
	- Extracts depName and currentValue with matchStrings.
	- Checks DockerHub for newer tags.
3. 
PR Creation


	- If updates found:
		- Updates the YAML files.
		- Runs python3 docker_file_generator.py to regenerate manifests.
		- Labels PR with docker-update and upstream-sync.
4. 
Merge PR


	- CI/CD builds/pushes updated images to internal registry.
	- Deploys to EKS.


[External Upstream Images]
       │ (1) Sync job: nightly/weekly
       ▼
[Monorepo: upstream_images.yaml, extra_images.yaml, ...]
       │ (2) Renovate scan (custom.regex)
       ▼
[Renovate Bot]
  - Detects newer tags in DockerHub
  - Opens PR with updated tags
  - Runs postUpgradeTasks (regen manifests)
       │ (3) Merge PR
       ▼
[CI/CD Pipeline]
  - Build/push to Internal Registry
       ▼
[EKS Cluster]
  - Deploy updated images



```

$schema: "https://docs.renovatebot.com/renovate-schema.json"

extends:
  - config:recommended

enabledManagers:
  - custom.regex

customManagers:
  - customType: regex
    # Match multiple upstream image files
    fileMatch:
      - "^upstream_images\\.yaml$"
      - "^extra_images\\.yaml$"
      - "^images/.*\\.yaml$"
    matchStrings:
      # Example format:
      # my-image:
      #   - 1.2.3
      - "(?<depName>[^:\\s]+?):\\s*?\\n\\s+?-\\s+(?<currentValue>[\\w.-]+)"
    datasourceTemplate: docker
    versioningTemplate: docker

packageRules:
  - matchDatasources:
      - docker
    automerge: false
    labels:
      - docker-update
      - upstream-sync
  - matchUpdateTypes:
      - major
    enabled: false
  - matchUpdateTypes:
      - minor
      - patch
    enabled: true

allowedPostUpgradeCommands:
  - ".*"

postUpgradeTasks:
  commands:
    - "python3 docker_file_generator.py"
  fileFilters:
    - "**/*"
  executionMode: branch

rangeStrategy: bump
separateMajorMinor: true
separateMinorPatch: true
prHourlyLimit: 5
schedule:
  - "after 2am and before 4am on every weekday"
postUpdateOptions:
  - yarnDedupeFewer

```

##
##


```
nginx:
  - 1.25.2
alpine:
  - 3.19.1
my-internal-tool:
  - 2.4.0
```
