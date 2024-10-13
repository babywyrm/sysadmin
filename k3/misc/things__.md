k3s-kk.sh

##
#
https://gist.github.com/brandond/5346acc3108b489fa2208b4eab4a1738
#
##

```
#!/bin/bash


# This script assumes a couple things:
# * you have a copy of kubernetes/kubernetes checked out to $GOPATH/src/github.com/kubernetes/kubernetes
# * you have a copy of k3s-io/k3s checked out to $GOPATH/src/github.com/k3s-io/k3s
# * the repos listed above have an origin named ${USER} (your login) that points to your personal fork of that repo
# * the repos listed above have an origin named k3s-io that points to the k3s-io fork of that repo
# * the kubernetes repo has an origin that points at the kubernetes upstream (doesn't matter what it's called)

set -euxo pipefail
export REMOTE="${USER}"
export K3S_REMOTE="${K3S_REMOTE=-k3s-io}"
#export GONOSUMDB="github.com/${REMOTE}/*"
#export GONOPROXY="${GONOSUMDB}"

if [ -z "${GOPATH}" ]; then
  export GOPATH=$(go env GOPATH)
fi

pushd ${GOPATH}/src/github.com/kubernetes/kubernetes
git fetch --all --tags
popd

if [ $REMOTE = "k3s-io" ] || [ $REMOTE = "rancher" ] || [ $REMOTE = "upstream" ] || [ $REMOTE = "origin" ]; then
  echo "ERROR: will not run against remote ${REMOTE}"
  exit 1
fi

pushd ${GOPATH}/src/github.com/k3s-io/k3s
git fetch --all --tags
popd

for RELEASE in ${RELEASE_LIST:-v1.19 v1.20 v1.21 v1.22}; do
  pushd ${GOPATH}/src/github.com/kubernetes/kubernetes
  NEWTAG=`git tag --sort=creatordate -l ${RELEASE}.\* | grep -Ev "${RELEASE_EXCLUDE:-k3s|alpha|beta|rc}" | tail -n 1`
  echo ${NEWTAG} | awk 'match($0, /v([0-9]+)\.([0-9]+)\.([0-9]+)(.*)/, v) {print v[1] " " v[2] " " v[3] " " v[4]}' | while read MAJOR MINOR PATCH META; do
    if [ -n "${FROM_RC:-}" ]; then
      META=""
    fi
    NEWVERSION="v${MAJOR}.${MINOR}.${PATCH}${META}"
    OLDPATCH="${PATCH}"

    if [ -n "${META}" ]; then
      NUM=$(grep -Eo '[[:digit:]]+$' <<<"${META}")
      let NUM-- || true
      META=$(sed -E "s/[0-9]+/${NUM}/" <<<"${META}")
      OLDVERSION="v${MAJOR}.${MINOR}.${OLDPATCH}${META}"
    else
      while [ "${OLDPATCH}" -ge "0" ]; do
        OLDVERSION="v${MAJOR}.${MINOR}.${OLDPATCH}${META}"
        if [ ! -z "$(git ls-remote --tags ${K3S_REMOTE} refs/tags/${OLDVERSION}-k3s1)" ]; then
          break
        fi
        let OLDPATCH-- || true
      done

      if [ "${OLDPATCH}" -lt "0" ]; then
        echo -e "\n===\nERROR: Unable to find previous release of ${RELEASE} in k3s-io/kubernetes\n===\n"
        sleep 5
        break
      fi
    fi

    echo -e "\n===\nCreating ${NEWTAG}-k3s1 by rebasing ${OLDVERSION}...${OLDVERSION}-k3s1 onto ${NEWTAG}\n===\n"
    sleep 5

    if [ "${NEWTAG}" != "${OLDVERSION}" ] && [ -z "${SKIP_KUBERNETES:-}" ]; then
      git reset --hard || true
      git rebase --abort || true
      rm -fr ".git/rebase-apply" || true
      git clean -xfd || true
      git checkout k3s-io/master &> /dev/null
      git tag -l | grep ${NEWTAG}-k3s1 | awk  '{print "+:refs/tags/" $1}' | xargs -tr git push ${REMOTE} || true
      git tag -l | grep ${NEWTAG}-k3s1 | xargs -tr git tag -d || true
      git rebase --onto refs/tags/${NEWTAG} refs/tags/${OLDVERSION} refs/tags/${OLDVERSION}-k3s1~1
      GOVERSION=$(yq e '.dependencies[] | select(.name == "golang: upstream version").version' build/dependencies.yaml)
      GOIMAGE="golang:${GOVERSION}-alpine3.15"
      echo -e "FROM ${GOIMAGE}\nRUN apk add --no-cache bash git make tar gzip curl git coreutils rsync alpine-sdk" | docker build -t ${GOIMAGE}-dev -
      GOWRAPPER="docker run --rm -u $(id -u) --mount type=tmpfs,destination=${GOPATH}/pkg --mount type=tmpfs,destination=/home/go -v ${GOPATH}/src:${GOPATH}/src -v ${GOPATH}/.cache:${GOPATH}/.cache  -v ${HOME}/.gitconfig:/home/go/.gitconfig -e HOME=/home/go -e GOCACHE=${GOPATH}/.cache -w ${PWD} ${GOIMAGE}-dev"
      $GOWRAPPER ./tag.sh ${NEWTAG}-k3s1 2>&1 | tee ~/tags-${NEWTAG}-k3s1.log
      grep -F 'git push' ~/tags-${NEWTAG}-k3s1.log | awk '{print "refs/tags/" $4}' | xargs -tr git push $REMOTE --force
      echo -e "\n\===\nKubernetes tag push steps recorded to ~/tags-${NEWTAG}-k3s1.log\n===\n"
    fi

    continue
    echo -e "\n===\nPreparing k3s updates for ${NEWVERSION}-k3s1\n===\n"

    MESSAGE="Update Kubernetes to ${NEWVERSION}-k3s1"
    if [ "${NEWVERSION}" != "${NEWTAG}" ]; then
      MESSAGE="${MESSAGE} (from ${NEWTAG})"
    fi
    pushd ${GOPATH}/src/github.com/k3s-io/k3s
    git push ${REMOTE} :refs/tags/${NEWVERSION}-k3s1 || true
    git reset --hard || true
    git rebase --abort || true
    rm -fr ".git/rebase-apply" || true
    git clean -xfd || true
    git checkout k3s-io/master &> /dev/null
    git branch -D ${NEWVERSION}-k3s1 || true
    git checkout -B ${NEWVERSION}-k3s1 k3s-io/release-${MAJOR}.${MINOR} || git checkout -B ${NEWVERSION}-k3s1 k3s-io/master
    mkdir -p build/data
    DRONE_TAG="${OLDVERSION}-k3s1" ./scripts/download
    GOVERSION=$(go mod edit --json | jq -r '.Go')
    GOIMAGE="golang:${GOVERSION}-alpine3.15"
    echo -e "FROM ${GOIMAGE}\nRUN apk add --no-cache bash git make tar gzip curl git coreutils rsync alpine-sdk" | docker build -t ${GOIMAGE}-dev -
    GOWRAPPER="docker run --rm -u $(id -u) --mount type=tmpfs,destination=${GOPATH}/pkg --mount type=tmpfs,destination=/home/go -v ${GOPATH}/src:${GOPATH}/src -v ${GOPATH}/.cache:${GOPATH}/.cache -v ${HOME}/.gitconfig:/home/go/.gitconfig -e HOME=/home/go -e GOCACHE=${GOPATH}/.cache -w ${PWD} ${GOIMAGE}-dev"
    $GOWRAPPER go generate
    sed -Ei "\|github.com/k3s-io/kubernetes| s|${OLDVERSION}-k3s1|${NEWTAG}-k3s1|" go.mod vendor/modules.txt
    sed -Ei "s|github.com/k3s-io/kubernetes|github.com/${REMOTE}/kubernetes|" go.mod vendor/modules.txt
    sed -Ei "s|k8s.io/kubernetes v\S+|k8s.io/kubernetes ${NEWTAG}|" go.mod vendor/modules.txt
    sed -Ei "s|k8s.io/(\S+) v0.[1-9]+\S+|k8s.io/\1 ${NEWTAG/v1/v0}|" go.mod vendor/modules.txt
    $GOWRAPPER sh -c "go mod vendor && go mod tidy"
    git add go.mod go.sum vendor/
    git status
    git commit --signoff -a -m "${MESSAGE}"
    git push --force --set-upstream ${REMOTE} ${NEWVERSION}-k3s1
    popd

    echo -e "\n===\nDone - you may now put in a pull request against release-${MAJOR}.${MINOR} from ${REMOTE}/${NEWVERSION}-k3s1\n===\n"
    sleep 5

  done
  popd
done
k3s-modsync.sh
#!/bin/bash

K8S_REPO="kubernetes/kubernetes"
if [ -z "${K8S_COMMIT}" ]; then
  K8S_REPLACE=$(go mod edit --json | jq -r '.Replace[] | select(.Old.Path | contains("k8s.io/kubernetes")) | .New.Path + " " + .New.Version')
  if [ -n "${K8S_REPLACE}" ]; then
    read K8S_REPO K8S_VERSION <<< ${K8S_REPLACE#github.com/}
  else
    K8S_VERSION=$(go mod edit --json | jq -r '.Require[] | select(.Path | contains("k8s.io/kubernetes")) | .Version')
  fi
  echo "Updating go.mod replacements from ${K8S_REPO} ${K8S_VERSION}"
  K8S_COMMIT=$(grep -oE '\w{12}$' <<< ${K8S_VERSION})
  if [ -z "${K8S_COMMIT}" ]; then
    K8S_COMMIT=${K8S_VERSION}
  fi
else
  echo "Updating go.mod replacements from ${K8S_REPO} ${K8S_COMMIT}"
fi

K8S_GO_MOD=$(curl -qsL "https://raw.githubusercontent.com/${K8S_REPO}/${K8S_COMMIT}/go.mod")

# update replacements
while read OLDPATH NEWPATH VERSION; do
  REPLACEMENT=$(go mod edit --json /dev/stdin <<<${K8S_GO_MOD} | jq -r --arg OLDPATH "${OLDPATH}" '.Replace[] | select(.Old.Path==$OLDPATH) | .New.Version')
  echo "Checking for updates to ${OLDPATH} ${VERSION} -> ${REPLACEMENT}"
  if [ -n "${REPLACEMENT}" ] && [ "${REPLACEMENT}" != "null" ] && grep -vq k3s <<<${NEWPATH} && semver-cli greater ${REPLACEMENT} ${VERSION} ; then
    (set -x; go mod edit --replace="${OLDPATH}=${NEWPATH}@${REPLACEMENT}")
  fi
done <<< $(go mod edit --json | jq -r '(.Replace[] | .Old.Path + " " + .New.Path + " " + .New.Version)')

#go mod tidy
rke2-bump-golang.sh
#!/usr/bin/env bash

REPOS=$(curl -s 'https://raw.githubusercontent.com/rancher/rke2/master/developer-docs/image_sources.md' | grep -E 'rancher/(hardened-build-base|rke2)' | awk -F '|' '{print $4}' | xargs -n1 echo | sort | uniq)
REPO_BASE=$(go env GOPATH)/src/github.com

for REPO in ${REPOS}; do
  if [[ ! -d ${REPO_BASE}/${REPO} ]]; then
    pushd $(dirname ${REPO_BASE}/${REPO}) || continue
    git clone -o rancher git@github.com:${REPO}.git
    popd
  fi

  pushd ${REPO_BASE}/${REPO} || continue
  gh repo fork ${REPO} --clone=false
  git remote add brandond git@github.com:${REPO/rancher/brandond}.git
  git fetch --all

  BRANCH="master"
  if [[ -z "$(git branch -a --list rancher/${BRANCH})" ]]; then
    BRANCH="main"
  fi
  if [[ "${REPO}" == "rancher/ingress-nginx" ]]; then
   BRANCH="hardened-nginx-1.0.x-fix"
  fi

  git reset --hard rancher/${BRANCH} || true
  git checkout -B bump_golang rancher/${BRANCH}

  FILES=$(grep -rlF 'hardened-build-base' | grep -vF .git)
  for FILE in ${FILES}; do
    sed -Ei 's/v1\.16\.[[:alnum:]]+/v1\.16\.10b7/; s/v1\.15\.[[:alnum:]]+/v1\.15\.15b5/' ${FILE}
    git add ${FILE}
  done

  sed -Ei 's/hardened-build-base:[[:alnum:].]+/hardened-build-base:v1\.16\.10b7/' .drone.yml
  git add .drone.yml

  git commit -sm 'Bump golang versions'
  git push --set-upstream brandond --force-with-lease

  echo -e "\n\nhttps://github.com/${REPO}/compare/${BRANCH}...brandond:bump_golang?expand=1\n\n"

  popd
done
rke2-bump-tag.sh

```
##
##
```

#!/usr/bin/env bash
set -e
set -o noglob

ORIGIN="${ORIGIN:-rancher}"
USERNAME="${USERNAME:-${USER}}"
REPOS=$(curl -s 'https://raw.githubusercontent.com/rancher/rke2/master/developer-docs/image_sources.md' | grep -E 'rancher/hardened-build-base' | awk -F '|' '{print $4}' | xargs -n1 echo | sort | uniq)
REPO_BASE=$(go env GOPATH)/src/github.com

print() {
  echo -e "\033[0;32m$@\033[0m" >&2
}

for REPO in ${REPOS}; do
  if [[ ! -d ${REPO_BASE}/${REPO} ]]; then
    pushd $(dirname ${REPO_BASE}/${REPO}) || continue
    git clone -o ${ORIGIN} git@github.com:${REPO}.git
    popd
  fi

  pushd ${REPO_BASE}/${REPO} || continue
  git fetch --prune --force ${ORIGIN} '+refs/tags/*:refs/tags/*'

  BRANCH="master"
  if [[ -z "$(git branch -a --list ${ORIGIN}/${BRANCH})" ]]; then
    BRANCH="main"
  fi
  if [[ "${REPO}" == "rancher/ingress-nginx" ]]; then
   BRANCH="hardened-nginx-1.0.x-fix"
  fi

  git reset --hard ${ORIGIN}/${BRANCH} || true
  git checkout -B ${BRANCH} ${ORIGIN}/${BRANCH}

  DATE=$(TZ=utc date '+-build%Y%m%d')
  HEAD_COMMIT=$(git rev-parse "${ORIGIN}/${BRANCH}")
  HEAD_MESSAGE=$(git show --quiet "${HEAD_COMMIT}")
  PREVIOUS_COMMIT=$(git rev-list --tags --max-count=1)
  PREVIOUS_TAGS=$(git tag --contains ${PREVIOUS_COMMIT})

  if [[ "${HEAD_COMMIT}" == "${PREVIOUS_COMMIT}" ]]; then
    print "\nMost recent commit to ${BRANCH} on ${REPO} is already tagged:\n${PREVIOUS_TAGS}\n"
    sleep 5
    popd
    continue
  fi

  print "\nMost recent tags for ${REPO}:\n${PREVIOUS_TAGS}"
  print "\nHead of ${BRANCH} is:\n---\n${HEAD_MESSAGE}\n---\n"

  for OLD_TAG in ${PREVIOUS_TAGS}; do
    TAG=${OLD_TAG/-build*/${DATE}}

    if [[ "${TAG}" == "${OLD_TAG}" ]]; then
      print "\nTag ${TAG} already exists; run the following command to delete:\ngit push ${ORIGIN} :refs/tags/${TAG}\n"
      sleep 5
      continue
    fi

    print "Creating new tag ${TAG} from commit ${HEAD_COMMIT}"
    read -p 'Continue? [y/n]: ' CONTINUE
    if [[ "${CONTINUE}" == "y" ]]; then
      git tag "${TAG}" "${HEAD_COMMIT}" && git push ${ORIGIN} "refs/tags/${TAG}" || true
    fi
  done

  popd
done
rke2-releases.sh
#!/usr/bin/env bash
set -e
set -o noglob

ORIGIN="${ORIGIN:-rancher}"
USERNAME="${USERNAME:-${USER}}"

print() {
  echo -e "\033[0;32m$@\033[0m" >&2
}

do_kube_proxy() {
  local VERSION="$1"
  local TAG="$2"
  if [[ -z "${TAG}" ]]; then
    print "Error: no hardened-kubernetes tag provided"
    return
  fi

  pushd "$(go env GOPATH)/src/github.com/rancher/rke2-charts" 1>/dev/null
  git fetch "${ORIGIN}"
  git reset --hard &>/dev/null || true
  git rebase --abort &>/dev/null || true
  git clean -xffd &>/dev/null || true
  git checkout -B "bump_rke2-kube-proxy-${VERSION}" "${ORIGIN}/main-source" &>/dev/null

  PACKAGE="rke2-kube-proxy-${VERSION}"
  APP_VERSION="$(cut -d- -f1-2 <<< "${TAG}")"

  sed -Ei "s/version: .*/version: ${TAG}/" "packages/${PACKAGE}/charts/Chart.yaml"
  sed -Ei "s/appVersion: .*/appVersion: ${APP_VERSION}/" "packages/${PACKAGE}/charts/Chart.yaml"
  sed -Ei "s/tag: .*/tag: ${TAG}/" "packages/${PACKAGE}/charts/values.yaml"
  sed -Ei "s/packageVersion: .*/packageVersion: 01/" "packages/${PACKAGE}/package.yaml"

  git add "packages/${PACKAGE}"
  git commit -sm "Bump ${PACKAGE} to ${TAG}"
  git push --set-upstream "${USERNAME}" --force-with-lease

  popd 1>/dev/null
}

do_hardened_kubernetes() {
  local TAG="$1"
  if [[ -z "${TAG}" ]]; then
    print "Error: no hardened-kubernetes tag provided"
    return
  fi

  APP_VERSION="$(cut -d- -f1-2 <<< "${TAG}")"

  pushd "$(go env GOPATH)/src/github.com/rancher/image-build-kubernetes" 1>/dev/null
  git fetch "${ORIGIN}"

  EXISTING_TAG="$(git tag -l "${APP_VERSION}-build*" | tail -n 1)"
  HEAD_COMMIT=$(git rev-parse --short "${ORIGIN}/master")
  HEAD_MESSAGE=$(git show --quiet "${HEAD_COMMIT}")

  print "\nHead of ${BRANCH} is:\n---\n${HEAD_MESSAGE}\n---\n"

  if [[ -z "${EXISTING_TAG}" ]]; then
    print "Creating new tag ${TAG} from commit ${HEAD_COMMIT}"
    read -p 'Continue? [y/n]: ' CONTINUE
    if [[ "${CONTINUE}" == "y" ]]; then
      git tag "${TAG}" "${HEAD_COMMIT}" && git push "${ORIGIN}" "refs/tags/${TAG}"
    fi
    echo "${TAG}"
  else
    print "Using existing tag ${EXISTING_TAG}"
    echo "${EXISTING_TAG}"
  fi

  popd 1>/dev/null
}

do_release_packaging() {
  local BRANCH="$1"
  local CHANNEL=$2
  print "\nDoing packaging for ${BRANCH} in ${CHANNEL}"
  pushd "$(go env GOPATH)/src/github.com/rancher/rke2" 1>/dev/null

  git fetch --prune --prune-tags --force "${ORIGIN}"

  TAG=$(git tag --merged "${ORIGIN}/${BRANCH}" --sort -committerdate | head -n1)
  print "Checking artifacts for ${TAG}"
  if ! curl -sfIo /dev/null "https://github.com/rancher/rke2/releases/download/${TAG}/sha256sum-amd64.txt"; then
    print "ERROR: Release artifacts for ${TAG} do not exist"
    return
  fi

  pushd "$(go env GOPATH)/src/github.com/rancher/rke2-packaging" 1>/dev/null

  git fetch --prune --prune-tags --force "${ORIGIN}"

  PACKAGING_TAG="${TAG}.${CHANNEL}.0"

  if [[ "$(git tag -l "${PACKAGING_TAG}" | wc -l)" -gt "0" ]]; then
    print "Packaging already tagged for ${PACKAGING_TAG}"
    return
  fi

  HEAD_COMMIT=$(git rev-parse --short "${ORIGIN}/master")
  HEAD_MESSAGE=$(git show --quiet "${HEAD_COMMIT}")

  print "\nHead of ${BRANCH} is:\n---\n${HEAD_MESSAGE}\n---\n"

  print "Creating new tag ${PACKAGING_TAG} from commit ${HEAD_COMMIT}"
  read -p 'Continue? [y/n]: ' CONTINUE
  if [[ "${CONTINUE}" == "y" ]]; then
    git tag "${PACKAGING_TAG}" "${HEAD_COMMIT}" && git push "${ORIGIN}" "refs/tags/${PACKAGING_TAG}"
  fi

  popd 1>/dev/null

  popd 1>/dev/null
}

do_release_tag() {
  local BRANCH="$1"
  local BUMP_TYPE=$2
  print "\nDoing release for ${BRANCH}"
  pushd "$(go env GOPATH)/src/github.com/rancher/rke2" 1>/dev/null

  git fetch --prune --prune-tags --force "${ORIGIN}"

  TAG=$(git tag --merged "${ORIGIN}/${BRANCH}" --sort -committerdate | head -n1)
  if [[ "${TAG}" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)([-+][a-zA-Z0-9]+)?([-+]rke2r[0-9]+)$ ]]; then
    MAJOR=${BASH_REMATCH[1]}
    MINOR=${BASH_REMATCH[2]}
    PATCH=${BASH_REMATCH[3]}
    RC=${BASH_REMATCH[4]}
    RKE2_PATCH=${BASH_REMATCH[5]}
    print "TAG=${TAG} parsed as MAJOR=${MAJOR} MINOR=${MINOR} PATCH=${PATCH} RC=${RC} RKE2_PATCH=${RKE2_PATCH}"
  else
    print "Couldn't match ${TAG}"
    return
  fi

  COMMIT_TARGET="${ORIGIN}/${BRANCH}"

  if [[ "${BUMP_TYPE}" == "patch" ]]; then
    print "Incrementing PATCH and resetting RKE2_PATCH/RC"
    ((++PATCH))
    RC="-rc1"
    RKE2_PATCH="+rke2r1"
  elif [[ "${BUMP_TYPE}" == "release" ]] && [[ -n "${RC}" ]]; then
    print "Using RC ${TAG} for release"
    COMMIT_TARGET="tags/${TAG}"
    RC=""
  else
    if [[ -n "${RC}" ]]; then
      print "Previous tag was an RC; incrementing RC"
      NUM=$(grep -Eo '[[:digit:]]+$' <<<"${RC}")
      ((++NUM))
      RC="-rc${NUM}"
    else
      print "Previous tag was not RC; incrementing RKE2_PATCH and adding RC"
      NUM=$(grep -Eo '[[:digit:]]+$' <<<"${RKE2_PATCH}")
      ((++NUM))
      RC="-rc1"
      RKE2_PATCH="+rke2r${NUM}"
    fi
  fi

  VERSION="v${MAJOR}.${MINOR}.${PATCH}${RC}${RKE2_PATCH}"
  HEAD_COMMIT=$(git rev-parse --short "${COMMIT_TARGET}")
  HEAD_MESSAGE=$(git show --quiet "${HEAD_COMMIT}")

  print "\nHead of ${BRANCH} is:\n---\n${HEAD_MESSAGE}\n---\n"

  print "Creating new tag ${VERSION} from commit ${HEAD_COMMIT}"
  read -p 'Continue? [y/n]: ' CONTINUE
  if [[ "${CONTINUE}" == "y" ]]; then
    git tag "${VERSION}" "${HEAD_COMMIT}" && git push "${ORIGIN}" "refs/tags/${VERSION}"
  fi
}

do_release_branch() {
  local BRANCH="$1"
  local BUMP_TYPE="$2"
  print "\nDoing release for ${BRANCH}"
  pushd "$(go env GOPATH)/src/github.com/rancher/rke2" 1>/dev/null

  git fetch --prune --prune-tags --force "${ORIGIN}"

  TAG=$(git tag --merged "${ORIGIN}/${BRANCH}" --sort -committerdate | head -n1)
  if [[ "${TAG}" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)([-+][a-zA-Z0-9]+)?([-+]rke2r[0-9]+)$ ]]; then
    MAJOR=${BASH_REMATCH[1]}
    MINOR=${BASH_REMATCH[2]}
    PATCH=${BASH_REMATCH[3]}
    RC=${BASH_REMATCH[4]}
    RKE2_PATCH=${BASH_REMATCH[5]}
    print "TAG=${TAG} parsed as MAJOR=${MAJOR} MINOR=${MINOR} PATCH=${PATCH} RC=${RC} RKE2_PATCH=${RKE2_PATCH}"
  else
    print "Couldn't match ${TAG}"
    return
  fi

  if [[ "${BUMP_TYPE}" == "patch" ]]; then
    print "Incrementing PATCH and resetting RKE2_PATCH/RC"
    ((++PATCH))
    RC="-rc1"
    RKE2_PATCH="+rke2r1"
  elif [[ "${BUMP_TYPE}" == "release" ]] && [[ -n "${RC}" ]]; then
    print "Marking RC ${RC} as released"
    RC=""
  else
    if [[ -n "${RC}" ]]; then
      print "Previous tag was an RC; incrementing RC"
      NUM=$(grep -Eo '[[:digit:]]+$' <<<"${RC}")
      ((++NUM))
      RC="-rc${NUM}"
    else
      print "Previous tag was not RC; incrementing RKE2_PATCH and adding RC"
      NUM=$(grep -Eo '[[:digit:]]+$' <<<"${RKE2_PATCH}")
      ((++NUM))
      RC="-rc1"
      RKE2_PATCH="+rke2r${NUM}"
    fi
  fi

  BUILD_DATE=$(TZ=utc date '+-build%Y%m%d')
  VERSION="v${MAJOR}.${MINOR}.${PATCH}${RC}${RKE2_PATCH}"
  KUBERNETES_TAG=$(tr + - <<< "v${MAJOR}.${MINOR}.${PATCH}${RKE2_PATCH}${BUILD_DATE}")
  print "Preparing for ${VERSION} with hardened kubernetes ${KUBERNETES_TAG}"

  git reset --hard &>/dev/null || true
  git rebase --abort &>/dev/null || true
  git clean -xffd &>/dev/null || true
  git checkout -B "rke2_bump_${BRANCH}" "${ORIGIN}/${BRANCH}" &>/dev/null

  K3S_BRANCH="master"
  KUBERNETES_TAG="$(do_hardened_kubernetes "${KUBERNETES_TAG}")"

  if [[ "${MINOR}" -eq "22" ]]; then
    K3S_BRANCH="release-${MAJOR}.${MINOR}"
  elif [[ "${MINOR}" -le "21" ]]; then
    do_kube_proxy "${MAJOR}.${MINOR}"  "${KUBERNETES_TAG}"
    K3S_BRANCH="engine-1.21"
  fi

  sed -Ei "s/:v.*rke2.*[0-9]+/:${KUBERNETES_TAG}/" Dockerfile
  sed -Ei "s/v.*rke2.*[0-9]+/${KUBERNETES_TAG}/" pkg/images/images.go
  sed -Ei "s/CHART_VERSION=\"v.*rke2.*[0-9]+/CHART_VERSION=\"${KUBERNETES_TAG}01/" Dockerfile
  sed -Ei "s/KUBERNETES_VERSION:.*[0-9]+/KUBERNETES_VERSION:-v${MAJOR}.${MINOR}.${PATCH}/" scripts/version.sh
  sed -Ei "s/KUBERNETES_IMAGE_TAG:-.*[0-9]+/KUBERNETES_IMAGE_TAG:-${KUBERNETES_TAG}/" scripts/version.sh

  K3S_REPLACE=$(go mod edit --json | jq -r '.Replace[] | select(.Old.Path | contains("rancher/k3s")) | .New.Path + " " + .New.Version')
  if [ -n "${K3S_REPLACE}" ]; then
    read _ K3S_VERSION <<< ${K3S_REPLACE#github.com/}
  else
    K3S_VERSION=$(go mod edit --json | jq -r '.Require[] | select(.Path | contains("rancher/k3s")) | .Version')
  fi
  K3S_OLD_COMMIT=$(grep -oE '\w{12}$' <<< ${K3S_VERSION})

  K3S_NEW_COMMIT=$(curl -qsL "https://api.github.com/repos/rancher/k3s/branches/${K3S_BRANCH}" | jq -r '.commit.sha')

  print "Using commit ID '${K3S_NEW_COMMIT}' from branch ${K3S_BRANCH}"
  go mod edit --require "github.com/rancher/k3s@${K3S_NEW_COMMIT}"
  go mod tidy
  ~/rke2-modsync.sh

  git add Dockerfile go.mod go.sum pkg/images/images.go scripts/version.sh
  git commit -sm "Bump versions for ${VERSION}" -m "Updates k3s: https://github.com/k3s-io/k3s/compare/${K3S_OLD_COMMIT}...${K3S_NEW_COMMIT}"
  git push --set-upstream "${USERNAME}" --force-with-lease

  popd 1>/dev/null
}

for BRANCH in ${BRANCHES:-master release-1.22 release-1.21 release-1.20}; do
  case "${ACTION:-bump}" in
    bump)
      do_release_branch "${BRANCH}" "${BUMP_TYPE}" || true
      ;;
    tag)
      do_release_tag "${BRANCH}" "${BUMP_TYPE}" || true
      ;;
    packaging)
      do_release_packaging "${BRANCH}" "${CHANNEL:-testing}" || true
      ;;
    *)
      print "Invalid action"
      exit 1
      ;;
  esac
done

```
##
##

```

!proxmox_k3s_cluster.sh
#!/bin/bash
# curl -s https://gist.githubusercontent.com/ilude/457f2ef2e59d2bff8bb88b976464bb91/raw/cluster_create_setup.sh?$(date +%s) > ~/bin/setup_cluster.sh; chmod +x ~/bin/setup_cluster.sh; setup_cluster.sh

echo "begin cluster_create_setup.sh"

export CREATE_TEMPLATE=1 #false
while test $# -gt 0; do
  case "$1" in
    --template)
      export CREATE_TEMPLATE=0 #true
      ;;
    *)
      break
      ;;
  esac
done

# check if .env file exists
if [[ -f ".env" ]]; then
  # read in .env file ignoring commented lines
  echo "reading in variables from .env..."
  export $(grep -v '^#' .env | xargs)
else
  echo "No .env file found! Downloading a sample file to .env"
  curl -s https://gist.githubusercontent.com/ilude/457f2ef2e59d2bff8bb88b976464bb91/raw/.env?$(date +%s) > .env
  echo "Exiting!"
  exit 1
fi

if [ -z "$CLUSTER_USERNAME" ] || [ -z "$CLUSTER_PASSWORD" ]; then
  echo 'one or more required variables are undefined, please check your .env file! Exiting!'        
  exit 1
fi

export CLUSTER_PASSWORD=$( openssl passwd -6 $CLUSTER_PASSWORD )

# download and run provision_cluster.sh
curl -s $GIST_REPO_ADDRESS/raw/provision_cluster.sh?$(date +%s) | /bin/bash -s
 
.env
GIST_REPO_ADDRESS=https://gist.githubusercontent.com/ilude/457f2ef2e59d2bff8bb88b976464bb91

# ssh login credentials for cluster nodes
CLUSTER_USERNAME=
CLUSTER_PASSWORD=

DOMAIN_NAME=ilude.com
ACME_EMAIL=mglenn@ilude.com

# switch for production
#ACME_ENDPOINT="https://acme-v02.api.letsencrypt.org/directory"
ACME_ENDPOINT="https://acme-staging-v02.api.letsencrypt.org/directory"

# cluster storage name for iso's and vm images
# tank is a personally defined proxmox storage location 
# replace with your own location
CLUSTER_STORAGE=tank

# network gateway ip address
CLUSTER_GW_IP=192.168.16.1
# management vm ip address
CLUSTER_LB_IP=192.168.16.30
CLUSTER_METALLB_IP_RANGE=192.168.16.40-192.168.16.49

# cluster node ip addresses
CLUSTER_IP_1=192.168.16.31
CLUSTER_IP_2=192.168.16.32
CLUSTER_IP_3=192.168.16.33
CLUSTER_IP_4=192.168.16.34
CLUSTER_IP_5=192.168.16.35
CLUSTER_IP_6=192.168.16.36
cluster_create_template.sh
#!/bin/bash
# curl -s $GIST_REPO_ADDRESS/raw/cluster_create_template.sh?$(date +%s) | /bin/bash -s

echo "begin cluster_create_template.sh"

export TEMPLATE_EXISTS=$(qm list | grep -v grep | grep -ci 9000)

if [[ $TEMPLATE_EXISTS > 0 && $CREATE_TEMPLATE > 0 ]]
then
  # destroy linked management vm 
  curl -s $GIST_REPO_ADDRESS/raw/cluster_destroy_loadbalancer.sh?$(date +%s) | /bin/bash -s

  # destroy any linked cluster nodes
  curl -s $GIST_REPO_ADDRESS/raw/cluster_destroy_nodes.sh?$(date +%s) | /bin/bash -s
  
  # could be running if in a wierd state from prior run 
  qm stop 9000 
  qm unlock 9000
  
  # destroy template
  qm destroy 9000 --purge 1
  
elif [[ $TEMPLATE_EXISTS > 0 && $CREATE_TEMPLATE == 0 ]]
then
  exit
fi

#fetch cloud-init image
wget -nc https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img

# create a new VM
qm create 9000 --memory 2048 --cores 4 --machine q35 --bios ovmf --net0 virtio,bridge=vmbr0 

# import the downloaded disk to local-lvm storage
qm importdisk 9000 focal-server-cloudimg-amd64.img $CLUSTER_STORAGE > /dev/null

# finally attach the new disk to the VM as scsi drive
qm set 9000 --scsihw virtio-scsi-pci --scsi0 $CLUSTER_STORAGE:vm-9000-disk-0
qm set 9000 --ide2 $CLUSTER_STORAGE:cloudinit
qm set 9000 --boot c --bootdisk scsi0
qm set 9000 --serial0 socket --vga serial0
qm set 9000 --ipconfig0 ip=dhcp

# qm cloudinit dump 9000 user > /var/lib/vz/snippets/user-data.yml; nano /var/lib/vz/snippets/user-data.yml
qm set 9000 --cicustom "user=local:snippets/user-data.yml"

echo "starting template vm..."
qm start 9000

echo "waiting for template vm to complete initial setup..."
secs=110
while [ $secs -gt 0 ]; do
   echo -ne "\t$secs seconds remaining\033[0K\r"
   sleep 1
   : $((secs--))
done

echo "initial setup complete..."
qm shutdown 9000
qm stop 9000

echo "creating template image"
qm template 9000
 
cluster_create_vms_loadbalancer.sh
#!/bin/bash
# curl -s $GIST_REPO_ADDRESS/raw/cluster_create_vms_loadbalancer.sh?$(date +%s) | /bin/bash -s

echo "begin cluster_create_vms_loadbalancer.sh"

# destroy linked management vm
curl -s $GIST_REPO_ADDRESS/raw/cluster_destroy_loadbalancer.sh?$(date +%s) | /bin/bash -s

# clone new vm from cloud-init template
qm clone 9000 3000 --name k3lb
qm set 3000 --onboot 1 --cores 2 --cicustom "user=local:snippets/user-data.yml" --ipconfig0 ip=$CLUSTER_LB_IP/24,gw=$CLUSTER_GW_IP

qm resize 3000 scsi0 10G

# start it up
qm start 3000

# wait for vm to spin up and then copy our private key
echo "waiting for loadbalancer vm to spin up..."
secs=20
while [ $secs -gt 0 ]; do
   echo -ne " \t$secs seconds remaining\033[0K\r"
   sleep 1
   : $((secs--))
done

echo
echo "adding server key for $CLUSTER_LB_IP to /root/.ssh/known_hosts"
ssh-keyscan -H $CLUSTER_LB_IP >> /root/.ssh/known_hosts 2>/dev/null
echo
echo "##### /root/known_hosts content #####"
cat /root/.ssh/known_hosts
echo "#####################################"
echo

echo "copying private key to loadbalancer..."
rsync -e "ssh -o StrictHostKeyChecking=no" --chmod=700 ~/.ssh/id_ed25519* $CLUSTER_USERNAME@$CLUSTER_LB_IP:~/.ssh/ # 
cluster_create_vms_worker.sh
#!/bin/bash
# curl -s $GIST_REPO_ADDRESS/raw/cluster_create_vms_worker.sh?$(date +%s) | /bin/bash -s

echo "begin cluster_create_vms_worker.sh"

# destroy any old nodes before we start
curl -s $GIST_REPO_ADDRESS/raw/cluster_destroy_nodes.sh?$(date +%s) | /bin/bash -s

# clone images for master nodes
qm clone 9000 3001 --name k3m-01 
qm set 3001 --onboot 1 --cores 2 --cicustom "user=local:snippets/user-data.yml" --ipconfig0 ip=$CLUSTER_IP_1/24,gw=$CLUSTER_GW_IP

qm clone 9000 3002 --name k3m-02
qm set 3002 --onboot 1 --cores 2 --cicustom "user=local:snippets/user-data.yml" --ipconfig0 ip=$CLUSTER_IP_2/24,gw=$CLUSTER_GW_IP

qm clone 9000 3003 --name k3m-03 
qm set 3003 --onboot 1 --cores 2 --cicustom "user=local:snippets/user-data.yml" --ipconfig0 ip=$CLUSTER_IP_3/24,gw=$CLUSTER_GW_IP


# clone images for worker nodes
qm clone 9000 3101 --name k3w-01
qm set 3101 --onboot 1 --cores 4 --cicustom "user=local:snippets/user-data.yml" --memory 6144 --ipconfig0 ip=$CLUSTER_IP_4/24,gw=$CLUSTER_GW_IP

qm clone 9000 3102 --name k3w-02
qm set 3102 --onboot 1 --cores 4 --cicustom "user=local:snippets/user-data.yml" --memory 6144 --ipconfig0 ip=$CLUSTER_IP_5/24,gw=$CLUSTER_GW_IP

qm clone 9000 3103 --name k3w-03
qm set 3103 --onboot 1 --cores 4 --cicustom "user=local:snippets/user-data.yml" --memory 6144 --ipconfig0 ip=$CLUSTER_IP_6/24,gw=$CLUSTER_GW_IP


# lets get this party started
## declare an array variable
declare -a arr=("3001" "3002" "3003" "3101" "3102" "3103")

## now loop through the above array
for VMID in "${arr[@]}"
do
  qm resize $VMID scsi0 96G
  qm start $VMID
done

echo "waiting for nodes to spin up..."
secs=25
while [ $secs -gt 0 ]; do
   echo -ne "\t$secs seconds remaining\033[0K\r"
   sleep 1
   : $((secs--))
done

## declare an array variable
declare -a arr=("$CLUSTER_IP_1" "$CLUSTER_IP_2" "$CLUSTER_IP_3" "$CLUSTER_IP_4" "$CLUSTER_IP_5" "$CLUSTER_IP_6")

## now loop through the above array
for IP in "${arr[@]}"
do
  ssh-keyscan -H $IP >> ~/.ssh/known_hosts > /dev/null 2>&1
done
 
cluster_destroy_loadbalancer.sh
# DO NOT RUN THIS DIRECTLY
# IT'S CALLED BY OTHER SCRIPTS 
echo "begin cluster_destroy_loadbalancer.sh"

# destroy existing loadbalancer image
if (( $(qm list | grep -v grep | grep -ci 3000) > 0 )); then
  qm stop 3000
  qm unlock 3000
  qm destroy 3000 --purge 1
fi

# clean up known_hosts file
ssh-keygen -R $CLUSTER_LB_IP 2>/dev/null
 
cluster_destroy_nodes.sh
# DO NOT RUN THIS DIRECTLY
# IT'S CALLED BY OTHER SCRIPTS 
echo "begin cluster_destroy_nodes.sh"

## declare an array variable
declare -a arr=("3001" "3002" "3003" "3101" "3102" "3103")

## now loop through the above array
for VMID in "${arr[@]}"
do
  # check if vm exists and destroy it
  if (( $(qm list | grep -v grep | grep -ci $VMID) > 0 )); then
    qm stop $VMID
    qm unlock $VMID
    qm destroy $VMID --purge 1 
  fi
done

## declare an array variable
declare -a arr=("$CLUSTER_IP_1" "$CLUSTER_IP_2" "$CLUSTER_IP_3" "$CLUSTER_IP_4" "$CLUSTER_IP_5" "$CLUSTER_IP_6")

## now loop through the above array
for IP in "${arr[@]}"
do
  ssh-keygen -R $IP > /dev/null 2>&1
done
provision_cluster.sh

echo "begin provision_cluster.sh"

# updated from https://pve.proxmox.com/wiki/Cloud-Init_Support
# man pages for qm command: https://pve.proxmox.com/pve-docs/qm.1.html
# install tools
apt-get install cloud-init

# generate an ssh key if one does not already exist
if [ ! -f ~/.ssh/id_ed25519 ]; then
  echo "generating ssh key in ~/.ssh/id_ed25519 with comment k3s@cluster.key"
  ssh-keygen -a 100 -t ed25519 -N '' -f ~/.ssh/id_ed25519 -C "k3s@cluster.key"
  chmod 700 ~/.ssh/id_ed25519*
fi
export CLUSTER_PUBKEY=`cat ~/.ssh/id_ed25519.pub`

# create the cloud-init user-data.yml file from template
curl -s $GIST_REPO_ADDRESS/raw/user-data.yml?$(date +%s) | envsubst > /var/lib/vz/snippets/user-data.yml

# provision proxmox template
curl -s $GIST_REPO_ADDRESS/raw/cluster_create_template.sh?$(date +%s) | /bin/bash -s

# provision proxmox management server
curl -s $GIST_REPO_ADDRESS/raw/cluster_create_vms_loadbalancer.sh?$(date +%s) | /bin/bash -s

# provision proxmox cluster nodes
curl -s $GIST_REPO_ADDRESS/raw/cluster_create_vms_worker.sh?$(date +%s) | /bin/bash -s

# create and run script on management server
ssh $CLUSTER_USERNAME@$CLUSTER_LB_IP "bash -s" <<EOF
cat <<- 'ENV' > .env 
export GIST_REPO_ADDRESS=$GIST_REPO_ADDRESS
# ssh login credentials for cluster nodes
export CLUSTER_USERNAME=$CLUSTER_USERNAME
export CLUSTER_PASSWORD=$CLUSTER_PASSWORD
# acme cert info
DOMAIN_NAME=$DOMAIN_NAME
ACME_EMAIL=$ACME_EMAIL
ACME_ENDPOINT=$ACME_ENDPOINT
# cluster ip addresses
export CLUSTER_GW_IP=$CLUSTER_GW_IP
export CLUSTER_LB_IP=$CLUSTER_LB_IP
export CLUSTER_IP_1=$CLUSTER_IP_1  # cluster node 1 ip address
export CLUSTER_IP_2=$CLUSTER_IP_2  # cluster node 2 ip address
export CLUSTER_IP_3=$CLUSTER_IP_3  # cluster node 3 ip address
export CLUSTER_IP_4=$CLUSTER_IP_4  # cluster node 4 ip address
export CLUSTER_IP_5=$CLUSTER_IP_5  # cluster node 5 ip address
export CLUSTER_IP_6=$CLUSTER_IP_6  # cluster node 6 ip address
ENV
source .env
# provision loadbalancer
# no longer using standalone loadbalancer
# curl -s $GIST_REPO_ADDRESS/raw/provision_cluster_loadbalancer.sh?$(date +%s) | /bin/bash -s
# download and run provision_cluster_nodes.sh script
curl -s $GIST_REPO_ADDRESS/raw/provision_cluster_nodes.sh?$(date +%s) | /bin/bash -s
echo "cluster setup completed!"
echo "ssh $CLUSTER_USERNAME@$CLUSTER_LB_IP"
EOF

# lets get this party started
## declare an array variable
declare -a arr=("3001" "3002" "3003" "3101" "3102" "3103")

## now loop through the above array
for VMID in "${arr[@]}"
do
  qm snapshot $VMID clean_cluster
done
provision_cluster_nodes.sh
#!/bin/bash
# curl -s $GIST_REPO_ADDRESS/raw/provision_cluster_nodes.sh?$(date +%s) | /bin/bash -s

echo "begin provision_cluster_nodes.sh"

# install k3sup
curl -sLS https://get.k3sup.dev | sh
sudo install k3sup /usr/local/bin/
k3sup version

#initial master
k3sup install --ip $CLUSTER_IP_1 --user $CLUSTER_USERNAME --ssh-key ~/.ssh/id_ed25519  --k3s-extra-args "--cluster-init --node-taint CriticalAddonsOnly=true:NoExecute --no-deploy servicelb --no-deploy traefik" # --tls-san $CLUSTER_LB_IP

# install kubectl
curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x ./kubectl
sudo mv ./kubectl /usr/local/bin/kubectl

# setup kubectl configuration
export KUBECONFIG=`pwd`/kubeconfig
echo "export KUBECONFIG=$KUBECONFIG" >> ~/.bashrc
echo "source <(kubectl completion bash)" >> ~/.bashrc
echo "alias l='ls -lha --color=auto --group-directories-first'" >> .bashrc
# kubectl config set-context default
# kubectl version --client

# install helm
curl -s https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | /bin/bash -s

echo "Waiting for initial node to start..."
while (( $(kubectl get node | grep -ci NotReady) > 0 )); do sleep 1; done
 

# additional masters
k3sup join --ip $CLUSTER_IP_2 --user $CLUSTER_USERNAME --ssh-key ~/.ssh/id_ed25519 --server-ip $CLUSTER_IP_1 --server-user $CLUSTER_USERNAME --server --k3s-extra-args "--node-taint CriticalAddonsOnly=true:NoExecute --no-deploy servicelb --no-deploy traefik" #--tls-san $CLUSTER_LB_IP"
k3sup join --ip $CLUSTER_IP_3 --user $CLUSTER_USERNAME --ssh-key ~/.ssh/id_ed25519 --server-ip $CLUSTER_IP_1 --server-user $CLUSTER_USERNAME --server --k3s-extra-args "--node-taint CriticalAddonsOnly=true:NoExecute --no-deploy servicelb --no-deploy traefik" #--tls-san $CLUSTER_LB_IP"

# join workers
k3sup join --ip $CLUSTER_IP_4 --user $CLUSTER_USERNAME --ssh-key ~/.ssh/id_ed25519 --server-ip $CLUSTER_IP_1 --server-user $CLUSTER_USERNAME 
k3sup join --ip $CLUSTER_IP_5 --user $CLUSTER_USERNAME --ssh-key ~/.ssh/id_ed25519 --server-ip $CLUSTER_IP_1 --server-user $CLUSTER_USERNAME 
k3sup join --ip $CLUSTER_IP_6 --user $CLUSTER_USERNAME --ssh-key ~/.ssh/id_ed25519 --server-ip $CLUSTER_IP_1 --server-user $CLUSTER_USERNAME 

echo "Waiting for remaining node to start..."
sleep 10
while(( $(kubectl get node | grep -ci NotReady) > 0 )); do sleep 1; done

kubectl get node -o wide

# setup metallb
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.9.5/manifests/namespace.yaml
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.9.5/manifests/metallb.yaml
kubectl create secret generic -n metallb-system memberlist --from-literal=secretkey="$(openssl rand -base64 128)"

envsubst << 'EOF' | sudo tee ~/metallb_config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - $CLUSTER_METALLB_IP_RANGE
EOF

kubectl apply -f ~/metallb_config.yaml

helm repo add traefik https://helm.traefik.io/traefik
helm repo update

envsubst << 'EOF' | sudo tee ~/traefik-chart-values.yaml
additionalArguments:
  - --providers.file.filename=/data/traefik-config.yaml
  - --entrypoints.websecure.http.tls.certresolver=cloudflare
  - --entrypoints.websecure.http.tls.domains[0].main=$DOMAIN_NAME
  - --entrypoints.websecure.http.tls.domains[0].sans=*.$DOMAIN_NAME
  - --certificatesresolvers.cloudflare.acme.email=$ACME_EMAIL
  - --certificatesresolvers.cloudflare.acme.caserver=$ACME_ENDPOINT
  - --certificatesresolvers.cloudflare.acme.dnschallenge.provider=cloudflare
  - --certificatesresolvers.cloudflare.acme.dnschallenge.resolvers=1.1.1.1
  - --certificatesresolvers.cloudflare.acme.storage=/certs/acme.json
ports:
  web:
    redirectTo: websecure
env:
  - name: CF_API_EMAIL
    valueFrom:
      secretKeyRef:
        key: email
        name: cloudflare-api-credentials
  - name: CF_API_KEY
    valueFrom:
      secretKeyRef:
        key: apiKey
        name: cloudflare-api-credentials
ingressRoute:
  dashboard:
    enabled: false
persistence:
  enabled: true
  path: /certs
  size: 128Mi
volumes:
  - mountPath: /data
    name: traefik-config
    type: configMap
EOF

envsubst << 'EOF' | sudo tee ~/traefik-config.yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: traefik
  labels:
    app: traefik
---
apiVersion: v1
kind: Secret
metadata:
  name: cloudflare-api-credentials
  namespace: traefik
type: Opaque
stringData:
  email: $ACME_EMAIL
  apiKey: $ACME_KEY
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: traefik-config
  namespace: traefik
data:
  traefik-config.yaml: |
    http:
      middlewares:
        headers-default:
          headers:
            sslRedirect: true
            browserXssFilter: true
            contentTypeNosniff: true
            forceSTSHeader: true
            stsIncludeSubdomains: true
            stsPreload: true
            stsSeconds: 15552000
            customFrameOptionsValue: SAMEORIGIN
---
apiVersion: v1
kind: Secret
metadata:
  name: traefik-dashboard-auth
  namespace: traefik
data:
  users: |2
    $TRAEFIK_HTPASSWD
---
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: traefik-dashboard-basicauth
  namespace: traefik
spec:
  basicAuth:
    secret: traefik-dashboard-auth
    
---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: traefik-dashboard
  namespace: traefik
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`traefik.$DOMAIN_NAME`)
      kind: Rule
      middlewares:
        - name: traefik-dashboard-basicauth
          namespace: traefik
      services:
        - name: api@internal
          kind: TraefikService
EOF

kubectl apply -f traefik-config.yaml
helm install traefik traefik/traefik --namespace=traefik --values=traefik-chart-values.yaml

user-data.yml
#cloud-config
manage_etc_hosts: true
user: $CLUSTER_USERNAME
password: $CLUSTER_PASSWORD
chpasswd:
  expire: False
users:
  - name: $CLUSTER_USERNAME
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBt48noMzgehjgTJszcAoj5InR6mbNTj3yA00ioXifk2 mglenn@ilude.com
      - $CLUSTER_PUBKEY
package_upgrade: true
packages:
  - bmon 
  - bwm-ng 
  - curl 
  - htop 
  - iftop 
  - iotop 
  - libpam-systemd 
  - locales-all 
  - locate 
  - nano 
  - net-tools 
  - ntpdate 
  - nfs-common 
  - qemu-guest-agent 
  - rsync 
  - screen 
  - strace 
  - sysstat 
  - snmpd 
  - sudo 
  - tcpdump 
  - tmux 
  - vlan 
  - vnstat
runcmd:
  - snap remove lxd
  - snap remove core18
  - snap remove snapd
  - apt purge snapd -y
  - apt autoremove -y
  - apt autoclean -y
  - hostnamectl set-hostname k3s-`ip -o addr show dev "eth0" | awk '$3 == "inet" {print $4}' | sed -r 's!/.*!!; s!.*\.!!'`
  
zz_provision_cluster_loadbalancer.sh
#!/bin/bash
# curl -s $GIST_REPO_ADDRESS/raw/provision_cluster_loadbalancer.sh?$(date +%s) | /bin/bash -s

# echo "$USER ALL=(ALL) NOPASSWD:ALL" | sudo tee --append /etc/sudoers
# sudo apt-get remove docker docker-engine docker.io
# sudo apt install apt-transport-https ca-certificates curl software-properties-common make git -y 
# curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
# sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable edge"
# sudo apt-get update
# sudo apt-get install logrotate docker-ce -y 
# sudo groupadd docker
# sudo usermod -aG docker $USER
# sudo systemctl enable docker
# sudo systemctl start docker

# curl -s https://api.github.com/repos/docker/compose/releases/latest \
#   | grep browser_download_url \
#   | grep docker-compose-Linux-x86_64 \
#   | cut -d '"' -f 4 \
#   | wget -qi -
# chmod +x docker-compose-Linux-x86_64
# sudo mv docker-compose-Linux-x86_64 /usr/local/bin/docker-compose

# sudo mkdir -p /apps/nginx
# sudo chown -R $USER:$USER /apps

# sudo rm -rf /apps/nginx/docker-compose.yml
# sudo tee -a /apps/nginx/docker-compose.yml >/dev/null << 'EOF'
# version: '3'
# services:
#   nginx:
#     image: nginx:alpine
#     restart: unless-stopped
#     container_name: nginx
#     healthcheck:
#       test: wget localhost/nginx_status -q -O - > /dev/null 2>&1
#       interval: 5s
#       timeout: 5s
#       retries: 3
#     volumes:
#       - ./nginx.conf:/etc/nginx/nginx.conf
#     ports:
#       - 6443:6443
# EOF

# sudo rm -rf /apps/nginx/nginx.conf
# envsubst << 'EOF' | sudo tee /apps/nginx/nginx.conf
# events {}

# stream {
#   upstream k3s_servers {
#     server $CLUSTER_IP_1:6443;
#     server $CLUSTER_IP_2:6443;
#     server $CLUSTER_IP_3:6443;
#   }

#   server {
#     listen 6443;
#     proxy_pass k3s_servers;
#   }
# }

# http {
#   server {
#     listen 80 default_server;
#     server_name _;
#     access_log off; # comment if you want to see healthchecks in the logs
    
#     location /nginx_status {
#       stub_status;
#       allow 127.0.0.1;
#       deny all;
#     }
#     deny all;
#   }
# }
# EOF

# sudo rm -rf /etc/systemd/system/docker-compose@.service
# sudo tee -a /etc/systemd/system/docker-compose@.service >/dev/null <<'EOF'
# [Unit]
# Description=%i service with docker compose
# Requires=docker.service
# After=docker.service

# [Service]
# Restart=always

# WorkingDirectory=/apps/%i

# # Remove old containers, images and volumes
# ExecStartPre=/usr/local/bin/docker-compose down

# # Compose up
# ExecStart=/usr/local/bin/docker-compose up

# # Compose down, remove containers and volumes
# ExecStop=/usr/local/bin/docker-compose down

# [Install]
# WantedBy=multi-user.target
# EOF

# sudo systemctl enable docker-compose@nginx
# sudo systemctl start docker-compose@nginx

```
