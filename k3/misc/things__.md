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
