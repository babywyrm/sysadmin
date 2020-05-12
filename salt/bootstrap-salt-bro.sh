#!/bin/bash -e

# bootstrap.sh

# Installs Salt and configure minimal SaltMaster or Minion to be used with:
# - http://github.com/salt-formulas-scripts
# - http://github.com/salt-formulas/salt-formula-salt (salt.master sls)

# NOTE: This script is collection of shared functions to automate bootstrap of "salted" CI environments.
#       Its not intended to be used in PRODUCTION unless you know what you are doing.
#       You have been warned!

__ScriptVersion="2018.09.12"
__ScriptName="bootstrap.sh"
__ScriptFullName="$0"
__ScriptArgs="$*"

# Source specific env vars.
# shopt -u dotglob
export RECLASS_ROOT=${RECLASS_ROOT:-/srv/salt/reclass}
function source_local_envs() {
  for path in / /tmp/kitchen /srv/salt . ${RECLASS_ROOT}/classes/cluster ${RECLASS_ROOT}/classes/cluster/${CLUSTER_NAME}; do
    for f in $(find $path -maxdepth 1 -name '*.env' 2> /dev/null); do
        echo "Sourcing env variables from $f"
        source $f
    done
  done
}
source_local_envs

##########################################
# Set defaults env variables

if [[ $DEBUG =~ ^(True|true|1|yes)$ ]]; then
    set -x
    SALT_LOG_LEVEL="--state-verbose=true -ldebug"
fi

export MAGENTA='\033[0;95m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;35m'
export CYAN='\033[0;96m'
export RED='\033[0;31m'
export NC='\033[0m' # No Color'

export LC_ALL=C
export SALT_LOG_LEVEL="--state-verbose=false -lerror"
export SALT_OPTS="${SALT_OPTS:- --timeout=120 --state-output=changes --retcode-passthrough --force-color $SALT_LOG_LEVEL }"
export SALT_STATE_RETRY=${SALT_STATE_RETRY:-3}

# salt apt repository
test -e /etc/lsb-release && eval $(cat /etc/lsb-release)
which lsb_release && DISTRIB_CODENAME=${DISTRIB_CODENAME:-$(lsb_release -cs)}
#
export APT_REPOSITORY=${APT_REPOSITORY:- deb [arch=amd64] http://apt.mirantis.com/${DISTRIB_CODENAME} ${DISTRIB_REVISION:-stable} salt}
export APT_REPOSITORY_GPG=${APT_REPOSITORY_GPG:-http://apt.mirantis.com/public.gpg}
# reclass
export RECLASS_ADDRESS=${RECLASS_ADDRESS:-https://github.com/salt-formulas/openstack-salt.git} # https/git
export RECLASS_BRANCH=${RECLASS_BRANCH:-master}

# formula
export FORMULAS_BASE=${FORMULAS_BASE:-https://github.com/salt-formulas}
export FORMULAS_PATH=${FORMULAS_PATH:-/usr/share/salt-formulas}
export FORMULAS_BRANCH=${FORMULAS_BRANCH:-master}
export FORMULAS_SOURCE=${FORMULAS_SOURCE:-pkg} # pkg/git
# Essential set of formulas (known to by used on cfg01 node for most setups during bootsrap)
# DEPRECATED: FORMULAS_SALT_MASTER=${FORMULAS_SALT_MASTER:- $EXTRA_FORMULAS maas memcached ntp nginx collectd sensu heka sphinx mysql grafana libvirt rsyslog glusterfs postfix xtrabackup freeipa prometheus telegraf elasticsearch kibana rundeck devops-portal rsync docker keepalived aptly jenkins gerrit artifactory influxdb horizon}
FORMULAS_SALT_MASTER=${FORMULAS_SALT_MASTER:- "$EXTRA_FORMULAS"}
# minimal set of formulas for salt-master bootstrap
declare -a FORMULAS_SALT_MASTER=(reclass salt git openssh linux $(echo "${FORMULAS_SALT_MASTER}"))
export FORMULAS_SALT_MASTER


# Install 'salt-formula-*'. Works only with FORMULAS_SOURCE==pkg
export EXTRA_FORMULAS_PKG_ALL=${EXTRA_FORMULAS_PKG_ALL:-False}

# system / host
export HOSTNAME=${HOSTNAME:-`hostname -s`}
export HOSTNAME=${HOSTNAME//.*/}
export DOMAIN=${DOMAIN:-`hostname -d`}
export DOMAIN=${DOMAIN:-bootstrap.local}

# salt
export MINION_ID=${MINION_ID:-${HOSTNAME}.${DOMAIN}}
export MASTER_HOSTNAME=${MASTER_HOSTNAME:-${HOSTNAME}.${DOMAIN}}
# Ignore state.apply salt.master.env error
export SA_IGNORE_ERROR_SALT_MASTER_ENV=${SA_IGNORE_ERROR_SALT_MASTER_ENV:-False}

# saltstack
BOOTSTRAP_SALTSTACK=${BOOTSTRAP_SALTSTACK:-True}
BOOTSTRAP_SALTSTACK_COM=${BOOTSTRAP_SALTSTACK_COM:-"https://bootstrap.saltstack.com"}
BOOTSTRAP_SALTSTACK_VERSION=${BOOTSTRAP_SALTSTACK_VERSION:- stable 2017.7 }
BOOTSTRAP_SALTSTACK_VERSION=${BOOTSTRAP_SALTSTACK_VERSION//latest*/stable}
# TODO add 'r' option by default
# Currently, without 'r' option, upstream saltstack repos will be used. Otherwise
# local one should be used, from http://apt.mirantis.com/ or whatever.
BOOTSTRAP_SALTSTACK_OPTS=${BOOTSTRAP_SALTSTACK_OPTS:- -dX $BOOTSTRAP_SALTSTACK_VERSION }
SALT_SOURCE=${SALT_SOURCE:-pkg}

# SECURITY
SSH_STRICTHOSTKEYCHECKING=no

# environment
if [ "$FORMULAS_SOURCE" == "git" ]; then
  SALT_ENV=${SALT_ENV:-dev}
elif [ "$FORMULAS_SOURCE" == "pkg" ]; then
  SALT_ENV=${SALT_ENV:-prd}
fi
eval "$(grep -h '=' /etc/*release 2> /dev/null)"
PLATFORM_FAMILY=$(echo ${ID_LIKE// */} | tr A-Z a-z)
case $PLATFORM_FAMILY in
  debian )
      PKGTOOL="$SUDO apt-get"
      test ${VERSION_ID//\.*/} -ge 16 && {
        SVCTOOL=service
      } || { SVCTOOL=service
      }
    ;;
  rhel )
      PKGTOOL="$SUDO yum"
      test ${VERSION_ID//\.*/} -ge 7 && {
        SVCTOOL=systemctl
      } || { SVCTOOL=service
      }
    ;;
esac

export PLATFORM_FAMILY
export PKGTOOL
export SVCTOOL

##########################################
# FUNCTIONS

log_info() {
    echo -e "${YELLOW}[INFO] $* ${NC}"
}

log_warn() {
    echo -e "${MAGENTA}[WARN] $* ${NC}"
}

log_debug() {
    echo -e "${CYAN}[WARN] $* ${NC}"
}

log_err() {
    echo -e "${RED}[ERROR] $* ${NC}" >&2
}

configure_pkg_repo()
{

    case $PLATFORM_FAMILY in
      debian)
          if [ -n "$APT_REPOSITORY_PPA" ]; then
            which add-apt-repository || $SUDO apt-get install -y software-properties-common
            $SUDO add-apt-repository -y ppa:${APT_REPOSITORY_PPA}
          else
            echo -e  "$APT_REPOSITORY " | $SUDO tee /etc/apt/sources.list.d/mcp_salt.list >/dev/null
            curl -sL $APT_REPOSITORY_GPG | $SUDO apt-key add -
          fi
          $SUDO apt-get clean
          $SUDO apt-get update
        ;;
      rhel)
          $SUDO yum install -y https://repo.saltstack.com/yum/redhat/salt-repo-latest-1.el${VERSION_ID}.noarch.rpm
          $SUDO yum clean all
        ;;
    esac

}

_atexit() {
    RETVAL=$?
    trap true INT TERM EXIT

    if [ $RETVAL -ne 0 ]; then
        log_err "Execution failed"
    else
        log_info "Execution successful"
    fi
    return $RETVAL
}

retry() {
    local tries
    if [[ $1 =~ ^[0-9]+$ ]]; then
        tries=$1; shift
    else
        tries=3
    fi
    ret=1
    for i in $(seq 1 $tries); do
        "$@" && return $? || ret=$?
        sleep $i
    done
    return $ret
}

function clone_reclass() {
  if [ ! -d ${RECLASS_ROOT}/classes ]; then
    # No reclass at all, clone from given address
    # In case, non-github repo
    _tmp_host=$(echo ${RECLASS_ADDRESS} | awk -F/ '{print $3}')
    ssh-keyscan -T 1 -H ${_tmp_host} >> ~/.ssh/known_hosts || true
    # But, awk is not perfect solution, so lets make double-check for github
    ssh-keyscan -T 1 -H github.com >> ~/.ssh/known_hosts || true
    if echo ${RECLASS_BRANCH} | egrep -q "^refs"; then
        git clone ${RECLASS_ADDRESS} ${RECLASS_ROOT}
        cd ${RECLASS_ROOT}
        git fetch ${RECLASS_ADDRESS} ${RECLASS_BRANCH} && git checkout FETCH_HEAD
        export RECLASS_REVISION=$(git rev-parse HEAD)
        cd -
    else
        git clone -b ${RECLASS_BRANCH} ${RECLASS_ADDRESS} ${RECLASS_ROOT};
    fi;
  fi;
  if [ ! -d ${RECLASS_ROOT}/classes ]; then
    log_err "Reclass ${RECLASS_ROOT} is not fetched locally;"
    ls -Rla ${RECLASS_ROOT}
    exit 1
  fi;
  $SUDO mkdir -p $RECLASS_ROOT/classes/service
  $SUDO mkdir -p $RECLASS_ROOT/nodes/_generated
}


##########################################
# Main calls

ci_config_ssh() {

    # for CI current user
    conf=~/.ssh/config
    mkdir -p $(dirname $conf)
    touch $conf
    echo -e "Host *\n\tStrictHostKeyChecking $SSH_STRICTHOSTKEYCHECKING\n" | tee -a $conf >/dev/null
    touch ~/.ssh/known_hosts

    if ! grep github.com ~/.ssh/known_hosts; then
      ssh-keyscan -H github.com >> ~/.ssh/known_hosts || true
      ssh-keyscan -H gitlab.com >> ~/.ssh/known_hosts || true
    fi

    # for root
    #conf=/root/.ssh/config
    #$SUDO mkdir -p $(dirname $conf)
    #$SUDO touch $conf
    #if ! $SSH_STRICTHOSTKEYCHECKING; then
    #  echo -e "Host *\n\tStrictHostKeyChecking no\n" | $SUDO tee -a $conf >/dev/null
    #fi
}

# DEPRECATED
system_config_ssh_conf() {
  # for backward compatibility
  ci_config_ssh
}

system_config_salt_modules_prereq() {
    # salt-formulas custom modules dependencies, etc:
    $SUDO $PKGTOOL install -y apt-transport-https curl git iproute2 openssh-client python-psutil python-apt python-m2crypto python-oauth python-pip sudo &>/dev/null
}

system_config_minion() {
    log_info "System configuration salt minion"
}

system_config_master() {
    log_info "System configuration salt master"

    system_config_salt_modules_prereq
    ci_config_ssh

    if ! grep '127.0.1.2.*salt' /etc/hosts; then
      echo "127.0.1.2  salt" | $SUDO tee -a /etc/hosts >/dev/null
    fi
}

configure_salt_master()
{

  echo "Configuring salt-master ..."

  if [[ $RECLASS_IGNORE_CLASS_NOTFOUND =~ ^(True|true|1|yes)$ ]]; then
    read -d '' IGNORE_CLASS_NOTFOUND <<-EOF
		  ignore_class_notfound: True
		  ignore_class_regexp:
		  - 'service.*'
EOF
  fi

  # to force alternative reclass module path
  if [ -n "$RECLASS_SOURCE_PATH" ]; then
    RECLASS_SOURCE_PATH="reclass_source_path: ${RECLASS_SOURCE_PATH}"
  else
    RECLASS_SOURCE_PATH=""
  fi

  [ ! -d /etc/salt/master.d ] && mkdir -p /etc/salt/master.d
  cat <<-EOF > /etc/salt/master.d/master.conf
	file_roots:
	  base:
	  - /usr/share/salt-formulas/env
	  prd:
	  - /srv/salt/env/prd
	  dev:
	  - /srv/salt/env/dev
	pillar_opts: False
	open_mode: True
	reclass: &reclass
	  storage_type: yaml_fs
	  inventory_base_uri: ${RECLASS_ROOT}
	  ${IGNORE_CLASS_NOTFOUND}
	  ${RECLASS_SOURCE_PATH}
	ext_pillar:
	  - reclass: *reclass
	master_tops:
	  reclass: *reclass
EOF

  echo "Configuring reclass ..."

  [ ! -d /etc/reclass ] && mkdir /etc/reclass
  cat <<-EOF > /etc/reclass/reclass-config.yml
	storage_type: yaml_fs
	pretty_print: True
	output: yaml
	inventory_base_uri: ${RECLASS_ROOT}
EOF

  clone_reclass
  # override some envs from cluster level *.env, use with care
  source_local_envs

  cd ${RECLASS_ROOT}
  if [ ! -d ${RECLASS_ROOT}/classes/system/linux ]; then
    # Possibly subrepo checkout needed
    git submodule update --init --recursive
  fi

  mkdir -vp ${RECLASS_ROOT}/nodes/_generated
  rm -rvf ${RECLASS_ROOT}/nodes/_generated/*

  CONFIG=$(find ${RECLASS_ROOT}/nodes -name ${MINION_ID}.yml| grep yml | tail -n1)
  CONFIG=${CONFIG:-${RECLASS_ROOT}/nodes/_generated/${MINION_ID}.yml}
  if [[ $SALT_MASTER_BOOTSTRAP_MINIMIZED =~ ^(True|true|1|yes)$ || ! -f "${CONFIG}" ]]; then
  log_warn "Salt Master node specification has not been found in model."
  log_warn "Creating temporary cfg01 configuration for bootstrap: ${CONFIG}"
  cat <<-EOF > ${CONFIG}
	classes:
	- cluster.${CLUSTER_NAME}.infra.config
	parameters:
	  _param:
	    salt_master_host: ${MASTER_IP:-$MASTER_HOSTNAME}
	    salt_master_base_environment: $SALT_ENV
	    salt_formula_branch: ${SALT_FORMULAS_BRANCH:-master}
	    reclass_data_revision: ${RECLASS_REVISION:-$RECLASS_BRANCH}
	    reclass_data_repository: "$RECLASS_ADDRESS"
	    reclass_config_master: ${MASTER_IP:-$MASTER_HOSTNAME}
	    linux_system_codename: ${DISTRIB_CODENAME}
	    cluster_name: ${CLUSTER_NAME}
	    cluster_domain: ${DOMAIN:-$CLUSTER_NAME.local}
	  linux:
	    system:
	      name: ${HOSTNAME:-cfg01}
	      domain: ${DOMAIN:-$CLUSTER_NAME.local}
	# ########
EOF

    cat <<-EOF >> ${CONFIG}
		  salt:
		    master:
		      accept_policy: open_mode
		      source:
		        engine: $SALT_SOURCE
		    minion:
		      source:
		        engine: $SALT_SOURCE
		# ########
		# vim: ft=yaml sw=2 ts=2 sts=2
EOF
  fi

  log_debug "Salt Master node config yaml:"
  log_debug "$(cat ${CONFIG})"
}

configure_salt_minion()
{
  [ ! -d /etc/salt/minion.d ] && mkdir -p /etc/salt/minion.d
  cat <<-EOF > /etc/salt/minion.d/minion.conf
	master: ${MASTER_IP:-$MASTER_HOSTNAME}
	id: $MINION_ID
	EOF
}

install_reclass()
{
  VERSION=${1:-$RECLASS_VERSION}
  VERSION=${VERSION:-pkg}
  case ${VERSION} in
      pkg|package)
        which reclass || $SUDO $PKGTOOL install -y reclass
        which reclass-salt || {
          if [ -e /usr/share/reclass/reclass-salt ]; then
               ln -fs /usr/share/reclass/reclass-salt /usr/bin
          fi
        }
        ;;
      *)
        log_warn "Install development version of reclass"
        # Note: dev/git/pip version...
        #       It replaces all local reclass versions on system
        # Required for reclass/git features:
        #       $SUDO $PKGTOOL install -y libffi-dev libgit2-dev || true
        for s in $(python -c "import site; print(' '.join(site.getsitepackages()))"); do
          sudo -H pip install --install-option="--prefix=" --upgrade --force-reinstall -I \
            -t "$s" git+https://github.com/salt-formulas/reclass.git@${VERSION};
        done
        ;;
  esac
}

install_salt_master_pkg()
{
    echo -e "\nPreparing base OS repository ...\n"

    configure_pkg_repo

    echo -e "\nInstalling salt master ...\n"

    case $PLATFORM_FAMILY in
      debian)
          $SUDO apt-get install -y git
          curl -L ${BOOTSTRAP_SALTSTACK_COM} | $SUDO sh -s -- -M ${BOOTSTRAP_SALTSTACK_OPTS} &>/dev/null || true
        ;;
      rhel)
          yum install -y git
          curl -L ${BOOTSTRAP_SALTSTACK_COM} | $SUDO sh -s -- -M ${BOOTSTRAP_SALTSTACK_OPTS} &>/dev/null || true
        ;;
    esac

    configure_salt_master

    echo -e "\nRestarting services ...\n"
    [ -f /etc/salt/pki/minion/minion_master.pub ] && rm -f /etc/salt/pki/minion/minion_master.pub
    $SVCTOOL salt-master restart
}

install_salt_master_pip()
{
    echo -e "\nPreparing base OS repository ...\n"

    case $PLATFORM_FAMILY in
      debian)
          $SUDO apt-get install -y python-pip python-dev zlib1g-dev git
        ;;
      rhel)
	  $SUDO yum install -y git
        ;;
    esac

    echo -e "\nInstalling salt master ...\n"
    # TODO: replace with saltstack bootstrap script

    if [ -z ${PIP_SALT_VERSION} ] || [ "$PIP_SALT_VERSION" == "latest" ]; then
      pip install salt
    else
      pip install salt==${PIP_SALT_VERSION}
    fi

    curl -Lo /etc/init.d/salt-master https://anonscm.debian.org/cgit/pkg-salt/salt.git/plain/debian/salt-master.init && chmod 755 /etc/init.d/salt-master
    ln -s /usr/local/bin/salt-master /usr/bin/salt-master

    configure_salt_master

    echo -e "\nRestarting services ...\n"
    [ -f /etc/salt/pki/minion/minion_master.pub ] && rm -f /etc/salt/pki/minion/minion_master.pub
    $SVCTOOL salt-master restart
}



install_salt_minion_pkg()
{

    echo -e "\nInstalling salt minion ...\n"

    case $PLATFORM_FAMILY in
      debian)
          curl -L ${BOOTSTRAP_SALTSTACK_COM} | $SUDO sh -s -- ${BOOTSTRAP_SALTSTACK_OPTS} &>/dev/null || true
      ;;
      rhel)
          curl -L ${BOOTSTRAP_SALTSTACK_COM} | $SUDO sh -s -- ${BOOTSTRAP_SALTSTACK_OPTS} &>/dev/null || true
      ;;
    esac


    configure_salt_minion
    #$SVCTOOL salt-minion restart
}

install_salt_minion_pip()
{
    echo -e "\nInstalling salt minion ...\n"

    curl -Lo /etc/init.d/salt-minion https://anonscm.debian.org/cgit/pkg-salt/salt.git/plain/debian/salt-minion.init && chmod 755 /etc/init.d/salt-minion
    ln -s /usr/local/bin/salt-minion /usr/bin/salt-minion

    configure_salt_minion
    #$SVCTOOL salt-minion restart
}

function install_salt_formula_pkg_all(){
    log_warn "Installing and configuring ALL formulas ..."
    if ! $SUDO apt-get install -y 'salt-formula-*'; then
      echo -e "\nInstall ALL formulas by mask 'salt-formula-*' failed.\n"
      exit 1
    fi
    for formula_service in $(ls ${FORMULAS_PATH}/reclass/service/); do
        #Since some salt formula names contain "-" and in symlinks they should contain "_" adding replacement
        formula_service=${formula_service//-/$'_'}
        if [ ! -L "${RECLASS_ROOT}/classes/service/${formula_service}" ]; then
            ln -sf ${FORMULAS_PATH}/reclass/service/${formula_service} ${RECLASS_ROOT}/classes/service/${formula_service}
        fi
    done
}

install_salt_formula_pkg()
{
    configure_pkg_repo

    case $PLATFORM_FAMILY in
      debian)
          echo "Configuring necessary formulas ..."

          [ ! -d ${RECLASS_ROOT}/classes/service ] && mkdir -p ${RECLASS_ROOT}/classes/service
          if [[ ${EXTRA_FORMULAS_PKG_ALL} =~ ^(True|true|1|yes)$ ]]; then
            install_salt_formula_pkg_all
            return
          fi
          # Set essentials if FORMULAS_SALT_MASTER is not defined at all
          [ -z ${FORMULAS_SALT_MASTER} ] && declare -a FORMULAS_SALT_MASTER=("linux" "reclass" "salt" "memcached")
          for formula_service in "${FORMULAS_SALT_MASTER[@]}"; do
              echo -e "\nConfiguring salt formula ${formula_service} ...\n"
              [ ! -d "${FORMULAS_PATH}/env/${formula_service}" ] && \
                  if ! $SUDO apt-get install -y salt-formula-${formula_service}; then
                    echo -e "\nInstall salt-formula-${formula_service} failed.\n"
                    exit 1
                  fi
              #Since some salt formula names contain "-" and in symlinks they should contain "_" adding replacement
              formula_service=${formula_service//-/$'_'}
              [ ! -L "${RECLASS_ROOT}/classes/service/${formula_service}" ] && \
                  ln -sf ${FORMULAS_PATH}/reclass/service/${formula_service} ${RECLASS_ROOT}/classes/service/${formula_service}
          done
        ;;
      rhel)
        # TODO
      ;;
    esac

    [ ! -d /srv/salt/env ] && mkdir -p /srv/salt/env || echo ""
    [ ! -L /srv/salt/env/prd ] && ln -s ${FORMULAS_PATH}/env /srv/salt/env/prd || echo ""
}

install_salt_formula_git()
{
    echo "Configuring necessary formulas ..."

    [ ! -d ${RECLASS_ROOT}/classes/service ] && mkdir -p ${RECLASS_ROOT}/classes/service
    # Set essentials if FORMULAS_SALT_MASTER is not defined at all
    [ -z ${FORMULAS_SALT_MASTER} ] && declare -a FORMULAS_SALT_MASTER=("linux" "reclass" "salt" "memcached")
    for formula_service in "${FORMULAS_SALT_MASTER[@]}"; do
        echo -e "\nConfiguring salt formula ${formula_service} ...\n"
        _BRANCH=${FORMULAS_BRANCH}
        [ ! -d "${FORMULAS_PATH}/env/_formulas/${formula_service}" ] && {
            if ! git ls-remote --exit-code --heads ${FORMULAS_BASE}/salt-formula-${formula_service}.git ${_BRANCH}; then
              # Fallback to the master branch if the branch doesn't exist for this repository
              _BRANCH=master
            fi
            if ! git clone ${FORMULAS_BASE}/salt-formula-${formula_service}.git ${FORMULAS_PATH}/env/_formulas/${formula_service} -b ${_BRANCH}; then
              echo -e "\nCloning of ${FORMULAS_BASE}/salt-formula-${formula_service}.git failed.\n"
              exit 1
            fi
          } || {
            cd ${FORMULAS_PATH}/env/_formulas/${formula_service};
            git fetch origin/${_BRANCH} || git fetch --all
            git checkout ${_BRANCH} && git pull || git pull;
            cd -
        }
        [ ! -L "/usr/share/salt-formulas/env/${formula_service}" ] && \
            ln -sf ${FORMULAS_PATH}/env/_formulas/${formula_service}/${formula_service} /usr/share/salt-formulas/env/${formula_service}
        [ ! -L "${RECLASS_ROOT}/classes/service/${formula_service}" ] && \
            ln -sf ${FORMULAS_PATH}/env/_formulas/${formula_service}/metadata/service ${RECLASS_ROOT}/classes/service/${formula_service}
    done

    [ ! -d /srv/salt/env ] && mkdir -p /srv/salt/env || echo ""
    [ ! -L /srv/salt/env/dev ] && ln -s /usr/share/salt-formulas/env /srv/salt/env/dev || echo ""
}

saltservice_stop() {
    set +e
    $SUDO service salt-minion stop
    $SUDO service salt-master stop
    sleep ${SALT_STOPSTART_WAIT:-30}
    ${SUDO} pkill -9 salt-master && ${SUDO} rm -rf /var/run/salt/master/* || true
    ${SUDO} pkill -9 salt-minion
}
saltservice_start() {
    set +e
    $SUDO service salt-master start
    $SUDO service salt-minion start
    sleep ${SALT_STOPSTART_WAIT:-30}
}

saltservice_restart() {
  set +e
  saltservice_stop
  saltservice_start
}

saltmaster_bootstrap() {

    log_info "Salt master setup"
    test -n "$MASTER_HOSTNAME" || exit 1

    # override some envs from cluster level *.env, use with care
    source_local_envs

    saltservice_stop

    clone_reclass

    SCRIPTS=$(dirname $0)

    test -e ${SCRIPTS}/.salt-master-setup.sh.passed || {
        export MASTER_IP=${MASTER_IP:-127.0.0.1}
        export MINION_ID=${MASTER_HOSTNAME}
        if ! [[ $DEBUG =~ ^(True|true|1|yes)$ ]]; then
          SALT_MASTER_SETUP_OUTPUT='/dev/stdout'
        fi
        # call local "setup() master"
        #if ! $SUDO ${SCRIPTS}/salt-master-setup.sh master &> ${SALT_MASTER_SETUP_OUTPUT:-/tmp/salt-master-setup.log}; then
        if ! setup master; then
          #cat /tmp/salt-master-setup.log
          log_err "salt master setup() failed."
          exit 1
        else
          $SUDO touch ${SCRIPTS}/.salt-master-setup.sh.passed
        fi
    }

    log_info "Install reclass"
    install_reclass ${RECLASS_VERSION/dev*/develop}

    log_info "Re/starting salt services"
    saltservice_restart
}

# Init salt master
saltmaster_init() {

    log_info "Runing saltmaster states"
    test -n "$MASTER_HOSTNAME" || exit 1

    set -e
    $SUDO salt-call saltutil.sync_all >/dev/null

    # workarond isolated and not fully bootstraped environments
    if [[ $RECLASS_IGNORE_CLASS_NOTFOUND =~ ^(True|true|1|yes)$ ]]; then
      SALT_MASTER_PILLAR='"salt":{"master":{"pillar":{"reclass":{"ignore_class_notfound": '${RECLASS_IGNORE_CLASS_NOTFOUND:-False}', "ignore_class_regexp": ["service.*"]}}}},'
    fi
    PILLAR='{'${SALT_MASTER_PILLAR}' "reclass":{"storage":{"data_source":{"engine":"local"}}} }'

    log_info "State: salt.master.env,salt.master.pillar"
    if ! $SUDO salt-call ${SALT_OPTS} state.apply salt.master.env,salt.master.pillar pillar="$PILLAR"; then
      log_err "State \`salt.master.env,salt.master.pillar pillar=$PILLAR\` failed, keep your eyes wide open!"
      if [[ $SA_IGNORE_ERROR_SALT_MASTER_ENV =~ ^(False|false|0|no)$ ]]; then
        exit 1
      fi

    fi

    # Revert temporary SaltMaster minimal configuration, if any
    pushd $RECLASS_ROOT
    if [ $(git diff --name-only nodes | sort | uniq | wc -l) -ge 1 ]; then
      PILLAR='{"reclass":{"storage":{"data_source":{"engine":"local"}}} }'
      git status || true
      log_warn "Locally modified $RECLASS_ROOT/nodes found. (Possibly salt-master minimized setup from bootstrap.sh call)"
      log_info "Checkout HEAD state of $RECLASS_ROOT/nodes/*."
      git checkout -- $RECLASS_ROOT/nodes || true
      log_info "Re-Run states: salt.master.env and salt.master.pillar according the HEAD state."
      log_info "State: salt.master.env,salt.master.pillar"
      if ! $SUDO salt-call ${SALT_OPTS} state.apply salt.master.env,salt.master.pillar pillar="$PILLAR"; then
        log_err "State \`salt.master.env,salt.master.pillar pillar=$PILLAR\` failed, keep your eyes wide open!"
        if [[ $SA_IGNORE_ERROR_SALT_MASTER_ENV =~ ^(False|false|0|no)$ ]]; then
          exit 1
        fi
      fi
    fi
    popd

    # finally re-configure salt master conf, ie: may remove ignore_class_notfound option
    log_info "State: salt.master.service"
    # ensure salt master is started
    saltservice_start
    retry ${SALT_STATE_RETRY} $SUDO salt-call ${SALT_OPTS} state.apply salt.master.service || true
    saltservice_start

    log_info "State: salt.master.storage.node"
    set +e
    # TODO:  PLACEHOLDER TO TRIGGER NODE GENERATION THROUG SALT REACT.
    # FIXME: PLACEHOLDER TO TRIGGER NODE GENERATION THROUG SALT REACT.
    retry ${SALT_STATE_RETRY} $SUDO salt-call ${SALT_OPTS} state.apply reclass.storage.node
    ret=$?

    set -e
    if [[ $ret -eq 2 ]]; then
        log_err "State reclass.storage.node failed with exit code 2 but continuing."
    elif [[ $ret -ne 0 ]]; then
        log_err "State reclass.storage.node failed with exit code $ret"
        exit 1
    fi

    set +e
    log_info "Updating minion.conf -> master: localhost"
    $SUDO sed -i 's/^master:.*/master: localhost/' /etc/salt/minion.d/minion.conf

    log_info "Re/starting salt services" # in order to load new deployed configuration from model
    saltservice_restart

    log_info "Salt Util sync all"
    $SUDO salt-call ${SALT_OPTS} saltutil.sync_all >/dev/null

    verify_salt_master

}

## CI Workarounds

function mockup_node_registration() {

  # for dynamic nodes registrations (require github.com/salt-formulas/salt-formula-reclass)

  source /etc/os-release
  os_codename=$VERSION_CODENAME
  domain=$(hostname -d)
  master_ip=$(hostname -I | awk '{print $1}')
  fake_ip_preffix=$(echo $master_ip | awk -F. '{print $1"."$2}')
  fake_ip_base=10

  # SHOULD BE ALREADY RUN AS A PART OF BOOTSTRAP
  # sync, in order to load custom modules
  #salt-call saltutil.sync_all

  # SHOULD BE ALREADY RUN AS A PART OF BOOTSTRAP
  #PILLAR='{"reclass":{"storage":{"data_source":{"engine":"local"}}} }'
  #salt-call state.apply reclass.storage.node  pillar="$PILLAR" > /dev/null 2>/dev/null || true

  # rotate over dynamic hosts
  for host_idx in {01..02};do
    for host in `salt-call pillar.items reclass:storage |grep '<<node_hostname>>' | awk -F_ '{print $NF}' | sed 's/[0-9]*//g' | egrep -v cfg | sort -u`; do
      hostname=${host}${host_idx}
      fake_ip_base=$(($fake_ip_base + 1))

      node_network01_ip="$fake_ip_preffix.11.$fake_ip_base"
      node_network02_ip="$fake_ip_preffix.12.$fake_ip_base"
      node_network03_ip="$fake_ip_preffix.13.$fake_ip_base"
      node_network04_ip="$fake_ip_preffix.14.$fake_ip_base"
      node_network05_ip="$fake_ip_preffix.15.$fake_ip_base"
      node_network01_iface=$(ls /sys/class/net/ | grep -v lo | sort | head -n1)
      node_network02_iface="eth1"
      node_network03_iface="eth2"
      node_network04_iface="eth3"
      node_network05_iface="eth4"

      declare -A vars
      vars=(
          ["node_master_ip"]=
          ["node_os"]=${os_codename}
          ["node_deploy_ip"]=${node_network01_ip}
          ["node_deploy_iface"]=${node_network01_iface}
          ["node_control_ip"]=${node_network02_ip}
          ["node_control_iface"]=${node_network02_iface}
          ["node_tenant_ip"]=${node_network03_ip}
          ["node_tenant_iface"]=${node_network03_iface}
          ["node_external_ip"]=${node_network04_ip}
          ["node_external_iface"]=${node_network04_iface}
          ["node_baremetal_ip"]=${node_network05_ip}
          ["node_baremetal_iface"]=${node_network05_iface}
          ["node_domain"]=$domain
          ["node_cluster"]=$(hostname -d |awk -F. '{print $1}')
          ["node_hostname"]=$hostname
      )

      data=""; i=0
      for key in "${!vars[@]}"; do
          data+="\"${key}\": \"${vars[${key}]}\""
          i=$(($i+1))
          if [ $i -lt ${#vars[@]} ]; then
              data+=", "
          fi
      done
      echo "Classifying node $hostname"
      NODECR='"node_name": "'${hostname}.${domain}'", "node_data": {'$data'}'
      PILLAR='{'${NODECR}', "reclass":{"storage":{"data_source":{"engine":"local"}}} }'
      salt-call state.apply reclass.reactor_sls.node_register pillar="$PILLAR" #-l info
      #salt-call event.send "reclass/minion/classify" "{$data}"
    done
  done

}

## VERIFY


function verify_salt_master() {
    set -e

    log_info "Verify Salt master"
    test -n "$MASTER_HOSTNAME" || exit 1

    if [[ $VERIFY_SALT_CALL =~ ^(True|true|1|yes)$ ]]; then
      $SUDO salt-call ${SALT_OPTS} --id=${MASTER_HOSTNAME} reclass.validate_yaml > /tmp/${MASTER_HOSTNAME}.reclass.validate_yaml
      $SUDO salt-call ${SALT_OPTS} --id=${MASTER_HOSTNAME} reclass.validate_pillar > /tmp/${MASTER_HOSTNAME}.reclass.validate_pillar
      $SUDO salt-call ${SALT_OPTS} --id=${MASTER_HOSTNAME} grains.item roles > /tmp/${MASTER_HOSTNAME}.grains.item.roles
      $SUDO salt-call ${SALT_OPTS} --id=${MASTER_HOSTNAME} state.show_lowstate > /tmp/${MASTER_HOSTNAME}.state.show_state
      $SUDO salt-call --no-color grains.items
      $SUDO salt-call --no-color pillar.data
    fi
    # TODO: REMOVE reclass --nodeinfo section / run only on debug - as the only required is reclass.validate_*
    if ! $SUDO python -m reclass.cli --nodeinfo ${MASTER_HOSTNAME} > /tmp/${MASTER_HOSTNAME}.reclass.nodeinfo; then
        log_err "For more details see full log /tmp/${MASTER_HOSTNAME}.reclass.nodeinfo"
        exit 1
    fi
    set +e
}

function verify_salt_minion() {
  set -e
  node=$1
  log_info "Verifying ${node}"
  if [[ $VERIFY_SALT_CALL =~ ^(True|true|1|yes)$ ]]; then
    $SUDO salt-call ${SALT_OPTS} --id=${node} grains.item roles > /tmp/${node}.grains.item.roles
    $SUDO salt-call ${SALT_OPTS} --id=${node} state.show_lowstate > /tmp/${node}.state.show_lowstate
  fi
  if ! $SUDO python -m reclass.cli --nodeinfo ${node} > /tmp/${node}.reclass.nodeinfo; then
      log_err "For more details see full log /tmp/${node}.reclass.nodeinfo"
      if [[ ${BREAK_ON_VERIFICATION_ERROR:-yes} =~ ^(True|true|1|yes)$ ]]; then
        exit 1
      fi
  fi
  set +e
}

function verify_salt_minions() {
    #set -e
    NODES=$(find $RECLASS_ROOT/nodes/_generated/ -name "*.yml" | grep -v "cfg")
    log_info "Verifying minions: $(echo ${NODES}|xargs)"

    # Parallel
    #echo $NODES | parallel --no-notice -j 2 --halt 2 "verify_salt_minion \$(basename {} .yml) > {}.pillar_verify"
    #ls -lrta *.pillar_verify | tail -n 1 | xargs -n1 tail -n30

    function filterFails() {
        grep -v '/grains' | tee -a $1 | tail -n20
    }

    log_info "Verify nodes"
    passed=0
    for node in ${NODES}; do
        node=$(basename $node .yml)

        # filter first in cluster.. ctl-01, mon-01, etc..
        if [[ "${node//.*}" =~ 01 || "${node//.*}" =~ 02  ]] ;then
            verify_salt_minion ${node} || continue
        else
            echo Skipped $node.
        fi
        passed=$(($passed+1))
    done
    # fail on failures
    total=$(echo $NODES | xargs --no-run-if-empty -n1 echo |wc -l)
    test ! $passed -lt $total || log_err "Results: $passed of $total passed."
    test ! $passed -lt $total || {
      tail -n50 /tmp/*.pillar_verify
      return 1
    }
    #set +e
}



##########################################
# To install salt master/minon

function install() {
  setup $@
}

function setup() {
  # CLI
  while [ x"$1" != x"" ]; do
    which curl &>/dev/null || $PKGTOOL -y install curl &>/dev/null

    case $1 in
        master )
          install_salt_master_$SALT_SOURCE
          install_salt_minion_$SALT_SOURCE
          install_salt_formula_$FORMULAS_SOURCE
          ;;
        minion )
          install_salt_minion_$SALT_SOURCE
          ;;
    esac
    shift
  done
  echo DONE
}

function bootstrap() {
  log_info "Bootstrap & verification of SaltMaster and configured minions."
  trap _atexit INT TERM EXIT

  system_config_master
  saltmaster_bootstrap &&\
  saltmaster_init #&&\
  #verify_salt_minions
}

function default() {
  bootstrap $@
}


##########################################
log_info "Running version: ${__ScriptVersion}"
log_info "Command line: '${__ScriptFullName} ${__ScriptArgs}'"

[[ "$0" != "$BASH_SOURCE" ]] || {
# unless file is being sourced
  default $@
}
