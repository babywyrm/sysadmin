#!/usr/bin/env bash
######################
##
##  _legit_for_OSx__
##
######################

if ! command -v bolt ; then
  brew cask install puppetlabs/puppet/puppet-bolt
fi

mkdir -p ~/.puppetlabs/bolt/

(cd bolt && cp \
    bolt.yaml \
    Puppetfile \
    ~/.puppetlabs/bolt/)

bolt puppetfile install
                         

#####################################
