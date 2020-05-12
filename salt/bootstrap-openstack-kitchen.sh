#!/bin/bash -xe
##
##
###############
##
##
##
################
# We do install from sources, as ohaio gem requires ruby2.4+, while Ubuntu xenial has 2.3 only
# If we want to have yet another ppa instead of sources build, just replase it.
# TODO(dstremkouski). Check if ppa is applicable here.
apt update
apt -y install python-pip autoconf bison build-essential libssl-dev libyaml-dev libreadline6-dev zlib1g-dev libncurses5-dev libffi-dev libgdbm3 libgdbm-dev wget git ruby-dev curl dnsutils rbenv
pip install PyYAML
pip install virtualenv

git clone https://github.com/rbenv/rbenv.git ~/.rbenv
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init -)"' >> ~/.bashrc
source ~/.bashrc
type rbenv
git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build
rbenv install 2.5.0
rbenv global 2.5.0
gem install kitchen-openstack
gem install berkshelf
gem install bundler
cat > Gemfile <<EOF
source 'https://rubygems.org'
gem 'rake'
gem 'test-kitchen'
gem 'kitchen-inspec'
gem 'inspec'
gem 'kitchen-salt', :git => 'https://github.com/salt-formulas/kitchen-salt.git'
EOF
bundle install
