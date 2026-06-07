
##
#
https://github.com/Perl/docker-perl-tester
#
##

# Dockerfile

```
# perlapp-base will be common for all perl application build images
FROM alpine

RUN apk update && apk upgrade && apk add --no-cache curl tar make gcc build-base wget gnupg vim bash zlib zlib-dev openssl openssl-dev

RUN mkdir -p /usr/src/perl
WORKDIR /usr/src/perl

RUN curl -SLO https://www.cpan.org/src/5.0/perl-5.36.0.tar.gz \
    && echo 'e26085af8ac396f62add8a533c3a0ea8c8497d836f0689347ac5abd7b7a4e00a *perl-5.36.0.tar.gz' | sha256sum -c - \
    && tar --strip-components=1 -xaf perl-5.36.0.tar.gz -C /usr/src/perl \
    && rm perl-5.36.0.tar.gz \
    && ./Configure -des \
        -Duse64bitall \
        -Dcccdlflags='-fPIC' \
        -Dcccdlflags='-fPIC' \
        -Dccdlflags='-rdynamic' \
        -Dlocincpth=' ' \
        -Duselargefiles \
        -Dusethreads \
        -Duseshrplib \
        -Dd_semctl_semun \
        -Dusenm \
        -Dprefix='/opt/perl' \
    && make -j$(nproc) \
    && make install \
    && rm -fr /usr/src/perl /var/cache/apk

WORKDIR /opt/perl
ENV PATH="/opt/perl/bin:${PATH}"

RUN curl -o /tmp/cpm -sL --compressed https://git.io/cpm \
    && chmod 755 /tmp/cpm \
    && /tmp/cpm install -g App::cpm IO::Socket::SSL Cpanel::JSON::XS \
    && rm -fr /root/.perl-cpm /tmp/cpm

RUN apk del zlib-dev openssl-dev

ONBUILD WORKDIR /tmp
ONBUILD COPY cpanfile /tmp/cpanfile
ONBUILD RUN cpm install -g && rm -rf /tmp/cpanfile
```


# Dockerfile


```
ARG BASE
ARG CPANOUTDATED
FROM perl:${BASE}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY cpanfile /tmp/

RUN perl -V

RUN apt-get update && \
        apt-get dist-upgrade -y && \
        apt-get -y --no-install-recommends install aspell aspell-en

RUN cpanm --self-upgrade || \
    ( echo "# Installing cpanminus:"; curl -sL https://cpanmin.us/ | perl - App::cpanminus )

RUN cpanm -nq App::cpm Carton::Snapshot

RUN cpm install -g --show-build-log-on-failure --cpanfile /tmp/cpanfile

RUN if [ "x${CPANOUTDATED}" = "x1" ] ; then cpan-outdated --exclude-core -p | xargs -n1 cpanm ; else cpan-outdated --exclude-core -p; fi

WORKDIR /tmp/
RUN git clone https://github.com/perl-actions/ci-perl-tester-helpers.git --depth 1 && \
    cp ci-perl-tester-helpers/bin/* /usr/local/bin/ && \
    rm -rf ci-perl-tester-helpers && \
    git config --system --add safe.directory '*'

CMD ["/bin/bash"]
```


Owner avatar
docker-perl-tester
Public
Perl/docker-perl-tester
Go to file
t
Add file
Folders and files
Name		
Latest commit
atoomic
atoomic
Merge pull request #59 from Perl/oalders/fix-build
4eef95a
 · 
3 months ago
History
.github
Use perl-actions/perl-versions to build perl-versions matrix
5 months ago
.gitignore
Use GitHub action to build and publish the images
5 years ago
Dockerfile
Add safe.directory at system rather than global
last year
README.md
Bump actions/checkout version in README
7 months ago
cpanfile
Plack 1.0051 bumps from 5.8.1 to 5.12
3 months ago
Repository files navigation
README
docker-perl-tester
This repo is used to build Perl Docker images with various pre-installed bits:

the aspell and aspell-en packages
cpanminus
App::cpm
Devel::Cover
various testing modules
Dist::Zilla with some common plugins (for Perl >= 5.20)
At this points images are refreshed daily, which could change overtime if it becomes an issue. This should guarantee you to test uptodate CPAN stack.

Note: if one dependency fails to install, this should not impact you as the image would not be published on failures.

List of Perl modules
See also the cpanfile in this repo for an up to date list of available modules.

Available on all Perl Versions
Code::TidyAll::Plugin::SortLines::Naturally
Code::TidyAll::Plugin::UniqueLines
Devel::Cover
Devel::Cover::Report::Codecov
Devel::Cover::Report::Coveralls
ExtUtils::MakeMaker
File::Temp
List::MoreUtils
Module::Build
Pod::Coverage::TrustPod
Test2::Bundle::Extended
Test2::Plugin::NoWarnings
Test2::Suite
Test2::Tools::Explain
Test::Builder
Test::CPAN::Meta
Test::Deep
Test::Differences
Test::EOL
Test::Fatal
Test::MinimumVersion
Test::MockModule
Test::Mojibake
Test::More
Test::Needs
Test::Notabs
Test::Pod
Test::Pod::Coverage
Test::Portability::Files
Test::RequiresInternet
Test::Simple
Test::Spelling
Test::Synopsis
Test::Version
Test::Warnings
Only on Perl 5.10 and later
Code::TidyAll::Plugin::Test::Vars
Test::Vars
Only on Perl 5.12 and later
Pod::Readme
Only on Perl 5.20 and later
Dist::Zilla & friends
Dist::Zilla::PluginBundle::Author::ETHER
Using Docker Images for your projects
The images can be found at https://hub.docker.com/repository/docker/perldocker/perl-tester/

The following tags are available from the repository perldocker/perl-tester

devel
5.38
5.36
5.34
5.32
5.30
5.28
5.26
5.24
5.22
5.20
5.18
5.16
5.14
5.12
5.10
5.8
devel build
Note that the devel build was added to test on the current Perl development version. (example: 5.37.8, ) This is tracking the last Perl devel version released.

OS flavor
At this time all the images built are based on buster distro.

Continuous Integrations
Using the images with GitHub Workflow
Here is a sample workflow for Linux running on all Perl version 5.8 to 5.38 You can save the content in .github/workflow/linux.yml.

Note: this example is using cpm to install the dependencies from a cpanfile. You can comment this line or use Dist::Zilla instead for supported Perl versions.

name: linux

on:
  push:
    branches:
      - '*'
    tags-ignore:
      - '*'
  pull_request:

jobs:
  perl:
    env:
      # some plugins still needs this to run their tests...
      PERL_USE_UNSAFE_INC: 0
      AUTHOR_TESTING: 1
      AUTOMATED_TESTING: 1
      RELEASE_TESTING: 1

    runs-on: ubuntu-latest

    strategy:
      fail-fast: false
      matrix:
        perl-version:
          - '5.38'
          - '5.36'
          - '5.34'
          - '5.32'
          - '5.30'
          - '5.28'
          - '5.26'
          - '5.24'
          - '5.22'
          - '5.20'
          - '5.18'
          - '5.16'
          - '5.14'
          - '5.12'
          - '5.10'
          - '5.8'

    container:
      image: perldocker/perl-tester:${{ matrix.perl-version }}

    steps:
      - uses: actions/checkout@v4
      - name: perl -V
        run: perl -V
      - name: Install Dependencies
        run: cpm install -g --no-test --show-build-log-on-failure --cpanfile cpanfile
      - name: Makefile.PL
        run: perl Makefile.PL
      - name: make test
        run: make test
Using Helper scripts
The scripts from perl-actions/ci-perl-tester-helpers are available in the path of each container. These scripts can build and test dists for you in various scenarios. See https://github.com/Perl-Critic/PPI/blob/master/.github/workflows/dzil-build-and-test.yml for an example of how to use the helpers to build and tests a Perl distribution.

More Examples
You can find more details on how to setup GitHub workflow to smoke Perl projects by reading skaji/perl-github-actions-sample GitHub repository.

Using GitHub actions
You can also consider using GitHub actions:

perl-actions/install-with-cpanm
perl-actions/install-with-cpm
Building Docker images
When pushing to GitHub, it's using a GitHub action .github/workflows/publish-to-docker.yml to automagically build and publish the docker images for you.

If you consider cloning this repository, you would have to set in your GitHub repository the following secret variables, with some example values.

DOCKER_REPO=perldocker/perl-tester
DOCKER_USERNAME=username
DOCKER_GITHUB_TOKEN=a-token-or-password
Developer Notes:
The main branch is named main and not master.

Author
@oalders initiated the project and @atoomic tried to give it more public visibility volunteers/ideas are welcome to improve the project.
