##
## https://gist.github.com/ecliptik/9a868cbe348d87a5141a
##
## https://github.com/cpanel/docker-perl-compiler
##

#Dockerfile
```
#This Dockerfile uses a Multi-Stage Build: https://docs.docker.com/develop/develop-images/multistage-build/
FROM debian:stable-slim AS base
LABEL maintainer="Micheal Waltz <dockerfiles@ecliptik.com>"

# Environment
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    LC_ALL=C.UTF-8 \
    LANGUAGE=en_US.UTF-8

# Install runtime packages
RUN apt-get update \
    && apt-get install -y \
      perl

# Set app dir
WORKDIR /app

# Intermediate build layer
FROM base AS build
#Update system and install packages
RUN apt-get update \
    && apt-get install -yq \
        build-essential \
        cpanminus

# Install cpan modules
RUN cpanm Proc::ProcessTable Data::Dumper

# Runtime layer
FROM base AS run

# Copy build artifacts from build layer
COPY --from=build /usr/local /usr/local

# Copy perl script
COPY ./ps.pl .

# Set Entrypoint
ENTRYPOINT [ "/app/ps.pl" ]

```
output.txt
```

PID    TTY        STAT     START                    COMMAND
1      /dev/pts/0 run      Fri Sep 11 17:45:16 2020 /usr/bin/perl -w /app/ps.pl
--------------------------------
uid:  0
gid:  0
pid:  1
fname:  ps.pl
ppid:  0
pgrp:  1
sess:  1
ttynum:  34816
flags:  4210944
minflt:  1684
cminflt:  0
majflt:  0
cmajflt:  0
utime:  40000
stime:  10000
cutime:  0
cstime:  0
priority:  20
start:  1599846316
size:  12779520
rss:  8192000
wchan:  0
time:  50000
ctime:  0
state:  run
euid:  0
suid:  0
fuid:  0
egid:  0
sgid:  0
fgid:  0
pctcpu:    5.00
pctmem:  0.07
cmndline:  /usr/bin/perl -w /app/ps.pl
exec:  /usr/bin/perl
cwd:  /app
cmdline:  ARRAY(0x55fb475bb9f0)
environ:  ARRAY(0x55fb472dd500)
tracer:  0

```
ps.pl
```
#!/usr/bin/perl -w

use strict;
use Getopt::Std;
use Proc::ProcessTable;

# declare the perl command line flags/options we want to allow
my %options=();
getopts("hv", \%options);

if ($options{h})
{
  show_help();
}

if ($options{v})
{
  show_version();
}

sub show_help {
  print "A simple perl version of ps";
  exit;
}

sub show_version {
  print "Version: 1.0";
  exit;
}

#Example from: http://search.cpan.org/~durist/Proc-ProcessTable-0.39/ProcessTable.pm
my $FORMAT = "%-6s %-10s %-8s %-24s %s\n";
my $t = new Proc::ProcessTable;
printf($FORMAT, "PID", "TTY", "STAT", "START", "COMMAND");
foreach my $p ( @{$t->table} ){
  printf($FORMAT,
         $p->pid,
         $p->ttydev,
         $p->state,
         scalar(localtime($p->start)),
         $p->cmndline);
}


# Dump all the information in the current process table
use Proc::ProcessTable;

$t = new Proc::ProcessTable;

foreach my $p (@{$t->table}) {
 print "--------------------------------\n";
 foreach my $f ($t->fields){
   print $f, ":  ", $p->{$f}, "\n";
 }
}
