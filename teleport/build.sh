## 
### https://goteleport.com/teleport/installing/
###
#######################

# get the source & build:
$ mkdir -p $GOPATH/src/github.com/gravitational
$ cd $GOPATH/src/github.com/gravitational
$ git clone https://github.com/gravitational/teleport.git

# create the default data directory:
$ sudo mkdir -p /var/lib/teleport
$ sudo chown $USER /var/lib/teleport

# build:
$ cd teleport
$ make full
If the build succeeds the binaries will be placed in $GOPATH/src/github.com/gravitational/teleport/build

OTHER USEFUL MAKE TARGETS
# Build using Docker. In this case golang is not required:
$ make -C build.assets full

# Generate release tarball using Docker:
$ make -C build.assets release

#######################
#######################
