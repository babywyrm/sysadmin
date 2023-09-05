# Conceptual SBOM model for an APT-based Linux distribution

##
#
https://gist.github.com/bureado/29e5da5fbf30fcb9bdde83d6c8f6d1b8
#
##


This is a draft of an entirely exploratory learning exercise to generate SBOMs from first principles that can accompany an APT-based Linux distribution, which in this context is either a disk or a container image obtained from any source including runtime instances, packaged images, debootstraps, etc. Input and comments welcome: [Twitter](https://twitter.com/bureado) and also on the CNCF, CycloneDX, CDF, Sigstore and other Slacks.

## Status

Here's the [current version of the output](https://gist.github.com/bureado/332dee67a368a377c23c29911145edbf) (SPDX) which features:

* Identifying information for the primary component (at this time, the `debian:latest` container image)
* `purl` identifiers for each binary package in the image
* Package name, version, architecture, SHA256 hashes from the package manager
* Declared licenses for each package, in machine-readable SPDX, from the binary packages' `copyright` files

Currently working on: `debsums` check, file declarations and subordinate SBOM generation. See [other flavors](https://gist.github.com/bureado/29e5da5fbf30fcb9bdde83d6c8f6d1b8#what-does-the-output-look-like) for more.

## Early learning/prelim work

* We are using [SwiftBOM](https://sbom.democert.org/sbom/) for a manual approximation to the problem
* We are focusing on the [NTIA-recommended fields](https://youtu.be/EVnQ4Riecy8?t=1573), all of which should be readily available in the local state of an APT-based Linux environment
  * We might need to acknowledge some transitive trust. For example, if we say a `Component` is a `Package`, then what should go in the hash of the `Package`? The only package hash we can get from the local APT state is what's in the repo indices as they were last fetched. The hashes may or may not match the package hash that was used to install the files in the local filesystem.
* It's possible we'll focus first on producing an SPDX document
  * As per SwiftBOM, there must be a `PrimaryComponent`, which in this case is likely to be the "instance" itself.
  * Subsequent components can have `PrimaryComponent` as `Parent`.
  * SwiftBOM allows using [CPE](https://nvd.nist.gov/products/cpe) to specify the component, which in turn allows for fetching vulnerability data.
* After the initial approximation to SwiftBOM, we mock up some initial SPDX, CycloneDX and SWID SBOMs and move to the actual model.
* Doing this all as a shellscript for simplicity.

## Model narrative

We `podman pull debian:latest`. We want to generate a SBOM for what we just pulled. The primary component in our SBOM is necessarily `purl pkg:docker/debian@latest`, more specifically: `purl pkg:docker/debian@acf7795dc91df17e10effee064bd229580a9c34213b4dba578d64768af5d8c51`.

Note that `podman` calls this image `docker.io/library/debian`, tag `latest`, ID `4a7a1f401734`. But `podman image inspect debian` provides enough disambiguation.

   For the curious, `podman history debian` will show (in my `amd64` system and `@1623906463`): `ADD file:1a1eae7a82c66d673971436ce2605e97d107e2934b7cdec876c64923ae6f4f85 in /` which should technically derive from [this](https://github.com/debuerreotype/docker-debian-artifacts/blob/dist-amd64/stable/rootfs.tar.xz.sha256) but I'm losing the traceability here.

   For that, some bridges like [docker-library/repo-info](https://github.com/docker-library/repo-info/blob/master/repos/debian/remote/latest.md#debianlatest---linux-amd64) might be necessary. This angle seems promising, but see also [package management and container metadata](https://nishakm.github.io/code/metadata/) for the more general problem of containers (the APT approach discussed here should also work for the more general problem of APT systems of all kinds)

Back to our narrative. The `PrimaryComponent` will be this image. What is this image? This is effectively Debian 10.9 (as per `/etc/debian_version`) for the `amd64` architecture, so we might as well use CPE and register it as such. And we should be able to add a hash for it (the hash of the image)

Good. Now it's time for the laborious part of detecting all the components inside this image. Intuitively, the components are all either packages, or files that are extraneous to a package. But we suspect from [docker-debian-artifacts](https://github.com/debuerreotype/docker-debian-artifacts/tree/dist-amd64/stable) that not many extraneous files (that matter for an SBOM) should be present in there.

If we trusted this chain programmatically, we could use [rootfs.manifest](https://github.com/debuerreotype/docker-debian-artifacts/blob/dist-amd64/stable/rootfs.manifest) in tandem with [sources.list-snapshot](https://github.com/debuerreotype/docker-debian-artifacts/blob/dist-amd64/stable/rootfs.sources-list-snapshot) to complete this task. It would look like this:

* Fetch the `Packages` index from the `snapshot.debian.org`
* For each package:version tuple in manifest:
  * Assemble a `purl` URI
  * Fetch the package version
  * Declare a relationship to the root component
  * Using the `Packages` index, extract the `SHA256` hash
  * Add an annotation on something potentially valuable (see below)

If we didn't trust the chain, we can do this entirely in-image by switching the repos in `/etc/apt/sources.list` to the snapshot, fetching lists and processing in-image. (As a follow-up note, it doesn't look like we need to go back in time to fetch indices as the `debian:latest` image has enough in `/var/lib/dpkg` to help complete the SBOM. But it could be useful in other type of scenarios.)

### What does the output look like?

* [Basic SPDX output for the `debian:latest` image](https://gist.github.com/bureado/332dee67a368a377c23c29911145edbf)
  * The output is roughly equivalent to `syft debian:latest`, even with `-o cyclonedx`: you get version, architecture, licenses.
    * `syft` does a lot of things really close to what I'm describing here, the main problem right now being the inability (at least for me) of scanning arbitrary `dir:` sources ([see this](https://github.com/anchore/syft/issues/119)) and a secondary problem for me is poor support for `podman`
      * Beyond the tool hiccups, the other aspects where the approach laid out here differs from `syft` is the description of the parent or primary component. Common gaps between this approach and `syft` are determining what are implicit and explicit dependencies or manually installed packages. And a place where `syft` is great out of the box is CPE output, and the fact that it can run other scanners (say, for golang or Python, see the section around "Files"). Another aspect to look into is the relationships (see all commentary in this document about dependencies) because `syft` has none. And note that with `syft-v0.17.1-SNAPSHOT-706322f` there's SPDX output support. 
* [SPDX output for `debian:latest` plus a few dependencies](https://gist.github.com/bureado/442b95d9390370d0d7495a4872ef95f8) (libapache2-mod-php7.3 postgresql and etcd-server)
* [SPDX output for a `stable` `debootstrap` with `npm`](https://gist.github.com/bureado/b90174d6b4f968a0089097ce32a2423e) (done from outside of the `chroot`)
* [SPDX output for a running container that has been `podman export` into disk](https://gist.github.com/bureado/6cab8aeeb9b4753e310990b58913fc1a) and analysis performed in disk image (`podman export foo | tar xf - -C chroot/`)

A brief note on SPDX validity: it's hard. Neither my output or `syft`'s passes the online validator, usually because of extraneous SPDX Package IDs or issues with licenses.

### What can client-only introspection feed the SBOM?

Package name and version, source name and version, maintainer (unlikely to be useful in this context), dependencies (unlikely to be meaningful in this context), and a flag of whether it was manually installed or not (unlikely in this example).

It should also be possible to fetch an SPDX license identifier for many packages by inspecting `/usr/share/doc/<pkg>/copyright` for `^License:` (done.)

### What about `PackageDownloadLocation`?

**TODO**.

### How can public Debian infrastructure enhance the SBOM?

Sources location, potentially upstream repo, vulnerability information and [buildinfo](https://wiki.debian.org/ReproducibleBuilds/BuildinfoFiles) fields such as build environment characteristics, then the sky is the limit but starts with reproducibility information and many techniques for tracing back to the originating sources.

## Source vs. binary packages

**TODO**, currently we're recording binary packages, but source packages would probably be meaningful. See commentary on flat SBOM below.

## And what about manually-installed packages? (or from PPA, etc.)

**TODO**

## And what about files?

There are three elements to this question. The first one is to ensure that the hash that is recorded for each package somehow matches the hashes of the files in the disk, at least for every file that is not a conffile. This can be done by running `debsums -c`. If `debsums` has no output, we can assume for practical purposes that the hash of the package as recorded in the SBOM represents the hashes of the files on disk (Can we? This depends on how representative `/var/lib/dpkg/available` is)

The second element is how to record _additional_ files that might be in the system. This can be done with a tool like `cruft`. The question is - are those files conffiles, or are they a software component that belongs in the SBOM? It's relatively easy to hash and run an SPDX license detector on the file and then add it to the SBOM, but that first determination (is this software?) is a bit harder. Approaches here range from `file` to buildpacks.

The third element is emitting subordinate SBOMs for other components that might be found in the system, such as a `package.json`, an RPM specfile or similar. Here we would need some heuristics to call specific SBOM generators and link them to our main manifest.

## And what about dependencies?

One of the most readily available pieces of metadata is dependency information, which isn't reflected in the SBOM, making it "flat". It's possible to make a treeful SBOM, but it would make more sense in cases where the tree doesn't need to be constructed from the scattered leafs. For example, a `for pkg in dpkg --selections do dpkg -p $pkg | grep SHA256` to assemble a package:version:hash tuple that can be used as a `purl` (or similar) identifier so that each `PackageName` section is spared in favor of `Relationship` stanzas for the primary component.

There's a separate discussion on whether `Build-Dependencies` or `Built-Using` dependencies could be worth capturing here.

It's likely this will be determined by consumer consensus, because it'll be semantic. For the examples here I use the [SwiftBOM approach](https://github.com/CERTCC/SBOM/tree/master/SwiftBOM#sbom-formats), but [read this](https://spdx.github.io/spdx-spec/7-relationships-between-SPDX-elements/#71-relationship) for the full descriptive approach of SPDX.

## Do I need to run this inside the container?

No, of course not. You can extract files from the container and analyze outside of it. Some tools like `dpkg` can be pointed to a different root. Examples **TODO**.

## How do I store this?

**TODO**, there seems to be a growing consensus that SBOMs should live along their artifacts, but different techniques going around.

## How do I consume this?

**TODO**, even though it's likely the most important part!

## How do you generalize it (e.g., for Ubuntu)?

**TODO**

## How do you expand it to other distros?

**TODO**

## Why is this useful?

There's no shortage of progress on SBOM generation and, more broadly, software supply chain security research happening right now. When you see [demos like this one](https://twitter.com/lorenc_dan/status/1407898416483639296), you notice it's using the SPDX SBOM generator tool and you know that doesn't support Linux packages yet. So you imagine that the outputted SBOM, while it can be signed and pushed to a registry, is probably... slim at best. And upon close inspection of the demo you see that the lines before `go mod` that didn't make it into a captured frame are likely to be... a Linux distro. Sure enough once you download the resulting image you see it was... `debian:latest`.
