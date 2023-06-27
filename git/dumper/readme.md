
##
https://gist.github.com/magnetikonline/5faab765cf0775ea70cd2aa38bd70432
##

Extract all files at every commit of a Git repository.
README.md
Extract all files at every commit of a Git repository
Bash script to iterate all commits of a given Git repository and extract all files within each commit.

Example
With a Git repository at /path/to/repository and an empty directory at /path/to/output we can run:

./export.sh /path/to/repository /path/to/output

Export 1d9048853b8073e43e43e3250300a82f93d2f431 -> /path/to/output/1d9048853b8073e43e43e3250300a82f93d2f431
Export 5bbaa3bb20b8cb2517b12e9bfb6bc7aef666b9a9 -> /path/to/output/5bbaa3bb20b8cb2517b12e9bfb6bc7aef666b9a9
Export fc56f7e038c272fbdd5e609c508de10056e74278 -> /path/to/output/fc56f7e038c272fbdd5e609c508de10056e74278
Export 75355bae79b22481007e4be13d13a387b7b1df0b -> /path/to/output/75355bae79b22481007e4be13d13a387b7b1df0b
Export d9e4a5742359610028597061babc19d76a937936 -> /path/to/output/d9e4a5742359610028597061babc19d76a937936
Target path /path/to/output will now contain directories named as each Git commit SHA-1.


  ```
export.sh
#!/bin/bash -e

function getRepoSHA1List {
	pushd "$1" >/dev/null
	git rev-list --all
	popd >/dev/null
}

function exportCommits {
	local commitSHA1

	local IFS=$'\n'
	for commitSHA1 in $(getRepoSHA1List "$1"); do
		# build export directory for commit and create
		local exportDir="${2%%/}/$commitSHA1"
		echo "Export $commitSHA1 -> $exportDir"
		mkdir --parents "$exportDir"

		# create archive from commit then unpack to export directory
		git \
			--git-dir "$1/.git" \
			archive \
			--format tar \
			"$commitSHA1" | \
				tar \
					--directory "$exportDir" \
					--extract
	done
}


# verify arguments
if [[ (! -d $1) || (! -d $2) ]]; then
	echo "Usage: $(basename "$0") GIT_DIR OUTPUT_DIR"
	exit 1
fi

if [[ ! -d "$1/.git" ]]; then
	echo "Error: it seems [$1] is not a Git repository?" >&2
	exit 1
fi

exportCommits "$1" "$2"

##
##
##
@MarcusJohnson91
MarcusJohnson91 commented on Mar 31, 2020
--parents isn't a thing in anything but gnu mkdir, use -p for portability.
