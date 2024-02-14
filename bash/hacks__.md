# More Stupid Bash Tricks

##
# https://gist.github.com/tsutsu/2c11fc0a36000a46566e9fd62c60dea4
##

### Before we get started, let's make a `~/.bash` directory

Bash expects just a few files in your homedir, but is fine with these files
being symlinks. As such, I instead create a subdir, `~/.bash`, and then symlink
`~/.bashrc` to `~/.bash/bashrc` and `~/.bash_profile` to `~/.bash/bash_profile`. This
gives you a new namespace (the `~/.bash` dir) to pollute with little files, which we're
going to do plenty of below.

Additionally, I sync my `~/.bash` dir (among others) between multiple machines,
by moving it into some file-sync program's managed directory-subtree (I use
iCloud, but you can use Dropbox or any of [these dotfile managers](https://dotfiles.github.io).)
Personally, I create a `Preferences` dir within the root of the file-sync subtree,
and drop the bash dir in there, such that my `~/.bash` points to e.g. `~/Documents/Preferences/bash`.

If you're not interested in syncing, though, I'd suggest instead making a `~/.config/bash`,
and pointing your `~/.bashrc` and `~/.bash_profile` into there. There's no reason for so many things
to reside directly in your homedir. We live in a society!

### Also, a note on macOS and `XDG_CACHE_HOME`

On macOS, software following the FreeDesktop.org filesystem standard will default
to storing cache data in `~/.cache`. macOS (and macOS "disk cleaner" apps) are
unaware of `~/.cache`. They expect cache files to live under `~/Library/Caches`. They
do special things with `~/Library/Caches`, like considering this disk space "free to use"
(as macOS knows how to purge many of these caches—at least the CoreData-managed ones—to reclaim space.)
As well, some backup software avoids backing up `~/Library/Caches`. Well, you probably don't want your
`pipenv`s or `gem` build cache backed up either, right?

The FreeDesktop.org standard requires these apps to reference the env-var `XDG_CACHE_HOME`
for the location of the cache dir. Thus, on macOS, you can just define this env-var to point into `~/Library/Caches`,
and macOS frameworks and apps will suddenly understand that these files are cache files.

Because of potential namespace collisions, you should probably create a subdirectory
for these FreeDesktop.org programs. Following the convention, I call this
subdirectory `org.freedesktop/`. This goes in `~/.bash/bashrc`:

```bash
export XDG_CACHE_HOME="$HOME/Library/Caches/org.freedesktop"
mkdir -p "${XDG_CACHE_HOME}"
```

Then, restart (to ensure nothing is going to write to `~/.cache` any more),
and then blow away your `~/.cache` dir. You might want to symlink `~/.cache`
to `~/Library/Caches/org.freedesktop` as well, for those programs that don't actually
obey XDG but just hardcode the config path. (Haven't encountered any yet, but it's
always a possibility.)

## `bin/` directories

Putting aside all the system `$PATH` elements, I have multiple *personal* `bin/` directories, all living
under my homedir. If you're a software developer, you probably do too!

* A git repo of scripts I've written.
* The FreeDesktop.org binary install location, `~/.local/bin`.
* A collection of binaries I've compiled and want to have available to every
  system I use, that live within a cloud-synced directory.
* Install directories for various runtimes:
  * `go install`, a.k.a. `$GOBIN`
  * `cargo install`
  * `gem install`, if you have a portable Ruby
  * etc.

Here are two strategies for keeping track of all these directories. In each strategy,
only the directories available on *this machine* will end up in `$PATH`.

(Yes, I know that this filtering is not *strictly* necessary, as shells will ignore
non-existent `$PATH` elements. But I believe that 1. it trades off a tiny `O(1)` increase
in Bash startup time, for `O(N)` quicker invocations of commands; and 2. it means
you can be sloppier when writing one-off scripts that deal with your `$PATH`, as you
can assume existence.)

#### `bin/`-management strategy 1: a `~/.bash/taps` file

```bash
while IFS='' read -r tap_dir || [[ -n "${tap_dir}" ]]; do
  tap_dir="$(eval echo -e "${tap_dir}")"

  if [ -d "${tap_dir}" ]; then
    PATH="${tap_dir}:$PATH"
  fi
done < "$HOME/.bash/taps"
```

A `taps` file is a newline-separated list of `bin/` paths. I prefer this; it's simpler
to edit and manage. Every time I learn about some new location something has chosen
to throw binaries into, I can just add a line here. I even use this in place of
an actual `export PATH=` stanza in my `~/.bash/bashrc`. So it has entries like this:

    /usr/local/sbin
    /Applications/Postgres.app/Contents/Versions/latest/bin
    $ENV_ROOT/bin
    /usr/local/opt/ruby/bin
    /usr/local/opt/ruby/libexec/gembin
    /usr/local/opt/python/bin
    /usr/local/opt/python/libexec/bin
    /usr/local/opt/fzf/bin

Note that each line is `eval`ed by Bash, so you can use env-vars in these paths.

#### `bin/`-management strategy 2: a `~/.bins` directory

```bash
if [ -d "$HOME/.bins" ]; then
  for bin_dir in "$HOME/.bins/"*; do
    resolved_bin_dir="$(readlink "${bin_dir}")"

    if [ -d "${resolved_bin_dir}" ]; then
      PATH="${resolved_bin_dir}:$PATH"
    fi
  done
fi
```

This strategy adds a layer of indirection. I manage a `~/.bins` directory separate
from Bash, which contains symlinks pointing to `bin/` directories.

Each symlink represents a mapping from a "common name" for a bin-dir, to its location
on *this* system. This is useful when you commonly switch between Linux and macOS;
you can use the locations of the `~/.bins` symlinks themselves as references in
other scripts you write, rather than needing to do OS-detection in those scripts.

Here's what's in my `~/.bins`, to give you an idea:

    $ ls -lah ~/.bins
    Permissions Size User   Date Modified Name
    lrwxr-xr-x    24 tsutsu  7 Aug 11:05  freedesktop -> /Users/tsutsu/.local/bin
    lrwxr-xr-x    50 tsutsu 16 Apr 10:50  golang -> /Users/tsutsu/Library/Caches/org.golang/gopath/bin
    lrwxr-xr-x    42 tsutsu  9 Apr  2018  rust -> /Users/tsutsu/Library/Caches/rs.rustup/bin
    lrwxr-xr-x    50 tsutsu  9 Apr  2018  scripts -> /Users/tsutsu/Documents/Bundles/Scripts.bundle/bin

You might find that either strategy, used on its own, solves 100% of your problem. Personally, I find it helpful to use both together.

## Bash Hooks

```bash
if [ -d "$HOME/.bash/hooks" ]; then
  for hook_script in "$HOME/.bash/hooks/"*; do
    if [ ! -x "${hook_script}" ]; then
      continue
    fi

    reqs=($(basename "${hook_script}" | tr '+' "\n"))
    satisfied_reqs=0

    for req in "${reqs[@]}"; do
      if hash "${req}" 2>/dev/null; then
        satisfied_reqs="$((satisfied_reqs+1))"
      fi
    done

    if [ "${#reqs[@]}" -eq "${satisfied_reqs}" ]; then
      source "${hook_script}"
    fi
  done
fi
```

This is one I'm somewhat proud of. The `~/.bash/hooks` directory contains scripts to
be sourced by bash. Each of these scripts contains a series of commands to execute iff
a specified set of command binaries are all available in `$PATH`. Each script file is
named after the commands it requires, joined by a `+`.

This means that, for example, you can create Bash `alias`es that only get defined if the
command they're implemented "on top of" exists.

This is also a good place to put all those things that programs tell you to put in
your `~/.bash_profile` to make them work. For example:

```bash
$ cat ~/.bash/hooks/direnv
eval "$(direnv hook bash)"
```

This command now won't screw up your Bash startup if you haven't installed `direnv`.

Hooks are *also* good for defining env-vars:

```bash
$ cat ~/.bash/hooks/less
export CLICOLOR=1
export LSCOLORS=ExFxBxDxCxegedabagacad

$ cat ~/.bash/hooks/erl
export ERL_AFLAGS="-kernel shell_history enabled"

$ cat ~/.bash/hooks/go
export GOPATH="$HOME/Library/Caches/org.golang/gopath"
export GOBIN="$GOPATH/bin"
```

For replacing programs with "better" ones iff you've got them:

```bash
$ cat ~/.bash/hooks/exa
alias ls=exa

$ cat ~/.bash/hooks/nvim
alias vi='nvim'
alias vim='nvim'
export EDITOR='nvim'

$ cat ~/.bash/hooks/pry
alias irb=pry
```

For sourcing Bash completions that don't get brought in correctly:

```bash
$ cat ~/.bash/hooks/gcloud
if [ -d '/usr/local/Caskroom/google-cloud-sdk/latest/google-cloud-sdk' ]; then
  source '/usr/local/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/path.bash.inc'
  source '/usr/local/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/completion.bash.inc'
fi
```

For fixing breakage between two apps iff they're installed together:

```bash
$ cat ~/.bash/hooks/curl+nix-env
export CURL_CA_BUNDLE="$HOME/.nix-profile/etc/ssl/certs/ca-bundle.crt"

$ cat ~/.bash/hooks/git+nix-env
export GIT_SSL_CAINFO="$HOME/.nix-profile/etc/ssl/certs/ca-bundle.crt"
```

...and probably for other things I haven't thought of yet, too :)

## More about Syncing

### Hiding Synced Preferences from the OS Indexer

An annoying thing about keeping these files in synced storage, is that synced storage
is usually considered a user-visible location by most OSes, and so by default,
these config files will get indexed by the OS and show up in searches. This is
usually not what you want. You can turn off indexing for your `Preferences` folder
manually on each OS it gets synced to, but I'd rather give the OS a hint to avoid
indexing by default, using the structure of the folder itself.

* On Linux (GNOME-specific):

```bash
touch ~/Dropbox/Preferences/.trackerignore
```

* On macOS:

```bash
touch ~/Dropbox/Preferences/.metadata_never_index
```

### DEPRECATED: `.bundle`-ing Synced Preferences

There's another approach, that *can* work for those who only use macOS. I used to
use this approach, but I think it's a bad idea now.

The approach is to rename your `Preferences` folder to `Preferences.bundle`. This
makes macOS perceive the folder as a generic document-bundle, and so treat it as
a single file at the Cocoa level. This has several benefits: you can still find the Preferences
bundle *itself* using OS indexing, but all the files within it will be considered
"implementation details" of the document, and so not indexed. POSIX software will still
perceive the `.bundle` directory as just a directory, so it'll be transparent to Bash et al.

This is a bad idea for iCloud specifically, though (and maybe other syncing apps, too, if they
have custom code-paths for bundles), because bundles are seen by syncing apps as something to
*atomically replace*. That is, if you change one file inside a bundle, the sync app doesn't
re-sync the *file*, but rather *the entire bundle*. Several pieces of POSIX software touch
their config files on startup, or write `history` files, or other things, which trigger a
complete re-upload of the containing bundle. For me, this was a 300MB blob that got re-uploaded
to iCloud roughly every time I opened a new terminal session. Silly!

If you can get your `.bundle` down to *only* containing data *referenced* by software,
but never data *modified* automatically by software, this approach might become tenable.

### DEPRECATED: Syncing other config (`XDG_CONFIG_HOME` + `XDG_DATA_HOME`, a.k.a. `~/.config` and `~/.local/share`)

Just don't do it. Even though these are nominally `etc/` and `share/` style directories,
and neither is supposed to be written to at runtime by the program, a lot of software developers have no
idea what the names of these dirs mean and treat both as `var/lib/foo`-like dirs. This means that many
pieces of software will write often under these dirs, and might even do things like unpacking software
updates into here (Heroku, I'm looking at you.)

If you want to symlink these into cloud-synced storage, do it item by item. Maybe write [a script, that you put
into cloud-synced storage, and run on each new machine, which builds this symlink tree.](https://gist.github.com/tsutsu/74c8dccd03c8914273171ad84a83859c)
