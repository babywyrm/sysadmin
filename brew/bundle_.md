# Brew Bundle Brewfile Tips

##
#
https://gist.github.com/ChristopherA/a579274536aab36ea9966f301ff14f3f
#
##

## Copyright & License

> Unless otherwise noted (either in this file or in a file's copyright section) the contents of this gist are Copyright :copyright:2020 by Christopher Allen, and are shared under [spdx:Creative Commons Attribution Share Alike 4.0 International (CC-BY-SA-4.)](https://spdx.org/licenses/CC-BY-SA-4.0.html) open-source license.

## Sponsor

> If you more tips and advice like these, you can become a monthly patron on my [GitHub Sponsor Page](https://github.com/sponsors/ChristopherA) for as little as $5 a month; and your contributions will be multipled, as GitHub is matching the first $5,000! 
> This gist is all about Homebrew, so if you like it you can support it by [donating](https://github.com/homebrew/brew#donations) to them or becoming one of their [Github Sponsors](https://github.com/sponsors/Homebrew).

## Intro to Brew, Bundle, and Brewfile

If you are using a Mac as your development environment, you really should be using [Brew](https://brew.sh). You probably should be using it if you are a power user as well, as it isn't really that difficult.

A key feature of Brew is its ability to set up your Mac to a known configuration. It does this a feature called Bundle that uses Brewfiles. As doing development, or experimenting with new apps can break your system, I can easily restore back to a known configuration, both on my primary Macs, but also in VMware Fusion instances where I do more testing, including testing on old versions of MacOS and new beta versions of MacOS.

A version of Brew also is available on Linux, but I mostly use apt-get on Debian. I am considering some cross-platform development scripts to use Brew instead.

## Installing Brew

Compete details are at [Brew](https://brew.sh) but fairly simple to install. Open terminal.app (command-space + "terminal") and paste this command on the command line.

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

If you don't have a recent version of macOS, you may need to install the latest Xcode command tools first. I don't like downloading all of Xcode, so I use this trick to only install the latest command-line tools.

```
touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress;
softwareupdate -i -a
rm /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
```

Another easy way to install all of this, along with some good basic security hardening practices, is to use [Mike McQuaid's Strap](https://github.com/MikeMcQuaid/strap) tool by going to https://macos-strap.herokuapp.com/. If you have a github account, it will also install basic github permissions.

## Basic Brew Bundle

The most basic command

```
brew bundle install
```

Looks for `~/Brewfile` and installs its contents

## Install a specific brewfile

If you want to use a brewfile from a non-standard place.

```
brew bundle --file=~/.private/Brewfile
```

Or more specifically:

```
brew bundle install --file=rs-brew-dump
```

## Creating a Brewfile

You can dump a Brewfile of your current brew/cask/mas entries into your current directory with

```
brew bundle dump
```

or to a specific directory and file name.

```
brew bundle dump --file=~/.private/Brewfile
```

If a Brewfile already exists, you'll need to do 

```
brew bundle dump --force
```

## Cleaning up to match brewfile

If you want your current system configuration to match your brewfile

```
brew bundle --force cleanup
```

## Best Practices: `brew cask`, `mas` and `cu`

A key practice is to install EVERYTHING possible using brew, brew cask, or mas. Even things like fonts!

Three tools that really make this work for more than just development tools is the ability to install a large number of macOS UI apps using `brew cask install <appname>`, Mac Apple Store apps using `mas install <appnumber>`, search for them using `brew search <searchterm>` & `mas search <searchterm>`. Not everything is avaiable this way, but the most important ones are.

To use this make sure that these entries are near the top of your `Brewfile`:

```
tap "homebrew/cask"
tap "buo/cask-upgrade"
brew "mas"
```

You even install many open source fonts this way. Do `brew tap homebrew/cask-fonts" and Add this top the top of your `Brewfile`:

```
tap "homebrew/cask-fonts"
```

On can search for fonts once tapped by

```
brew search font
```

Finally, there is a [Cask-Update](https://github.com/buo/homebrew-cask-upgrade) tool that works with `brew cask` to update all of your Mac apps.

Add this to your `Brewfile`:

```
tap "buo/cask-upgrade"
```

Then to upgrade all of you Mac apps, just do:

```
brew cu
```

[Cask-Update](https://github.com/buo/homebrew-cask-upgrade) details some other features. In particular, I like `brew cu pin <caskname>` which locks an app to a specific version.

## Minimal Essential Bundle

My current minimal Brew on macOS is:

```
tap "homebrew/core"
tap "homebrew/bundle"
tap "homebrew/cask"
tap "buo/cask-upgrade"
tap "homebrew/cask-fonts"
brew "github-keygen"
brew "gnupg"
brew "pinentry-mac"
brew "stow"
brew "mas"
brew "gh"
cask "atom"
cask "carbon-copy-cloner"cask "atom"
cask "typora"
```

## Best Pracices: Using with `.dotfiles`

I have two brewfiles currently:

* One in `~.private` which I install right after installing brew and before setting up my basic `.ssh` and `.gnupg` files so that I can use GitHub. It is the minimal essential list above. I can install this manually with a script inside `.private`.

* My standard in `~/Brewfile` is actually a symlink to `~/.dotfiles/mac/Brewfile`. I different `~/.dotfiles/` for different environments.
  * My primary Mac is a monster MacBook Pro is really more of a "desktop" for me. It has 64 GB RAM with an 8TB HD. It probably has my largest Brewfile.
  * That being said, it actually doesn't have many development tools in it. Instead, I mostly use VMware instances (mostly macOS but some Debian) for my development images. They use a different `~.dotfiles` based Brewfile. 
  * My smaller, older MacBook is mostly for travel. It has different set of `~/.dotfiles/` focused on just enough to work remotely. I'm always prepared to restore this Mac from scratch.
  * For a month or so each year, late summer early fall, my old MacBook also will run the latest beta of macOS, allowing me to test not just macOS, but also be prepared for changes to my development environments.
  
## Advanced Topics & To Investigate

* Instead of `brew cask uninstall <caskname>` you can do `brew cask zap <caskname>` which may also do additional removal of preferences, caches, updaters, etc. stored in `~/Library`. See [Zap](https://github.com/Homebrew/homebrew-cask/blob/master/doc/cask_language_reference/stanzas/zap.md)

* A pariculary powerful feature for Brew is that it attempts to install developer tools in ways that allow them to co-exist. However if you are using multiple versions of a tool, it can be difficult to understand dependencies. These links may help:
  * brew deps
    * `brew deps --tree <brewformula>`
    * `brew deps --tree -1 <brewformula>`
    * `brew deps --include-build --tree $(brew leaves)`
  * [brew leaves](https://thoughtbot.com/blog/brew-leaves)
    * `brew leaves | xargs brew deps --include-build --tree`
    * `brew leaves | xargs brew deps --installed --for-each | sed "s/^.*:/$(tput setaf 4)&$(tput sgr0)/"`
    * `brew leaves | sed 's/^/install /' > Brewfile`
  * [brew graph](https://github.com/martido/homebrew-graph)
  * A [critique](https://blog.jpalardy.com/posts/untangling-your-homebrew-dependencies/) of `brew leaves` and `brew graph`

* If you are a heavy Github user, or are creating brew formulae, there is an advanced wrapper for Homebrew that automates the creation of the Brewfile and can store it on Github, along with a many more features: https://homebrew-file.readthedocs.io/


  
```
ChristopherA commented on Sep 18, 2022
TODO: brew bundle dump --file=~/brew_bundle_titania_2022-09-18.txt

@ariel-frischer
ariel-frischer commented on Oct 24, 2022
This is super informative and useful. Thank you! 🚀

@NH3R717
NH3R717 commented on Jun 22
When restoring a Mac from scratch do you have a way to implement save preferences? There doesn't seem to be a set way to install macOS with these kinds of settings from a config file.

@phette23
phette23 commented on Oct 25
@NH3R717 defaults might help. You could try to dump settings with defaults read and then apply them when restoring with defaults write. This is essentially what Mathias Bynens' .macos does. The concern that's stopped me from doing this is new settings / state stored in settings messing up a new machine but it should at least be possible.
```

