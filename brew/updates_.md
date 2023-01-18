# Scheduled updates for homebrew

This two launchdaemon scripts provide scheduled updates and upgrade for homebrew packages.

It will run in the following way:
* `brew update` every day at 12:10
* `brew upgrade` every day at 12:20

# How to install

Create directory to store logs:

```
$ sudo mkdir -p /var/log/homebrew
```

There are two options for running those scripts.

## For specific user

This will run tasks only when user is logged in.

1. Put both files to `~/Library/LaunchAgents/`
2. Load both plist files using `launchctl load` providing absolute path to the plist file

## For all users

This way it is possible to run updates regardless of any user active login session. This method, however requires admin  privileges, thus run commands below with `sudo`. 

1. Put both files to `/Library/LaunchDaemons/`
2. Fix permissions `chmod 644 /Library/LaunchDaemons/*.plist`
3. Make sure that owner is `root:wheel` by running `chown root:wheel /Library/LaunchDaemons/*.plist`
4. Load both plist files using `launchctl load` providing absolute path to the plist file

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>Label</key>
		<string>com.example.brew.update</string>
		<key>ProgramArguments</key>
		<array>
			<string>/usr/local/bin/brew</string>
			<string>update</string>
		</array>
		<key>RunAtLoad</key>
		<true/>
		<key>StartCalendarInterval</key>
		<dict>
			<key>Hour</key>
			<integer>12</integer>
			<key>Minute</key>
			<integer>10</integer>
		</dict>
		<key>StandardErrorPath</key>
		<string>/var/log/homebrew/update.log</string>
		<key>StandardOutPath</key>
		<string>/var/log/homebrew/update.log</string>
	</dict>
</plist>

```

##
##
##

```<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>Label</key>
		<string>com.example.brew.upgrade</string>
		<key>ProgramArguments</key>
		<array>
			<string>/usr/local/bin/brew</string>
			<string>upgrade</string>
		</array>
		<key>RunAtLoad</key>
		<true/>
		<key>StartCalendarInterval</key>
		<dict>
			<key>Hour</key>
			<integer>12</integer>
			<key>Minute</key>
			<integer>20</integer>
		</dict>
		<key>StandardErrorPath</key>
		<string>/var/log/homebrew/upgrade.log</string>
		<key>StandardOutPath</key>
		<string>/var/log/homebrew/upgrade.log</string>
	</dict>
</plist>
```
