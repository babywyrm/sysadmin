# remove specific file from git cache
git rm --cached filename

# remove all files from git cache
```
git rm -r --cached .
git add .
git commit -m ".gitignore is now working"
```
##
##

Run all command together at once:
```
git rm -r --cached . && git add . && git commit -m ".gitignore is now working"
```
####
####

remove all files from git cache
Just copy these command & fixed the problem.
```
git rm -r --cached .
git add .
git commit -m "untracked fixed"
```
####
####


### joe made this: http://goel.io/joe
```
#####=== Windows ===#####
# Windows image file caches
Thumbs.db
ehthumbs.db

# Folder config file
Desktop.ini

# Recycle Bin used on file shares
$RECYCLE.BIN/

# Windows Installer files
*.cab
*.msi
*.msm
*.msp

# Windows shortcuts
*.lnk

#####=== Linux ===#####
*~

# KDE directory preferences
.directory

# Linux trash folder which might appear on any partition or disk
.Trash-*

#####=== MacOS ===#####
.DS_Store
.AppleDouble
.LSOverride

# Icon must end with two \r
Icon


# Thumbnails
._*

# Files that might appear on external disk
.Spotlight-V100
.Trashes

# Directories potentially created on remote AFP share
.AppleDB
.AppleDesktop
Network Trash Folder
Temporary Items
.apdisk

#####=== JetBrains ===#####
# Covers JetBrains IDEs: IntelliJ, RubyMine, PhpStorm, AppCode, PyCharm

*.iml

## Directory-based project format:
.idea/
# if you remove the above rule, at least ignore the following:

# User-specific stuff:
# .idea/workspace.xml
# .idea/tasks.xml
# .idea/dictionaries

# Sensitive or high-churn files:
# .idea/dataSources.ids
# .idea/dataSources.xml
# .idea/sqlDataSources.xml
# .idea/dynamic.xml
# .idea/uiDesigner.xml

# Gradle:
# .idea/gradle.xml
# .idea/libraries

# Mongo Explorer plugin:
# .idea/mongoSettings.xml

## File-based project format:
*.ipr
*.iws

## Plugin-specific files:

# IntelliJ
out/

# mpeltonen/sbt-idea plugin
.idea_modules/

# JIRA plugin
atlassian-ide-plugin.xml

# Crashlytics plugin (for Android Studio and IntelliJ)
com_crashlytics_export_strings.xml
crashlytics.properties
crashlytics-build.properties

#####=== SublimeText ===#####
# cache files for sublime text
*.tmlanguage.cache
*.tmPreferences.cache
*.stTheme.cache

# workspace files are user-specific
*.sublime-workspace

# project files should be checked into the repository, unless a significant
# proportion of contributors will probably not be using SublimeText
# *.sublime-project

# sftp configuration file
sftp-config.json

#####=== Jekyll ===#####
_site/
.sass-cache/

#####=== Custom ===#####
# Logic files:
.gitsecret/
git-secret

# Temporary packages:
temp/

# Packaging:
build/
*.deb
*.fpm

# Docs:
docs/man
docs/_posts
docs/_includes/install-*.sh
docs/_includes/version.txt
CHANGELOG-RELEASE.md
