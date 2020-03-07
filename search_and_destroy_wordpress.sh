
#!/bin/bash
#
#
##
###   __pinpoint_ancient_wordpress_
###   __to_be_clear_wordpress_is_the_bane_of_all_existance_
###
###
##############################
##############################
##
# Author: Andrew Howard
# https://github.com/StafDehat/scripts/blob/master/wp-find-versions.sh
##############################
##############################
# Desc: Find wordpress installs on this system and print the version
# For info on what version is the current version, go here:
#  https://codex.wordpress.org/WordPress_Versions

if [ `id -u` -ne 0 ]; then
  echo "Must run as root"
  exit 1
fi

updatedb

locate wp-includes/version.php | \
while read x; do 
  echo -n "$x : "
  egrep '^\s*\$wp_version\s*=' "$x" | cut -d\' -f2
done | column -t -s :

# For a list of just the outdated ones, grep out the current version like so:
# grep -vE '\s3\.8\.1\s*$'

##
##
###
##
##
