####################################
##
## create separate /nginx/ directory 
## likely within /srv/salt/
##
####################################

add_epel:
  pkg.installed:
    - name: epel-release
    
####################################
