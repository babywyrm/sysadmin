  
#!/bin/bash
##
##   _might_want_to_refactor_for_2020_lifestyles__
##
###########################################################
## c/o Author: Andrew Howard
##   https://github.com/StafDehat/scripts/blob/master/repair-mysql.sh
##
##
##

########## Helper Functions ##########
####### Yes bash has functions #######
########## lololol ###################
## Bye
##
############

# Shut off everything that could get in our way
start()
{
  echo "Halting MySQL..."
  if [ -f /etc/init.d/chkservd ]; then
    /etc/init.d/chkservd stop
  fi
  if [ -f /etc/init.d/mysql ]; then
    /etc/init.d/mysql stop 2>&1 > /dev/null
    killall mysql 2>&1 > /dev/null
    killall -9 mysql 2>&1 > /dev/null
  else
    /etc/init.d/mysqld stop 2>&1 > /dev/null
    killall mysqld 2>&1 > /dev/null
    killall -9 mysqld 2>&1 > /dev/null
  fi
}

# Start everything back up.  Always call this before exiting.
finish()
{
  # Clean up after yourself
  rm -f blah blah2
  cd $DIR

  # Restart MySQL
  echo "Starting MySQL..."
  if [ -f /etc/init.d/mysql ]; then
    /etc/init.d/mysql start
  else
    /etc/init.d/mysqld start
  fi

  if [ -f /etc/init.d/chkservd ]; then
    /etc/init.d/chkservd start
  fi
}


########## Begin Main ##########
DIR=`pwd`
cd /var/lib/mysql

# Stop mysql and anything else that could bother us
start

# Do a very careful repair on the tables - Gauranteed not to break anything
echo "Analyzing databases (this could take awhile)..."
for x in `find * | grep .MYI`; do myisamchk -s $x; done 2> blah
cat blah | grep "myisamchk: MyISAM file " | sed s/"myisamchk: MyISAM file "// > blah2
echo "Done!"
sleep .5
if [ `cat blah | wc -l` == 0 ]; then
  echo "No problems found!"
  finish
  exit
fi
echo "Problems found with the following databases:"
cat blah2
echo "Attempting this repair will not damage databases."
echo -n "Repair these databases? [y/N]:"
read opt
if [ "$opt" = "y" ]; then
  echo "Repairing databases..."
  for x in `cat blah2`; do myisamchk -r -q $x; done
else
  echo "Did not attempt repair."
  echo -n "Continue with script? [y/N]:"
  read opt
  if [ "$opt" != "y" ]; then
    finish
    exit
  fi
fi

# Attempt a repair that has potential to cause damage.  Backing up the tables is not a bad idea.
echo "Assessing success of repair attempts..."
for x in `cat blah2`; do myisamchk -s $x; done 2> blah
cat blah | grep "myisamchk: MyISAM file " | sed s/"myisamchk: MyISAM file "// > blah2
echo "Done!"
sleep .5
if [ `cat blah | wc -l` == 0 ]; then
  echo "No problems found!"
  finish
  exit
fi
echo "Problems found with the following databases:"
cat blah2
echo "This is a more intense repair that may fix problems the previous attempt failed to repair, but has potential to cause damage to databases.  A backup of /var/lib/mysql is recommended prior to attempting this repair."
echo -n "Repair these databases? [y/N]:"
read opt
if [ "$opt" = "y" ]; then
  echo "Repairing databases..."
  for x in `cat blah2`; do myisamchk -r $x; done
else
  echo "Did not attempt repair."
  echo -n "Continue with script? [y/N]:"
  read opt
  if [ "$opt" != "y" ]; then
    finish
    exit
  fi
fi

# Attempt older, slower technique that tries some things -r does not
echo "Assessing success of repair attempts..."
for x in `cat blah2`; do myisamchk -s $x; done 2> blah
cat blah | grep "myisamchk: MyISAM file " | sed s/"myisamchk: MyISAM file "// > blah2
echo "Done!"
sleep .5
if [ `cat blah | wc -l` == 0 ]; then
  echo "No problems found!"
  finish
  exit
fi
echo "Problems found with the following databases:"
cat blah2 echo "This is an older method that is slower than the previous attempts, but will attempt some methods the others do not.  This technique may potentially damage databases, so a mysql backup is recommended."
echo -n "Repair these databases? [y/N]:"
read opt
if [ "$opt" = "y" ]; then
  echo "Repairing databases..."
  for x in `cat blah2`; do myisamchk -o $x; done
else
  echo "Did not attempt repair."
  finish
  exit
fi

# Start everything back up
finish

##
##
###########################################################
