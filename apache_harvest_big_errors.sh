#!/bin/bash
###
############# scan through apache error_log, report the big things, thank you
###
### _bro_configure_it_right_pls__
##
##
##

temp="/tmp/$(basename $0).$$"

##############################################
## customize the next three
## __do_the_needful, (obvi)
##############################################

htdocs="/usr/local/apache/htdocs/"
myhome="/root/BASH/"
cgibin="/root/BASH/cgi-bin/"

##############################################

sedstr="s/^/ /g;s|$htdocs|[htdocs] |;s|$myhome|[homedir] "
sedstr=$sedstr"|;s|$cgibin|[cgi-bin] |"

screen"(File does not exist|Invalid error redirect|premature EOF"
screen=$screen"|Premature end of script|script not found)"

length=5   ## Entries per category to display

checkfor()
{
	grep "${2}:" "$1" | awk '{print $NF}' \
	  | sort | uniq -c | sort -rn | head -$length | sed "$sedstr" > $temp

	if [ $(wc -l < $temp) -gt 0 ] ; then
	  echo ""
          echo "$2 errors:"
	  cat $temp
    fi
}

trap "$(which rm) -f $temp" 0

if [ "$1" = "-l" ] ; then
  length=$2; shift 2
fi

if [ $# -ne 1 -o ! -r "$1" ] ; then
   echo "Usage: $(basename $0) [-l len] error_log" >&2
   exit 1
fi

echo Input file $1 has $(wc -l < "$1") entries.

start="$(grep -E '\[.*:.*:.*\]' "$1" | head -1 \
	| awk '{print $1" "$2" "$3" "$4" "$5 }')"
end="$(grep -E '\[.*:.*:.*\]' "$1" | tail -1 \
	| awk '{print $1" "$2" "$3" "$4" "$5 }')"


/bin/echo -n "Entries from $start to $end"

echo ""

### Check for various common and well-known errors

checkfor "$1" "File does not exist"
checkfor "$1" "Invalid error redirection directive"
checkfor "$1" "Premature EOF"
checkfor "$1" "Script not found or unable to stat"
checkfor "$1" "Premature end of script headers"

grep -vE "$screen" "$1" | grep "\[error\]" | grep "\[client " \
	| sed 's/\[error\]/\`/' | cut -d\` -f2 | cut -d\ -f4- \
	| sort | uniq -c | sort -rn | sed 's/^/ /' | head -$length > $temp

if [ $(wc -l < $temp) -gt 0 ] ; then
	echo ""
	echo "Additional error messages in log file:"
	cat $temp

fi

echo ""
echo "And non-error messages occuring in the log file:"

grep -vE "$screen" "$1" | grep -v "\[error\]" \
	| sort | uniq -c | sort -rn \
	| sed 's/^/ /' | head -$length

exit 0



htdocs="/usr/local/apache/htdocs/"
myhome="/root/BASH/"
cgibin="/root/BASH/cgi-bin/"

sedstr="s/^/ /g;s|$htdocs|[htdocs] |;s|$myhome|[homedir] "
sedstr=$sedstr"|;s|$cgibin|[cgi-bin] |"

screen"(File does not exist|Invalid error redirect|premature EOF"
screen=$screen"|Premature end of script|script not found)"

length=5   ## Entries per category to display

checkfor()
{
	grep "${2}:" "$1" | awk '{print $NF}' \
	  | sort | uniq -c | sort -rn | head -$length | sed "$sedstr" > $temp

	if [ $(wc -l < $temp) -gt 0 ] ; then
	  echo ""
          echo "$2 errors:"
	  cat $temp
    fi
}

trap "$(which rm) -f $temp" 0

if [ "$1" = "-l" ] ; then
  length=$2; shift 2
fi

if [ $# -ne 1 -o ! -r "$1" ] ; then
   echo "Usage: $(basename $0) [-l len] error_log" >&2
   exit 1
fi

echo Input file $1 has $(wc -l < "$1") entries.

start="$(grep -E '\[.*:.*:.*\]' "$1" | head -1 \
	| awk '{print $1" "$2" "$3" "$4" "$5 }')"
end="$(grep -E '\[.*:.*:.*\]' "$1" | tail -1 \
	| awk '{print $1" "$2" "$3" "$4" "$5 }')"


/bin/echo -n "Entries from $start to $end"

echo ""

### Check for various common and well-known errors

checkfor "$1" "File does not exist"
checkfor "$1" "Invalid error redirection directive"
checkfor "$1" "Premature EOF"
checkfor "$1" "Script not found or unable to stat"
checkfor "$1" "Premature end of script headers"

grep -vE "$screen" "$1" | grep "\[error\]" | grep "\[client " \
	| sed 's/\[error\]/\`/' | cut -d\` -f2 | cut -d\ -f4- \
	| sort | uniq -c | sort -rn | sed 's/^/ /' | head -$length > $temp

if [ $(wc -l < $temp) -gt 0 ] ; then
	echo ""
	echo "Additional error messages in log file:"
	cat $temp

fi

echo ""
echo "And non-error messages occuring in the log file:"

grep -vE "$screen" "$1" | grep -v "\[error\]" \
	| sort | uniq -c | sort -rn \
	| sed 's/^/ /' | head -$length

exit 0

##################################
##
##
