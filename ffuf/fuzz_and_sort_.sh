#!/bin/bash
# ./ffufs.sh <WORDLIST> <URL2FUZZ>
# ./ffufs.sh mysuperbestwordlist.txt https://www.bla.com
##############
##########################
##############

# Pretty Colors
RESET='\033[00m'  
RED='\033[01;31m'
GREEN='\033[01;32m'
BLUE='\033[01;34m'
MAGENTA='\033[01;35m'
WHITE='\033[01;37m'

THISDOMAIN=$(echo $2 | cut -d\/ -f3)
# Variable You Ought to Change if You Want it to Work
WHEREITLIVES='/home/hs/my/scriptz/ff'

#  ffuf it here
ffuf -c -w $1 -u $2/FUZZ -o $WHEREITLIVES/$THISDOMAIN-raw-res.csv -of csv

# Removes the CSV Headers
sed -i '1d' $WHEREITLIVES/$THISDOMAIN-raw-res.csv

# Loop That CSV to Get Colors Applied to HTTP Response Codes
for x in `cat $WHEREITLIVES/$THISDOMAIN-raw-res.csv`; do
	THISWEBPATH=$(echo $x | cut -d, -f1)
	THISSTATUS=$(echo $x | cut -d, -f5)
	THISSIZE=$(echo $x | cut -d, -f4)
	if [ `echo $THISSTATUS | grep "^2"` ]; then echo -e $2"/"$THISWEBPATH" [Status: "${GREEN}$THISSTATUS${RESET}", Size: "$THISSIZE"]" >> $WHEREITLIVES/$THISDOMAIN-final-res.txt.tmp; fi
	if [ `echo $THISSTATUS | grep "^3"` ]; then echo -e $2"/"$THISWEBPATH" [Status: "${BLUE}$THISSTATUS${RESET}", Size: "$THISSIZE"]" >> $WHEREITLIVES/$THISDOMAIN-final-res.txt.tmp; fi
	if [ `echo $THISSTATUS | grep "^4"` ]; then echo -e $2"/"$THISWEBPATH" [Status: "${MAGENTA}$THISSTATUS${RESET}", Size: "$THISSIZE"]" >> $WHEREITLIVES/$THISDOMAIN-final-res.txt.tmp; fi
	if [ `echo $THISSTATUS | grep "^5"` ]; then echo -e $2"/"$THISWEBPATH" [Status: "${RED}$THISSTATUS${RESET}", Size: "$THISSIZE"]" >> $WHEREITLIVES/$THISDOMAIN-final-res.txt.tmp; fi
done

# Get Our Results Sorted All Nice Like
sort -t: -k3,3 $WHEREITLIVES/$THISDOMAIN-final-res.txt.tmp > $WHEREITLIVES/$THISDOMAIN-final-res.txt.tmp.sorted

echo -e ${BLUE}"RESULTS: ${WHITE}$2"${RESET} > $WHEREITLIVES/$THISDOMAIN-final-res.txt
cat $WHEREITLIVES/$THISDOMAIN-final-res.txt.tmp.sorted >> $WHEREITLIVES/$THISDOMAIN-final-res.txt 

cat $WHEREITLIVES/$THISDOMAIN-final-res.txt
rm  $WHEREITLIVES/$THISDOMAIN-{final-res.txt.tmp,final-res.txt.tmp.sorted}


###########################
##
##
