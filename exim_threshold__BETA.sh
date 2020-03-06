
##
##  _this_needs_apparent_help__
##  _surprise__
##
##########################
##########################

##[root]#exim -bpr | grep "<*@*>" | awk '{print $4}'|grep -v "<>" |awk -F "@" '{ print $2}' | sort | uniq -c | sort -n
##[root]#exim -bpr | grep "<*@*>" | awk '{print $4}'|grep -v "<>" | sort | uniq -c | sort -n
##[root]#awk '{ if ($0 ~ "cwd" && $0 ~ "home") {print $3} }' /var/log/exim_mainlog | sort | uniq -c | sort -nk 1

#!/bin/sh
ABNORMAL_NUMBER=150
EMAIL=”XXX@XXX.COM”

#DO NOT CHANGE BELOW THIS LINE
qnum=$(/usr/sbin/exim -bpr | grep "<" | wc -l)
if (( $qnum > $ABNORMAL_NUMBER ));
then
        script_mail=$(tail --lines=5000 /var/log/exim_mainlog|sed -ne "s|$(date +%F).*cwd=\(/home[^ ]*\).*$|\1|p"| sort | uniq -c | awk '{printf "%d %s\n",$1,$2}' | sort -rn|head -n 1)
        script_num=$(echo "$script_mail"|awk '{split($0,a," "); print a[1]}')
        script_loc=$(echo "$script_mail"|awk '{split($0,a," "); print a[2]}')
        script_threshold=$(echo $ABNORMAL_NUMBER 0.5 | awk '{printf "%0.0f\n",$1*$2}')
        if (( $script_num > $script_threshold ));
        then
                script_mailbody=$(echo "Number of mail queue is $qnum.\n$script_num emails have been send out recently by script locating at $script_loc")
        fi
        mailbody=$(/root/mailqinfo)
        printf "$script_mailbody\n$mailbody" | mail -s "MAIL ALERT!" $EMAIL
fi

#############################################
#############################################################
~                                                                                                                                                                                     
~                                                                                                                                                                                     
~                                                                                                                                                                                     
~                                                                
