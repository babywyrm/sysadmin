#!/bin/bash
# This script assumes Responder is in /opt/Responder

## c/o
## https://gist.github.com/seajaysec/65e6e22cc64b5e44dfc4c3bbce89fbcc
##

# Error messages begone!
exec 2>/dev/null

# Hardcoded location for script output files
OUTDIR=${HOME}'/working/loot/gathered'
# Hardcoded location for ntlmrelayx's .sam file output directory
NTLMRELAY=${HOME}'/working/loot/ntlmrelay'

# Reminder to prep cmedb
echo "In cmedb, run this:"
echo -e "export creds csv ${HOME}/.cme/cmedb.csv\n"
# Pause
read -n 1 -s -r -p "Press any key to continue"

### Reminder to prep cmxdb - ON HOLD UNTIL EXPORT FUNCTION IS ADDED TO CMXDB
# echo "In cmxdb, run this:"
# echo -e "export creds csv ${HOME}/.cmx/cmxdb.csv\n"
# Pause
# read -n 1 -s -r -p "Press any key to continue"
###

# Creating output directory just in case
mkdir -p $OUTDIR

# CM: SAM Hash Parse
grep -h 'aad3b435b51404eeaad3b435b51404ee' /root/.cme/logs/*.sam | sort -u | grep -v "$:" | grep -v "Guest:501:" | tr a-z A-Z >>$OUTDIR/crackmapSAM.txt
grep -h 'aad3b435b51404eeaad3b435b51404ee' /root/.cmx/logs/*.sam | sort -u | grep -v "$:" | grep -v "Guest:501:" | tr a-z A-Z >>$OUTDIR/crackmapSAM.txt
gawk -i inplace -F':' '!seen[$1]++' $OUTDIR/crackmapSAM.txt
echo "CrackMap: SAM Hash Parse - Complete"

# CM: LSA Secrets Dump Parse
grep -hv 'NL$KM' /root/.cme/logs/*.secrets | grep -v '$:' | grep -v 'L$ASP.NETAutoGenKeys' | grep -v -i 'dpapi' | grep -v 'RasDialParams' | grep -v 'SCM:' | grep -v 'UpdatusUser' | grep -v 'SQSA' >>$OUTDIR/crackmapLSA.txt
grep -hv 'NL$KM' /root/.cmx/logs/*.secrets | grep -v '$:' | grep -v 'L$ASP.NETAutoGenKeys' | grep -v -i 'dpapi' | grep -v 'RasDialParams' | grep -v 'SCM:' | grep -v 'UpdatusUser' | grep -v 'SQSA' >>$OUTDIR/crackmapLSA.txt
echo "CrackMap: LSA Secrets Dump Parse - Complete"

# CM: Kerberos Ticket Granting Ticket Search
grep 'krbtgt' /root/.cme/logs/* | tr a-z A-Z >>$OUTDIR/crackmapKRBTGT.txt
grep 'krbtgt' /root/.cmx/logs/* | tr a-z A-Z >>$OUTDIR/crackmapKRBTGT.txt
echo "CrackMap: Kerberos Ticket Granting Ticket Parse - Complete"

# CM: NTDS.dit Cleartext Password Output
sort -u /root/.cme/logs/*.cleartext >>$OUTDIR/crackmapNTDSplain.txt
sort -u /root/.cmx/logs/*.cleartext >>$OUTDIR/crackmapNTDSplain.txt
echo -e "CrackMap: NTDS.dit Cleartext Password Parse - Complete\n"

# CM: Domain Cached Credential Search
grep -ha . ${HOME}/.cme/logs/*.cached | grep -a 'DCC2' | tr -cd '\11\12\15\40-\176' | tr a-z A-Z | sort -u >>$OUTDIR/crackmapDCC2.txt
grep -ha . ${HOME}/.cmx/logs/*.cached | grep -a 'DCC2' | tr -cd '\11\12\15\40-\176' | tr a-z A-Z | sort -u >>$OUTDIR/crackmapDCC2.txt
gawk -i inplace -F':' '!seen[$1]++' $OUTDIR/crackmapDCC2.txt
echo "CrackMap: Domain Cached Credential Parse - Complete"

# CMDB: Odds and Ends
grep 'hash' ${HOME}/.cme/cmedb.csv | grep -v 'aad3b435b51404eeaad3b435b51404ee' | cut -d "," -f 2,3,4 >>$OUTDIR/crackmapOTHER.txt
grep 'hash' ${HOME}/.cmx/cmxdb.csv | grep -v 'aad3b435b51404eeaad3b435b51404ee' | cut -d "," -f 2,3,4 >>$OUTDIR/crackmapOTHER.txt
grep -ha . ${HOME}/.cme/logs/*.cached | grep -av 'DCC2' | tr -cd '\11\12\15\40-\176' | sort -u >>$OUTDIR/crackmapOTHER.txt
grep -ha . ${HOME}/.cmx/logs/*.cached | grep -av 'DCC2' | tr -cd '\11\12\15\40-\176' | sort -u >>$OUTDIR/crackmapOTHER.txt
sed -e 's/,/:/g' -i $OUTDIR/crackmapOTHER.txt
echo -e "CrackMap DB: Odds and Ends Parse - Complete\n"

# CMDB: Plaintext Creds Output
grep 'plaintext' ${HOME}/.cme/cmedb.csv | cut -d ',' -f 2-4 | sed -r 's/[,]+/::/g' | grep -v -i 'dpapi' >>$OUTDIR/crackmapPLAIN.txt
grep 'plaintext' ${HOME}/.cmx/cmxdb.csv | cut -d ',' -f 2-4 | sed -r 's/[,]+/::/g' | grep -v -i 'dpapi' >>$OUTDIR/crackmapPLAIN.txt
ex -s +'%!sort' -cxa $OUTDIR/crackmapPLAIN.txt
echo "CrackMap DB: Plaintext Creds Parse - Complete"

# CMDB: NTLM Hashed Creds Output
grep -h 'aad3b435b51404eeaad3b435b51404ee' ${HOME}/.cme/cmedb.csv | sort -u | grep -v "$:" | grep -v ",Guest," | grep -v "31d6cfe0d16ae931b73c59d7e0c089c0" | cut -d "," -f 3,4 | sed -r 's/[,]+/:/g' >>$OUTDIR/crackmapNTLM.txt
grep -h 'aad3b435b51404eeaad3b435b51404ee' ${HOME}/.cmx/cmxdb.csv | sort -u | grep -v "$:" | grep -v ",Guest," | grep -v "31d6cfe0d16ae931b73c59d7e0c089c0" | cut -d "," -f 3,4 | sed -r 's/[,]+/:/g' >>$OUTDIR/crackmapNTLM.txt
gawk -i inplace -F':' '!seen[$1]++' $OUTDIR/crackmapNTLM.txt
sed -e 's/$/:::/' -i $OUTDIR/crackmapNTLM.txt
sed -e 's/:aad3b435b51404eeaad3b435b51404ee/:9999:aad3b435b51404eeaad3b435b51404ee/g' -i $OUTDIR/crackmapNTLM.txt
ex -s +'%!sort' -cxa $OUTDIR/crackmapNTLM.txt
echo "CrackMap DB: NTLM Hashed Creds Parse - Complete"

# Responder: Cleartext Password Output - With Hostname and IP
grep ':' /opt/Responder/logs/*Clear* | cut -d "/" -f 5 | rev | cut -d "-" -f 1,3,4 | rev | sed -e 's/Cleartext-//g' | sort -u >>$OUTDIR/responderPLAIN.txt
echo "Responder: Cleartext Password Parse - Complete"

# Responder: NTLMv2 (Needs a lot more testing)
grep -hI '::' /opt/Responder/logs/*.txt | sort -u >$OUTDIR/NTLMv2.txt
echo -e "Responder: NTLMv2 Parse - Complete\n"

# PCredz: NTLMv2
grep -hI 'NTLMv2' /usr/sbin/CredentialDump-Session.log | sed 's/NTLMv2 complete hash is: //g' | sort -u >>$OUTDIR/NTLMv2.txt
grep -hI 'NTLMv2' /usr/bin/CredentialDump-Session.log | sed 's/NTLMv2 complete hash is: //g' | sort -u >>$OUTDIR/NTLMv2.txt
echo "PCredz: NTLMv2 Parse - Complete"

# PCredz: NTLMv1
grep -hI 'NTLMv1' /usr/sbin/CredentialDump-Session.log | sed 's/NTLMv1 complete hash is: //g' | sort -u >>$OUTDIR/NTLMv1.txt
grep -hI 'NTLMv1' /usr/bin/CredentialDump-Session.log | sed 's/NTLMv1 complete hash is: //g' | sort -u >>$OUTDIR/NTLMv1.txt
echo "PCredz: NTLMv1 Parse - Complete"

# PCredz: SNMP
cat /usr/sbin/CredentialDump-Session.log | grep 'Community String' >>$OUTDIR/pcredzSNMP.txt
cat /usr/bin/CredentialDump-Session.log | grep 'Community String' >>$OUTDIR/pcredzSNMP.txt
echo "PCredz: SNMP Output Dump - Complete"

# PCredz: FTP
cat /usr/sbin/CredentialDump-Session.log | grep 'FTP User' -C 1 >>$OUTDIR/pcredzFTP.txt
cat /usr/bin/CredentialDump-Session.log | grep 'FTP User' -C 1 >>$OUTDIR/pcredzFTP.txt
echo "PCredz: FTP Output Dump - Complete"

# PCredz: HTTP
cat /usr/sbin/CredentialDump-Session.log | grep 'HTTP' -B 1 >>$OUTDIR/pcredzHTTP.txt
cat /usr/bin/CredentialDump-Session.log | grep 'HTTP' -B 1 >>$OUTDIR/pcredzHTTP.txt
echo "PCredz: HTTP Output Dump - Complete"

# PCredz: Other
cat /usr/sbin/CredentialDump-Session.log | grep -wive 'NTLMv2\|NTLMv1\|Community String\|FTP\|HTTP' >>$OUTDIR/pcredzOTHER.txt
cat /usr/bin/CredentialDump-Session.log | grep -wive 'NTLMv2\|NTLMv1\|Community String\|FTP\|HTTP' >>$OUTDIR/pcredzOTHER.txt
echo -e "PCredz: 'Other' Output Dump - Complete\n"

# NTLMRELAY: SAM Dumps
cat $NTLMRELAY/*.sam | tr a-z A-Z | sort -u >> $OUTDIR/ntlmrelaySAMs.txt
echo -e 'NTLMRELAYX.PY: SAM Dump Parse - Complete\n'

# Dedupe Everything
tr a-z A-Z <$OUTDIR/NTLMv2.txt | sed -e 's/\@/::/g' | awk -F':' '!seen[$1,$3]++' >$OUTDIR/NTLMv2.txt
gawk -i inplace '!a[$0]++' $OUTDIR/*

# SessionGopher: Cleartext Password Output - With all pertinent details - RUNS AFTER DEDUPE
cat /root/.cme/logs/SessionGopher* | sed '/^$/d' | grep -v 'SessionGopher' | grep -v 'rvanaghi' | grep -v 'o_' | grep -v ',"  _' | grep -v '"   m m ' | grep -v "  _-" | sed '/^$/d' | sed -e 's/Source/\nSource/g' | sed -e 's/Microsoft/\nMicrosoft/g' | sed -e 's/FileZilla/\nFileZilla/g' | sed -e 's/WinSCP/\nWinSCP/g' | uniq >$OUTDIR/sessiongopher.txt
cat /root/.cmx/logs/SessionGopher* | sed '/^$/d' | grep -v 'SessionGopher' | grep -v 'rvanaghi' | grep -v 'o_' | grep -v ',"  _' | grep -v '"   m m ' | grep -v "  _-" | sed '/^$/d' | sed -e 's/Source/\nSource/g' | sed -e 's/Microsoft/\nMicrosoft/g' | sed -e 's/FileZilla/\nFileZilla/g' | sed -e 's/WinSCP/\nWinSCP/g' | uniq >>$OUTDIR/sessiongopher.txt
echo -e "SessionGopher: Output Parse - Complete\n"

# Removing Empty Files
find $OUTDIR/ -type f -empty -delete

# Finding Unique NTLM Strings
cat $OUTDIR/ntlmrelaySAMs.txt | tr a-z A-Z >>$OUTDIR/uniqNTLM.txt
cat $OUTDIR/crackmapSAM.txt | tr a-z A-Z >>$OUTDIR/uniqNTLM.txt
cat $OUTDIR/crackmapNTLM.txt | tr a-z A-Z >>$OUTDIR/uniqNTLM.txt
gawk -i inplace -F':' '!seen[$1,3,4]++' $OUTDIR/uniqNTLM.txt
echo -e "Unique NTLM Hash Parse - Complete\n"

# Username Parse
cat $OUTDIR/crackmapLSA.txt | cut -d ":" -f 1 | grep '@' | awk -F'@' '{ print $2 "\\" $1}' | tr a-z A-Z >$OUTDIR/usernames.txt
cat $OUTDIR/crackmapPLAIN.txt | sed -e 's#::#/#g' | cut -d "/" -f 1,2 | tr a-z A-Z >>$OUTDIR/usernames.txt
cat $OUTDIR/crackmapOTHER.txt | sed -e 's#:#/#g' | cut -d "/" -f 1,2 | tr a-z A-Z >>$OUTDIR/usernames.txt
cat $OUTDIR/crackmapDCC2.txt | cut -d ":" -f 1 | tr a-z A-Z >>$OUTDIR/usernames.txt
sed -e 's#\\#/#g' -i $OUTDIR/usernames.txt
ex -s +'%!sort' -cxa $OUTDIR/usernames.txt
grep -v "\\\$" $OUTDIR/usernames.txt | sort -u > $OUTDIR/usernames.tmp
mv $OUTDIR/usernames.tmp $OUTDIR/usernames.txt
echo -e "LSA, Plaintext, and DCC Username Parse - Complete\n"

# Showing the output
echo -e "Creds and Hashes gathered from CrackMap, Responder, and PCredz\n"
echo " Lines Filename" && wc -l $OUTDIR/*

##
##
