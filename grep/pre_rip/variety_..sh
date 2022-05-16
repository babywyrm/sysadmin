#!/bin/sh
############################
# ~~both regex and html follow, sorry not~~ sorry
#alias rgg="rg -i -z --max-columns-preview --max-columns 900 --hidden --no-ignore --pre-glob '*.{pdf,xl[tas][bxm],xl[wsrta],do[ct],do[ct][xm],p[po]t[xm],p[op]t,html,epub,chm}' --pre rgpre"
# ubuntu wants: sudo apt-get poppler-utils, p7zip, w3m
# simplest way to deal with mobi files is here -> https://github.com/kevinhendricks/KindleUnpack/archive/v032.zip
# obvious room for improvement not done here - fix regex of epub and chm to address occasionally nested files
# obvious room for improvement not done here - add appropriate flags to strings for xls/ppt/doc
# better binaries for specific filetypes for haters of recoll / lovers of complexity
# -- -- catdoc, catppt, xls2csv
# termux wants: pkg install poppler, p7zip, w3m
case "$1" in
*.pdf)
   exec pdftotext -layout "$1" -
   ;;
*.xl[ast][xmt])
   exec unzip -qc "$1" *.xml |  sed -e 's/<\/[vft]>/\n/g; s/<[^>]\{1,\}>//g; s/[^[:print:]\n]\{1,\}//g'
   ;;
*.xlsb)
   unzip -qc "$1" *.bin |  strings -e l
   ;;
*.xl[wsrta])
   exec strings  "$1"
   ;;
*.do[ct])
   exec strings -d -15 "$1"
   ;;
*.do[tc][xm])
   exec unzip -qc "$1" word/document.xml | sed -e 's/<\/w:p>/\n/g; s/<[^>]\{1,\}>//g; s/[^[:print:]\n]\{1,\}//g'
   ;;
*.p[po]t)
   exec strings -d "$1"
   ;;
*.p[po]t[xm])
   exec unzip -qc "$1" ppt/slides/*.xml | sed -e 's/<\/a:t>/\n/g; s/<[^>]\{1,\}>//g; s/[^[:print:]\n]\{1,\}//g'
   
####################
##
##
   ;;
*.html)
   exec cat "$1" | w3m -T text/html -dump -cols 250
   ;;
*.epub)
   exec unzip -qc "$1" *.*htm* |  w3m -T text/html -dump -cols 250
   ;;
*.chm)
   exec 7z e -r -so "$1" *.*htm* | w3m -T text/html -dump -cols 250
   ;;
*)
   case $(file "$1") in
   *Zstandard*)
       exec pzstd -cdq
       ;;
   *)
       exec cat
       ;;
   esac
   ;;
esac
