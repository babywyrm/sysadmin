#!/bin/sh
# both regex and html follow, sorry not sorry
# alias rgg='rg -i --pre-glob '*.{pdf,xlsx,xls,docx,doc,pptx,ppt,html,epub}' --pre rgpre' # note the pre-glob, super important
# ubuntu requirements: 
# sudo apt-get poppler-utils
# termux requirements:
# pkg install poppler
case "$1" in
*.pdf)
   exec pdftotext "$1" -
   ;;
*.xlsx)
   exec unzip -qc "$1" *.xml |  sed -e 's/<\/[vf]>/\n/g; s/<[^>]\{1,\}>//g; s/[^[:print:]\n]\{1,\}//g'
   ;;
*.docx)
   exec unzip -qc "$1" word/document.xml | sed -e 's/<\/w:p>/\n/g; s/<[^>]\{1,\}>//g; s/[^[:print:]\n]\{1,\}//g'
   ;;
*.pptx)
   exec unzip -qc "$1" ppt/slides/*.xml | sed -e 's/<\/a:t>/\n/g; s/<[^>]\{1,\}>//g; s/[^[:print:]\n]\{1,\}//g'
   ;;
*.doc)
   exec strings -d -15 "$1"
   ;;
*.xls)
   exec strings "$1"
   ;;
*.ppt)
   exec strings -d "$1"
   ;;
*.html)
   exec cat "$1" | sed 's/<\/[^>]*>/\n/g'
   ;;
*.epub)
   exec unzip -qc "$1" *.{xhtml,html} |  sed 's/<\/[^>]*>/\n/g'
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
