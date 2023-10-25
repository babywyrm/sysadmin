##
##

# modified version of https://github.com/sachaos/viddy/issues/2#issuecomment-907586514 for respecting passed arguments
# eg: vd kgp -n flux-system

function vd() {
    args=$(echo $* | cut -d' ' -f 2-) 
    real_cmd=$(which $1 | cut -d' ' -f 4-) 
    viddy -d -n 1 --shell $SHELL  "$real_cmd $args"
}

##
##

#!/bin/sh

JS_PATH="_js"
FINAL_JS="scripts.js"

SASS_PATH="_sass"
FINAL_CSS="."

echo " ≫ Building and minifying assets."

rm $FINAL_JS
touch $FINAL_JS
cat $JS_PATH/*.js >> $FINAL_JS
echo "  \033[0;32m$FINAL_JS\033[0m"
sass --force --update $SASS_PATH:$FINAL_CSS --style compressed

jsmin --overwrite scripts.js

##
##
