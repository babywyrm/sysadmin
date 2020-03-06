  
#!/bin/bash
##
###############################################
###
# Author: Andrew Howard
##   
##  https://github.com/StafDehat/scripts/blob/master/testMtu.sh
##  _c/o_Messiah__also_refactor_to_pyth3_and_powershell__
##
###############################################
function max() {
  for x in ${@}; do
    echo "${x}"
  done | sort -n | tail -n 1
}

function debug() {
  echo "${@}" >&2
}

function testMtu() {
  local dstHost
  dstHost="${1}"

  local testSize
  local lower
  testSize=1500
  lower=29
  upper=999999999
  while true; do
    debug "${lower} <= MTU < ${upper}"
    if [[ "${testSize}" -le "${lower}" ]]; then
      break
    fi
    if ping -c 2 -i 0.1 -M do -s $((testSize-28)) "${dstHost}" &>/dev/null; then
      lower=$( max "${testSize}" "${lower}" )
      testSize=$(( testSize * 2 ))
    else
      upper="${testSize}"
      testSize=$(( (testSize-lower) / 2 + lower ))
    fi
  done
  echo "${testSize}"
}

###########################################
