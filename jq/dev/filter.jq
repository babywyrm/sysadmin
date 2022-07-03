##########   cat filter.jq 
##########   jq -n --argfile source slim.json --argfile target pets.json -f filter.jq 
##########
##
##

([$target|paths(scalars)] | unique) as $paths
| reduce ($source|paths(scalars)) as $p
    ($target;
     if $paths | bsearch($p) > -1 
     then setpath($p; $source|getpath($p))
     else . end)



##
##
###################
###################
