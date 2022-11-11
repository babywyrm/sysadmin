#####
#####

echo '[{"name": "name #1", "value": "value #1"} , {"name": "name#2", "value": "value#2"}]' |

jq --raw-output 'map([.name, .value])[] | @tsv' |

while IFS=$'\t' read name value; do
    echo "$name = $value"
done

#####
#####

for row in $(echo "${jsonData}" | jq -r '.daos[] | @base64'); do
     name=$(echo ${row} | base64 --decode | jq -r '.name | @html' )
done

#####
#####

jsonData='[{"name": "name#1","value": "value#1"},{"name": "name#2","value": "value#2"}]'
for row in $(echo "${jsonData}" | jq -r '.[] | @base64'); do
    _jq() {
     echo "${row}" | base64 --decode | jq -r "${1}"
    }
    
    # OPTIONAL
    # Set each property of the row to a variable
    name=$(_jq '.name')
    value=$(_jq '.value')

    # Utilize your variables
    echo "$name = $value"
done

# $ stoxe@box:~$ ./loop-json-test.sh 
#     name#1 = value#1\
#     name#2 = value#2
@nate

#####
#####

