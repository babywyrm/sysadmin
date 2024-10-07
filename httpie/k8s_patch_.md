# example derived from https://kubernetes.io/docs/tasks/administer-cluster/extended-resource-node/

```
NODE_NAME="foo"
URL="localhost:8001/api/v1/nodes/${NODE_NAME}/status Content-Type:application/json-patch+json"
DATA='[{"op": "add", "path": "/status/capacity/example.com~1dongle", "value": "4"}]'

echo -n "${DATA}" | http PATCH "${URL}"

# or
http PATCH "${URL}" <<< "${DATA}"

# or 
http PATCH "${URL}" --raw "${DATA}"
```
##
##

```
##https://gist.github.com/Ryanb58/8b843c325f81b9e6d26a58b92d3aac02
##

curl.example
$ curl -XPUT 'http://localhost:9200/twitter/' -d '{
    index : {
        number_of_shards : 3
        number_of_replicas : 2
    }
}'
@Ryanb58
Author
Ryanb58 commented on Oct 4, 2016 • 
http PUT localhost:9200/twitter/ <<<'{
index : {
number_of_shards : 3
number_of_replicas : 2
}
}'

via redirected input: https://github.com/jkbrzt/httpie#redirected-input
```
##
##
```
# Get username and emails from a Keycloak realm
# assuming you've installed httpie and jq
#
# - https://httpie.io
# - https://jqlang.github.io/jq/

# Armed with a keycloak URL
# And realm and realm manager password
URL=example.com
REALM=blob
PASSWORD=blob1234
# You can get the realm-manager admin CLI token...
http --form POST https://${URL}/auth/realms/${REALM}/protocol/openid-connect/token \
      grant_type=password \
        client_id=admin-cli \
        username=manager \
        password=${PASSWORD}
        
# With this token you can get the users and their emails...
TOKEN=01234567890
http https://${URL}/auth/admin/realms/${REALM}/users \
      "Authorization: bearer ${TOKEN}" | jq '[.[] | {username: .username, email: .email}]'
