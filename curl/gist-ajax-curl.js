//
// http://techslides.com/github-gist-api-with-curl-and-ajax
//
// curl -sS --remote-name-all $(curl -sS https://api.github.com/gists/997ccc3690ccd3ac5196211aff59d989 | jq -r '.files[].raw_url')
// Downloads each file from a github gist individually. 
// Requires jq ( https://stedolan.github.io/jq/ ).
//
// Download all files from a Gist without Git
// https://twitter.com/westonruter/status/501855721172922369
// curl -L https://gist.github.com/westonruter/ea038141e46e017d280b/download | tar -xvz --strip-components=1
//

/*
Assuming jQuery Ajax instead of vanilla XHR
*/

//Get Github Authorization Token with proper scope, print to console
$.ajax({ 
    url: 'https://api.github.com/authorizations',
    type: 'POST',
    beforeSend: function(xhr) { 
        xhr.setRequestHeader("Authorization", "Basic " + btoa("USERNAME:PASSWORD")); 
    },
    data: '{"scopes":["gist"],"note":"ajax gist test for a user"}'
}).done(function(response) {
    console.log(response);
});

//Create a Gist with token from above
$.ajax({ 
    url: 'https://api.github.com/gists',
    type: 'POST',
    beforeSend: function(xhr) { 
        xhr.setRequestHeader("Authorization", "token TOKEN-FROM-AUTHORIZATION-CALL"); 
    },
    data: '{"description": "a gist for a user with token api call via ajax","public": true,"files": {"file1.txt": {"content": "String file contents via ajax"}}}'
}).done(function(response) {
    console.log(response);
});

//Using Gist ID from the response above, we edit the Gist with Ajax PATCH request
$.ajax({ 
    url: 'https://api.github.com/gists/GIST-ID-FROM-PREVIOUS-CALL',
    type: 'PATCH',
    beforeSend: function(xhr) { 
        xhr.setRequestHeader("Authorization", "token TOKEN-FROM-AUTHORIZATION-CALL"); 
    },
    data: '{"description": "updated gist via ajax","public": true,"files": {"file1.txt": {"content": "updated String file contents via ajax"}}}'
}).done(function(response) {
    console.log(response);
});
