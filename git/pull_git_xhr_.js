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
