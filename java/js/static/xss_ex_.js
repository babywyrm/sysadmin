//
//

<!DOCTYPE html>
<html>
<head>
    <title>XSS Example</title>
</head>
<body>
    <h1>Welcome to our website</h1>

    <script>
        // Assume the user's name is obtained from an untrusted source
        var userName = untrustedInput(); // Simulated untrusted input

        // Display the user's name in a script
        var message = "Hello, " + userName + "!";
        document.write("<p>" + message + "</p>");
    </script>
</body>
</html>

//
//

<!DOCTYPE html>
<html>
<head>
    <title>XSS Example</title>
</head>
<body>
    <h1>Welcome to our website</h1>

    <div id="userMessage"></div>

    <script>
        // Assume the user's name is obtained from an untrusted source
        var userName = untrustedInput(); // Simulated untrusted input

        // Sanitize and display the user's name using textContent
        var userMessage = document.getElementById("userMessage");
        userMessage.textContent = "Hello, " + userName + "!";
    </script>
</body>
</html>

//
//
