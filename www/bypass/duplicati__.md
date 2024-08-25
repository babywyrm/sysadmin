
##
#
https://github.com/duplicati/duplicati/issues/5197
#
##

Comments
@AKiileX
AKiileX commented on May 18
[ x ] I have searched open and closed issues for duplicates.
[ x ] I have searched the forum for related topics.
Environment info
Duplicati version: <= 2.0.7
Operating system: Linux
Backend: Local
Description
When Duplicati is configured with a login password , it is possible to bypass the login authentication using the Database server passphrase without actually knowing the correct password. The issue lies in the way the server passphrase is used to generate the authentication token.

https://github.com/duplicati/duplicati/blob/67c1213a98e9f98659f3d4b78ded82b80ddab8bb/Duplicati/Server/webroot/login/login.js
```
$.ajax({
	url: './login.cgi',
	type: 'POST',
	dataType: 'json',
	data: {'get-nonce': 1}
})
.done(function(data) {
	var saltedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Utf8.parse($('#login-password').val()) + CryptoJS.enc.Base64.parse(data.Salt)));

	var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(data.Nonce) + saltedpwd)).toString(CryptoJS.enc.Base64);

	$.ajax({
		url: './login.cgi',
		type: 'POST',
		dataType: 'json',
		data: {'password': noncedpwd }
	})
```
First saltedpwd is the SHA256 hash of the plaintext password entered by the user concatenated with the salt. Then noncedpwd is the SHA256 hash of the nonce concatenated with saltedpwd, which is then sent as the password parameter to login.cgi.

Steps to reproduce
Setup Duplicati with a login password
Open Duplicati DB using any tool (like sqlite)
Grab the (Server_passphrase)
Open Burp Suite and enable "Intercept".
Go to the Duplicati login page and enter any password.
Intercept the request in Burp Suite and select "Do intercept > Response to this request".
Analyze the intercepted response to retrieve the Nonce and Salt values.
Verify that the Salt matches the one from the Duplicati database and note that the Nonce changes with each request.
Convert the server passphrase from Base64 to Hex.
Open the browser console (Chrome/Firefox), type allow pasting, and run the following modified command:
```
var saltedpwd = 'HexOutputFromCyberChef'; // Replace with the Hex output from step 6
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('NonceFromBurp') + saltedpwd)).toString(CryptoJS.enc.Base64); // Replace 'NonceFromBurp' with the intercepted nonce
console.log(noncedpwd);
```
Copy the noncedpwd value returned by the console.
In Burp Suite, forward the intercepted request and modify the password parameter with the noncedpwd value, URL encoding it if necessary (use CTRL+U in Burp Suite to URL encode).
Forward the request and observe that you are logged into the Duplicati web interface.
Actual result:
Successfully logs into the Duplicati web interface without needing the login password, using the server passphrase.
Expected result:
The server passphrase should not bypass the login authentication. Only the correct login password should grant access to the web interface.
Screenshots
N/A

Debug log
N/A

@kenkendk
Member
kenkendk commented on May 21
Context
It is a problem if someone can access the Duplicati-server.sqlite in some way, as they can extract the password for the UI.
Using the password, it is possible to perform all operations a valid user would do (delete, create new, change, etc), and this can be used to escalate access.

Mitigations
Permissions are set on Windows and Linux/MacOS to prevent unathorized access to the database, meaning that an attacker needs access to the system and the folder where the Duplicati-server.sqlite is stored.

In case the file is, for some reason, part of a backup, it can be obtained through the backup. Encryption on the backup will prevent access, granted that the passphrase is kept secret.

Background
The password mechanism used in Duplicati is designed to never send a token/password that can be used to grant access or reveal the password. In other words, the security is designed to prevent passive & active monitoring over the http-connection between the server (or tray-icon) and the browser.

The scheme works by accepting a nonce/salt (can be attacker chosen) and then hashing the password with this and returning the result. Even if the attacker chooses the salt, they can only obtain the hashed value and not perform MITM because the server will send a new nonce at later connection attempts.

For this scheme to work, the server needs to know the "password" that is used to access it. To avoid storing the actual password in the database, a hash of the password is stored. This is only done to hide a weak password and means that the hash is now the password. It is, however, only slightly better than storing the password clear-text.

Improvements
Given that the password is exchanged for an access token, any attacker listening could simply intercept the access token instead.

Ideally, it would be great if we could get TLS in, but this is hard to do securely for localhost, without exposing the user to a greater risk with an approved self-signed certificate.

An alternative to this is to encrypt values that are sensitive, such as the UI password, and store only the encrypted versions in the database. This requires a good mechanism for storing the database password, which should ideally be using the operating system keychain for this.

Encrypting the entire database is currently not an option for SQLite database, but another database could be used, as performance is non-essential for the settings.

@duplicatibot
duplicatibot commented on Jun 19
This issue has been mentioned on Duplicati. There might be relevant details there:

https://forum.duplicati.com/t/battle-plan-for-dropping-httpserver/18002/7

@kenkendk
Member
kenkendk commented 2 weeks ago
This particular issue has been fixed by #5227 which makes the stored password PBKDF2 hashed.
At the same time that PR introduced a JWT where the signing key is stored in plain, meaning that a similar approach can be used to extract the key and generate a valid token.
That new problem is addressed in #5420.

@kenkendk kenkendk closed this as completed 2 weeks ago
@duplicatibot
duplicatibot commented last week
This issue has been mentioned on Duplicati. There might be relevant details there:

https://forum.duplicati.com/t/release-2-0-9-103-canary-2024-08-15/18827/7

