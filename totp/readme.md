Google Authenticator (PAM Module):


# User-specific:

~/.google_authenticator

This is the default file where the Google Authenticator PAM module stores a user’s secret and configuration.

PAM_OATH (for OATH-based OTPs):

# System-wide (commonly): /etc/users.oath or /etc/oath/users.oath
These files (or similar paths) are often used by the PAM_OATH module to store secrets for all users, though the exact location may be set in your PAM configuration.
oathtool:

No fixed default:
The oathtool itself does not manage secret storage. Users typically store their TOTP secrets in a file of their choice (e.g., ~/.totp_secrets, ~/.config/oathtool/secrets, or similar).
Yubico Authenticator (Desktop Version):

User configuration: Typically under the user’s config directories such as

# ~/.config/Yubico/ or ~/.local/share/Yubico/

The exact file name may vary depending on the version and packaging.
LinOTP (if used on Linux for OTP management):

Configuration Directory: Often found in /etc/linotp/
(Note that LinOTP is a full OTP management system rather than a simple TOTP file store.)
Other Custom or Third-Party Tools:

Many desktop authenticators or command-line utilities use per-user configuration directories (e.g., ~/.config/<appname>/ or ~/.local/share/<appname>/)
Since there isn’t a universal standard, you should check the documentation for the specific tool.
In summary, for many Linux environments:

```
Google Authenticator PAM: ~/.google_authenticator
PAM_OATH: /etc/users.oath (or similar)
oathtool: User-defined (commonly something like ~/.totp_secrets)
Yubico Authenticator: Under ~/.config/Yubico/ or ~/.local/share/Yubico/
```




WinAuth:

Typically stores its configuration and TOTP secrets in the user’s application data folder.
Default location:
%APPDATA%\WinAuth\
You may find an XML or JSON file containing the secrets.
Authy Desktop:

The desktop version of Authy often uses either the roaming or local app data folders.
Common locations include:

```%APPDATA%\Authy Desktop\ or %LOCALAPPDATA%\Authy Desktop\ ```

KeePass with TOTP Plugin:

The TOTP secrets are stored within your KeePass database file.
The file’s location is user-defined (often in your Documents folder or a secure directory you’ve chosen).
Microsoft Authenticator (Windows version, if applicable):

Although primarily a mobile app, if you’re using a Windows version or a similar Microsoft authenticator, its data is often stored in a sandboxed location.
For example:

```%LOCALAPPDATA%\Packages\Microsoft.WindowsAuthenticator_8wekyb3d8bbwe\LocalState\```

Note that these folders may require special permissions or tools to access.
Other Third-Party Tools:

Many other Windows TOTP utilities store their data within %APPDATA% or %LOCALAPPDATA% in a folder specific to the application, or even use the Windows Registry.

Check the documentation for the specific tool you’re using.


###
###

# https://hacktricks.boitatech.com.br/pentesting-web/2fa-bypass

2FA/OTP Bypass
Bypassing two-factor authentication
Direct bypass
Fuck the 2FA, just try to access the next endpoint directly (you need to know the path of the next endpoint). If this doesn't work, try to change the Referrer header as if you came from the 2FA page.

Reusing token
Maybe you can reuse an already used token inside the account to authenticate.

Sharing unused tokens
Check if you can get for your account a token and try to use it to bypass the 2FA in a different account.

Leaked Token
Is the token leaked on a response from the web application?

Session permission
Using the same session start the flow using your account and the victims account. When reaching the 2FA point with both account, complete the 2FA with your account but do not access the next part. Instead of that, try to access to the next step with the victims account floe. If the back-end only set a boolean inside your sessions saying that you have successfully passed the 2FA you will be able to bypass the 2FA of the victim.

Password reset function
In almost all web applications the password reset function automatically logs the user into the application after the reset procedure is completed.
Check if a mail is sent with a link to reset the password and if you can reuse that link to reset the password as many times as you want (even if the victim changes his email address).

OAuth
If you can compromise the account of the user in a trusted OAuth platform(Google, Facebook...)

Brute force
Lack of Rate limit
There is any limit in the amount of codes that you can try, so you can just brute force it. Be careful with a possible "silent" rate-limit, always try several codes and then the real one to confirm the vulnerability.

Flow rate limit but no rate limit
In this case there is a flow rate limit (you have to brute force it very slowly: 1 thread and some sleep before 2 tries) but no rate limit. So with enough time you can be able to find the valid code.

Re-send code reset the limit
There is a rate limit but when you "resend the code" the same code is sent and the rate limit is reset. Then, you can brute force the code while you resend it so the rate limit is never reached.

Client side rate limit bypass
Rate Limit Bypass
Lack of rate limit in user's account
Sometimes you can configure the 2FA for some actions inside your account (change mail, password...). However, even in cases where there was a rate limit when you tried to log in, there isn't any rate limit protecting this actions.

Lack of rate limit re-sending the code via SMS
You want be able to bypass the 2FA but you will be able to waste money of the company.

Infinite OTP regeneration
If you can generate a new OTP infinite times, the OTP is simple enough (4 numbers), and you can try up to 4 or 5 tokens per generated OTP, you can just try the same 4 or 5 tokens every time and generate OTPs until it matches the ones you are using.

CSRF/Clickjacking
Check if there is a CSRF or a Clickjacking vulnerability to disable the 2FA.

Remember me functionality
Guessable cookie
If the remember me functionality uses a new cookie with a guessable code, try to guess it.

IP address
If the "remember me" functionality is attached to your IP address, you can try to figure out the IP address of the victim and impersonate it using the X-Forwarded-For header.

Older versions
Subdomains
If you can find some "testing" subdomains with the login functionality, they could be using old versions that don't support 2FA (so it is directly bypassed) or those endpoints could support a vulnerable version of the 2FA.

Apis
If you find that the 2FA is using an API located under a /v*/ directory (like "/v3/"), this probably means that there are older API endpoints that could be vulnerable to some kind of 2FA bypass.

Previous sessions
When the 2FA is enabled, previous sessions created should be ended.This is because when a client has his account compromised he could want to protect it activating the 2FA, but if the previous sessions aren't ended, this won't protect him.

Improper access control to backup codes
Backup codes are being generated immediately after 2FA is enabled and are available on a single request. After each subsequent call to the request, the codes can be regenerated or remain unchanged (static codes). If there are CORS misconfigurations/XSS vulnerabilities and other bugs that allow you to “pull” backup codes from the response’ request of the backup code endpoint, then the attacker could steal the codes and bypass 2FA if the username and password are known.

Information Disclosure
If in the 2FA page appears some confidential information that you didn't know previously (like the phone number) this can be considered an information disclosure vulnerability.

Referrer Check Bypass
Try to navigate to the page which comes after 2FA or any other authenticated page of the application. If there is no success, change the refer header to the 2FA page URL. This may fool application to pretend as if the request came after satisfying 2FA Condition.

References
