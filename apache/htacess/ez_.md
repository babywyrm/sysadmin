```


#stop directory browsing
Options All -Indexes

# SSL Https active Force non-www
<IfModule mod_rewrite.c>
   RewriteEngine on
   RewriteCond %{HTTP_HOST} ^www\.(.*)$ [NC]
   RewriteRule ^(.*)$ https://%1/$1 [R=301,L]
   RewriteCond %{HTTPS} !=on
   RewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]
</IfModule>

# SSL Https Active Force www in a Generic Way
<IfModule mod_rewrite.c>
   RewriteEngine on
   RewriteCond %{HTTP_HOST} !^$
   RewriteCond %{HTTP_HOST} !^www\. [NC]
   RewriteCond %{HTTPS}s ^on(s)|
   RewriteRule ^ https://www.%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</IfModule>


# Remove .php, .html, .htm extensions with .htaccess
<IfModule mod_rewrite.c>
    
    # domain.com/page
    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^([^\.]+)$ $1.php [NC,L]
   
    
    # domain.com/page/
    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^([^/]+)/$ $1.php
    RewriteRule ^([^/]+)/([^/]+)/$ /$1/$2.php
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} !(\.[a-zA-Z0-9]{1,5}|/)$
    RewriteRule (.*)$ /$1/ [R=301,L]
    
</IfModule>


#AIOWPS_PREVENT_IMAGE_HOTLINKS_START
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{HTTP_REFERER} !^$
RewriteCond %{REQUEST_FILENAME} -f
RewriteCond %{REQUEST_FILENAME} \.(gif|jpe?g?|png)$ [NC]
RewriteCond %{HTTP_REFERER} !^http(s)?://univahost\.com [NC]
RewriteRule \.(gif|jpe?g?|png)$ - [F,NC,L]
</IfModule>
#AIOWPS_PREVENT_IMAGE_HOTLINKS_END


# Text FIle access
<files file.txt>
order allow,deny
deny from all
</files>


# Block double extensions from being uploaded or accessed, including htshells
<FilesMatch ".*\.([^.]+)\.([^.]+)$">
Order Deny,Allow
Deny from all
</FilesMatch>

# secure uploads directory
<FilesMatch "\.(jpg|jpeg|jpe|gif|png|tif|tiff)$">
    Order Deny,Allow
    Allow from all
</FilesMatch>


# Block shell uploaders, htshells, and other baddies
RewriteCond %{REQUEST_URI} ((php|my|bypass)?shell|remview.*|phpremoteview.*|sshphp.*|pcom|nstview.*|c99|c100|r57|webadmin.*|phpget.*|phpwriter.*|fileditor.*|locus7.*|storm7.*)\.(p?s?x?htm?l?|txt|aspx?|cfml?|cgi|pl|php[3-9]{0,1}|jsp?|sql|xml) [NC,OR]
RewriteCond %{REQUEST_URI} (\.exe|\.php\?act=|\.tar|_vti|afilter=|algeria\.php|chbd|chmod|cmd|command|db_query|download_file|echo|edit_file|eval|evil_root|exploit|find_text|fopen|fsbuff|fwrite|friends_links\.|ftp|gofile|grab|grep|htshell|\ -dump|logname|lynx|mail_file|md5|mkdir|mkfile|mkmode|MSOffice|muieblackcat|mysql|owssvr\.dll|passthru|popen|proc_open|processes|pwd|rmdir|root|safe0ver|search_text|selfremove|setup\.php|shell|ShellAdresi\.TXT|spicon|sql|ssh|system|telnet|trojan|typo3|uname|unzip|w00tw00t|whoami|xampp) [NC,OR]
RewriteCond %{QUERY_STRING} (\.exe|\.tar|act=|afilter=|alter|benchmark|chbd|chmod|cmd|command|cast|char|concat|convert|create|db_query|declare|delete|download_file|drop|edit_file|encode|environ|eval|exec|exploit|find_text|fsbuff|ftp|friends_links\.|globals|gofile|grab|insert|localhost|logname|loopback|mail_file|md5|meta|mkdir|mkfile|mkmode|mosconfig|muieblackcat|mysql|order|passthru|popen|proc_open|processes|pwd|request|rmdir|root|scanner|script|search_text|select|selfremove|set|shell|sql|sp_executesql|spicon|ssh|system|telnet|trojan|truncate|uname|union|unzip|whoami) [NC]
RewriteRule .* - [F]



# Follow symbolic links in this directory.
Options +FollowSymLinks

# Set the default handler.
DirectoryIndex index.php index.html index.htm

# Set the default handler.
DirectoryIndex index.php index.html index.htm

# Override PHP settings that cannot be changed at runtime. See
# sites/default/default.settings.php and drupal_environment_initialize() in
# includes/bootstrap.inc for settings that can be changed at runtime.

# PHP 5, Apache 1 and 2.
<IfModule mod_php5.c>
  php_flag magic_quotes_gpc                 off
  php_flag magic_quotes_sybase              off
  php_flag register_globals                 off
  php_flag session.auto_start               off
  php_value mbstring.http_input             pass
  php_value mbstring.http_output            pass
  php_flag mbstring.encoding_translation    off
</IfModule>

# Default Carset
AddDefaultCharset utf-8
DirectoryIndex index.html index.htm index.php

# File Control
<FilesMatch ".(flv|gif|jpg|jpeg|png|ico|swf|js|css|pdf)$">
  Header set Cache-Control "max-age=2592000"
</FilesMatch>

# Htaccess File Security
<Files .htaccess>
order allow,deny
deny from all
</Files>


# Adding this to your .htaccess will prevent hotlinking from happening:
RewriteEngine on
RewriteCond %{HTTP_REFERER} !^$
RewriteCond %{HTTP_REFERER} !^http(s)?://(www\.)?YourDomain [NC]
RewriteRule \.(jpg|jpeg|png|gif)$ - [NC,F,L]


# Protect the .htaccess Itself
<files ~ "^.*\.([Hh][Tt][Aa])">
order allow,deny
deny from all
satisfy all
</files>

 
# Leverage Browser Caching
<IfModule mod_expires.c>
  ExpiresActive On
  ExpiresByType image/jpg "access 1 year"
  ExpiresByType image/jpeg "access 1 year"
  ExpiresByType image/gif "access 1 year"
  ExpiresByType image/png "access 1 year"
  ExpiresByType text/css "access 1 month"
  ExpiresByType text/html "access 1 month"
  ExpiresByType application/pdf "access 1 month"
  ExpiresByType text/x-javascript "access 1 month"
  ExpiresByType application/x-shockwave-flash "access 1 month"
  ExpiresByType image/x-icon "access 1 year"
  ExpiresDefault "access 1 month"
</IfModule>
<IfModule mod_headers.c>
  <filesmatch "\.(ico|flv|jpg|jpeg|png|gif|css|swf)$">
  Header set Cache-Control "max-age=2678400, public"
  </filesmatch>
  <filesmatch "\.(html|htm)$">
  Header set Cache-Control "max-age=7200, private, must-revalidate"
  </filesmatch>
  <filesmatch "\.(pdf)$">
  Header set Cache-Control "max-age=86400, public"
  </filesmatch>
  <filesmatch "\.(js)$">
  Header set Cache-Control "max-age=2678400, private"
  </filesmatch>
</IfModule>




# Enable Compression
<IfModule mod_deflate.c>
  AddOutputFilterByType DEFLATE application/javascript
  AddOutputFilterByType DEFLATE application/rss+xml
  AddOutputFilterByType DEFLATE application/vnd.ms-fontobject
  AddOutputFilterByType DEFLATE application/x-font
  AddOutputFilterByType DEFLATE application/x-font-opentype
  AddOutputFilterByType DEFLATE application/x-font-otf
  AddOutputFilterByType DEFLATE application/x-font-truetype
  AddOutputFilterByType DEFLATE application/x-font-ttf
  AddOutputFilterByType DEFLATE application/x-javascript
  AddOutputFilterByType DEFLATE application/xhtml+xml
  AddOutputFilterByType DEFLATE application/xml
  AddOutputFilterByType DEFLATE font/opentype
  AddOutputFilterByType DEFLATE font/otf
  AddOutputFilterByType DEFLATE font/ttf
  AddOutputFilterByType DEFLATE image/svg+xml
  AddOutputFilterByType DEFLATE image/x-icon
  AddOutputFilterByType DEFLATE text/css
  AddOutputFilterByType DEFLATE text/html
  AddOutputFilterByType DEFLATE text/javascript
  AddOutputFilterByType DEFLATE text/plain
</IfModule>

<IfModule mod_gzip.c>
  mod_gzip_on Yes
  mod_gzip_dechunk Yes
  mod_gzip_item_include file .(html?|txt|css|js|php|pl)$
  mod_gzip_item_include handler ^cgi-script$
  mod_gzip_item_include mime ^text/.*
  mod_gzip_item_include mime ^application/x-javascript.*
  mod_gzip_item_exclude mime ^image/.*
  mod_gzip_item_exclude rspheader ^Content-Encoding:.*gzip.*
</IfModule>

# Block Bad Bots
# Block one or more IP address.
# Replace IP_ADDRESS_* with the IP you want to block
<Limit GET POST>
order allow,deny
deny from IP_ADDRESS_1
deny from IP_ADDRESS_2
allow from all
</Limit>


# Restrict All Access to wp-includes
# Block wp-includes folder and files
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^wp-admin/includes/ - [F,L]
RewriteRule !^wp-includes/ - [S=3]
RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]
RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]
RewriteRule ^wp-includes/theme-compat/ - [F,L]
</IfModule>

# Allow only Selected IP Addresses to Access wp-admin
# Limit logins and admin by IP
<Limit GET POST PUT>
order deny,allow
deny from all
allow from 302.143.54.102
allow from IP_ADDRESS_2
</Limit>


# Protect wp-config.php and .htaccess from everyone
# Deny access to wp-config.php file
<files wp-config.php>
order allow,deny
deny from all
</files>
# Deny access to all .htaccess files
<files ~ "^.*\.([Hh][Tt][Aa])">
order allow,deny
deny from all
satisfy all
</files>


# Redirect to a Maintenance page
# Redirect all traffic to maintenance.html file
RewriteEngine on
RewriteCond %{REQUEST_URI} !/maintenance.html$
RewriteCond %{REMOTE_ADDR} !^123\.123\.123\.123
RewriteRule $ /maintenance.html [R=302,L] 

# Custom Error Pages
# Custom error page for error 403, 404 and 500
ErrorDocument 404 /error.html
ErrorDocument 403 /error.html
ErrorDocument 500 /error.html



# Hide extension like .html or .php from the URL path show only file name in normal HTML or PHP sites
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^([^\.]+)$ $1.php [NC,L]
</IfModule>


# Protect .htaccess From Unauthorized Access
<files ~ "^.*\.([Hh][Tt][Aa])">
order allow,deny
deny from all
satisfy all
</files>

# Increase File Upload Size
php_value upload_max_filesize 64M
php_value post_max_size 64M
php_value max_execution_time 300
php_value max_input_time 300

# Blocking Author Scans in WordPress

RewriteEngine On
RewriteBase /
RewriteCond %{QUERY_STRING} (author=\d+) [NC]
RewriteRule .* - [F]


# Password Protect your Applection Admin Login DIR
AuthName "Admins Only"
AuthUserFile /home/yourdirectory/.htpasswds/public_html/wp-admin/passwd
AuthGroupFile /dev/null
AuthType basic
require user putyourusernamehere
<Files admin-ajax.php>
Order allow,deny
Allow from all
Satisfy any 
</Files>

##
##
#Hide directories and files
Options -Indexes

#Set Enviroment Varaibles
SetEnv APPLICATION_ENV "development"

# Enable the rewrite engine
RewriteEngine On

# redirect non www to www
RewriteCond %{HTTP_HOST} !^$
RewriteCond %{HTTP_HOST} !^www\. [NC]
RewriteCond %{HTTPS}s ^on(s)|
RewriteRule ^ http%1://www.%{HTTP_HOST}%{REQUEST_URI} [R=301,L]


# Force SSL
RewriteCond %{HTTPS} !=on
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Forece SSL and the www
RewriteCond %{HTTP_HOST} ^www\.(.+)$ [NC]
RewriteRule ^(.*)$ https://%1/$1 [R=301,L]


 	#little bit more secure?

#post/comment/login with bad referer
RewriteEngine On
RewriteCond %{REQUEST_METHOD} POST
RewriteCond %{REQUEST_URI} .admin* [OR]
RewriteCond %{REQUEST_URI} .login\.php* [OR]
RewriteCond %{REQUEST_URI} .wp-comments-post\.php*
RewriteCond %{HTTP_HOST}@@%{HTTP_REFERER} !^([^@]*)@@https?://\1/.* [OR]
RewriteCond %{HTTP_USER_AGENT} ^$
RewriteRule ^(.*)$ http://www.ndparking.com/serve.php?lid=557555&dn=%{HTTP_HOST} [R=301,L]

# Prevent Directoy listing 
Options -Indexes
IndexIgnore *
# all access to subfolder will get /index.php
DirectoryIndex index.html index.php /index.html /index.php /404.php

RewriteEngine on

# from wp forum
# Forbid fingerprinting variants of timthumb and thumbs.db
# (with or without tim or php prefixes, s (plural), various php and db extensions, or infected theme cache directory files)
RewriteCond %{REQUEST_FILENAME} ^(tim|php)?thumb(s)?\.(php[2-5]?|db)$ [NC,OR]
RewriteCond %{REQUEST_FILENAME} /uploads/[a-f0-9]+\.php[2-5]?$ [NC,OR]
RewriteCond %{REQUEST_FILENAME} /cache/[a-f0-9]+\.php[2-5]?$ [NC]
RewriteRule ^.*$ http://superherbfood.blogspot.com/?dari=gist [R,L]
#RewriteRule .* - [F]

# Prevent Direct Access to files
<FilesMatch "\.(tpl|ini|log|htaccess|htpasswd|phps|fla|psd|sh|inc|sql|dtb)">
 Order deny,allow
 Deny from all
</FilesMatch>

<FilesMatch "(config.php|readme|timthumb|phpthumb|thumb.php|thumbs.php)">
 Order deny,allow
 Deny from all
</FilesMatch>
6scan.htaccess
# Created by 6Scan plugin
#don't show directory listing and apache information
ServerSignature Off

<IfModule mod_rewrite.c>
RewriteEngine On

#Broad-spectrum protection: User agent/referrer injections. XSS,RFI and SQLI prevention
RewriteCond %{HTTP_USER_AGENT} (<|%3c|>|%3e|'|%27|%00) [NC,OR]
RewriteCond %{HTTP_REFERER} (<|%3c|>|%3e|'|%27|%00) [NC,OR]
RewriteCond %{QUERY_STRING} (<|%3c).*(script|iframe|src).*(>|%3e) [NC,OR]
RewriteCond %{QUERY_STRING} (http(s)?:\/\/|ftp:\/\/|zlib:|bzip2:) [NC,OR]
RewriteCond %{QUERY_STRING} union.*select [NC,OR]
RewriteCond %{QUERY_STRING} (concat|delete|right|ascii|left|mid|version|substring|extractvalue|benchmark|load_file).*\(.*\)	[NC,OR]
RewriteCond %{QUERY_STRING} (into.*outfile) [NC,OR]
RewriteCond %{QUERY_STRING} (having.*--) [NC]
RewriteRule .*  - [E=sixscansecuritylog:1] -


</IfModule>
# End of 6Scan plugin
iana.htaccess
#link local RFC5735
deny from 0.0.0.0/8 
deny from 169.254.0.0/16

#private RFC1918 #warning: do not block your own LAN!
deny from 10.0.0.0/8 
deny from 172.16.0.0/12
deny from 192.168.0.0/16

#test RFC5737
deny from 192.0.2.0/24
deny from 198.51.100.0/24
deny from 203.0.113.0/24

#others
deny from 224.0.0.0/4 #multicast 
deny from 240.0.0.0/4 #future 
deny from 198.18.0.0/15 #benchmark test RFC2544][RFC3330
#deny from 192.0.0.0/8 #RFC5736 this is big and might block your lan too!
sucuri.htaccess
#http://blog.sucuri.net/2012/05/sucuri-wordpress-security-plugin-protects-against-php-cgi-vulnerability.html
RewriteCond %{QUERY_STRING} ^[^=]*$
RewriteCond %{QUERY_STRING} %2d|\- [NC]
RewriteRule ^.*$ http://superherbfood.blogspot.com/?dari=gist[R,L]
w3tc.htaccess
# BEGIN W3TC Browser Cache
<IfModule mod_mime.c>
    AddType text/css .css
    AddType application/x-javascript .js
    AddType text/x-component .htc
    AddType text/html .html .htm
    AddType text/richtext .rtf .rtx
    AddType image/svg+xml .svg .svgz
    AddType text/plain .txt
    AddType text/xsd .xsd
    AddType text/xsl .xsl
    AddType text/xml .xml
    AddType video/asf .asf .asx .wax .wmv .wmx
    AddType video/avi .avi
    AddType image/bmp .bmp
    AddType application/java .class
    AddType video/divx .divx
    AddType application/msword .doc .docx
    AddType application/vnd.ms-fontobject .eot
    AddType application/x-msdownload .exe
    AddType image/gif .gif
    AddType application/x-gzip .gz .gzip
    AddType image/x-icon .ico
    AddType image/jpeg .jpg .jpeg .jpe
    AddType application/vnd.ms-access .mdb
    AddType audio/midi .mid .midi
    AddType video/quicktime .mov .qt
    AddType audio/mpeg .mp3 .m4a
    AddType video/mp4 .mp4 .m4v
    AddType video/mpeg .mpeg .mpg .mpe
    AddType application/vnd.ms-project .mpp
    AddType application/x-font-otf .otf
    AddType application/vnd.oasis.opendocument.database .odb
    AddType application/vnd.oasis.opendocument.chart .odc
    AddType application/vnd.oasis.opendocument.formula .odf
    AddType application/vnd.oasis.opendocument.graphics .odg
    AddType application/vnd.oasis.opendocument.presentation .odp
    AddType application/vnd.oasis.opendocument.spreadsheet .ods
    AddType application/vnd.oasis.opendocument.text .odt
    AddType audio/ogg .ogg
    AddType application/pdf .pdf
    AddType image/png .png
    AddType application/vnd.ms-powerpoint .pot .pps .ppt .pptx
    AddType audio/x-realaudio .ra .ram
    AddType application/x-shockwave-flash .swf
    AddType application/x-tar .tar
    AddType image/tiff .tif .tiff
    AddType application/x-font-ttf .ttf .ttc
    AddType audio/wav .wav
    AddType audio/wma .wma
    AddType application/vnd.ms-write .wri
    AddType application/vnd.ms-excel .xla .xls .xlsx .xlt .xlw
    AddType application/zip .zip
</IfModule>
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType text/css A31536000
    ExpiresByType application/x-javascript A31536000
    ExpiresByType text/x-component A31536000
    ExpiresByType text/html A3600
    ExpiresByType text/richtext A3600
    ExpiresByType image/svg+xml A3600
    ExpiresByType text/plain A3600
    ExpiresByType text/xsd A3600
    ExpiresByType text/xsl A3600
    ExpiresByType text/xml A3600
    ExpiresByType video/asf A31536000
    ExpiresByType video/avi A31536000
    ExpiresByType image/bmp A31536000
    ExpiresByType application/java A31536000
    ExpiresByType video/divx A31536000
    ExpiresByType application/msword A31536000
    ExpiresByType application/vnd.ms-fontobject A31536000
    ExpiresByType application/x-msdownload A31536000
    ExpiresByType image/gif A31536000
    ExpiresByType application/x-gzip A31536000
    ExpiresByType image/x-icon A31536000
    ExpiresByType image/jpeg A31536000
    ExpiresByType application/vnd.ms-access A31536000
    ExpiresByType audio/midi A31536000
    ExpiresByType video/quicktime A31536000
    ExpiresByType audio/mpeg A31536000
    ExpiresByType video/mp4 A31536000
    ExpiresByType video/mpeg A31536000
    ExpiresByType application/vnd.ms-project A31536000
    ExpiresByType application/x-font-otf A31536000
    ExpiresByType application/vnd.oasis.opendocument.database A31536000
    ExpiresByType application/vnd.oasis.opendocument.chart A31536000
    ExpiresByType application/vnd.oasis.opendocument.formula A31536000
    ExpiresByType application/vnd.oasis.opendocument.graphics A31536000
    ExpiresByType application/vnd.oasis.opendocument.presentation A31536000
    ExpiresByType application/vnd.oasis.opendocument.spreadsheet A31536000
    ExpiresByType application/vnd.oasis.opendocument.text A31536000
    ExpiresByType audio/ogg A31536000
    ExpiresByType application/pdf A31536000
    ExpiresByType image/png A31536000
    ExpiresByType application/vnd.ms-powerpoint A31536000
    ExpiresByType audio/x-realaudio A31536000
    ExpiresByType image/svg+xml A31536000
    ExpiresByType application/x-shockwave-flash A31536000
    ExpiresByType application/x-tar A31536000
    ExpiresByType image/tiff A31536000
    ExpiresByType application/x-font-ttf A31536000
    ExpiresByType audio/wav A31536000
    ExpiresByType audio/wma A31536000
    ExpiresByType application/vnd.ms-write A31536000
    ExpiresByType application/vnd.ms-excel A31536000
    ExpiresByType application/zip A31536000
</IfModule>
<IfModule mod_deflate.c>
    <IfModule mod_setenvif.c>
        BrowserMatch ^Mozilla/4 gzip-only-text/html
        BrowserMatch ^Mozilla/4\.0[678] no-gzip
        BrowserMatch \bMSIE !no-gzip !gzip-only-text/html
        BrowserMatch \bMSI[E] !no-gzip !gzip-only-text/html
    </IfModule>
    <IfModule mod_headers.c>
        Header append Vary User-Agent env=!dont-vary
    </IfModule>
    <IfModule mod_filter.c>
        AddOutputFilterByType DEFLATE text/css application/x-javascript text/x-component text/html text/richtext image/svg+xml text/plain text/xsd text/xsl text/xml image/x-icon
    </IfModule>
</IfModule>
<FilesMatch "\.(css|js|htc|CSS|JS|HTC)$">
    <IfModule mod_headers.c>
        Header set Pragma "public"
        Header append Cache-Control "public, must-revalidate, proxy-revalidate"
    </IfModule>
    FileETag MTime Size
    <IfModule mod_headers.c>
         Header set X-Powered-By "W3 Total Cache/0.9.2.4"
    </IfModule>
</FilesMatch>
<FilesMatch "\.(html|htm|rtf|rtx|svg|svgz|txt|xsd|xsl|xml|HTML|HTM|RTF|RTX|SVG|SVGZ|TXT|XSD|XSL|XML)$">
    <IfModule mod_headers.c>
        Header set Pragma "public"
        Header append Cache-Control "public, must-revalidate, proxy-revalidate"
    </IfModule>
    FileETag MTime Size
    <IfModule mod_headers.c>
         Header set X-Powered-By "W3 Total Cache/0.9.2.4"
    </IfModule>
</FilesMatch>
<FilesMatch "\.(asf|asx|wax|wmv|wmx|avi|bmp|class|divx|doc|docx|eot|exe|gif|gz|gzip|ico|jpg|jpeg|jpe|mdb|mid|midi|mov|qt|mp3|m4a|mp4|m4v|mpeg|mpg|mpe|mpp|otf|odb|odc|odf|odg|odp|ods|odt|ogg|pdf|png|pot|pps|ppt|pptx|ra|ram|svg|svgz|swf|tar|tif|tiff|ttf|ttc|wav|wma|wri|xla|xls|xlsx|xlt|xlw|zip|ASF|ASX|WAX|WMV|WMX|AVI|BMP|CLASS|DIVX|DOC|DOCX|EOT|EXE|GIF|GZ|GZIP|ICO|JPG|JPEG|JPE|MDB|MID|MIDI|MOV|QT|MP3|M4A|MP4|M4V|MPEG|MPG|MPE|MPP|OTF|ODB|ODC|ODF|ODG|ODP|ODS|ODT|OGG|PDF|PNG|POT|PPS|PPT|PPTX|RA|RAM|SVG|SVGZ|SWF|TAR|TIF|TIFF|TTF|TTC|WAV|WMA|WRI|XLA|XLS|XLSX|XLT|XLW|ZIP)$">
    <IfModule mod_headers.c>
        Header set Pragma "public"
        Header append Cache-Control "public, must-revalidate, proxy-revalidate"
    </IfModule>
    FileETag MTime Size
    <IfModule mod_headers.c>
         Header set X-Powered-By "W3 Total Cache/0.9.2.4"
    </IfModule>
</FilesMatch>
# END W3TC Browser Cache
