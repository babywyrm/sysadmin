```

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
