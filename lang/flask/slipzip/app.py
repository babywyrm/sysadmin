#!/usr/bin/python3

##############################
##
## zipslip-via-flask-tho
##

from flask import Flask, request

import zipfile, os
# Import modules

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(32)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = '/tmp/uploads/'

# Configure flask

@app.route('/') # Define what to do when webroot is hit

def source():

    return '

%s

' % open('/app/run.py').read() # Return this python scripts source code

def zip_extract(zarchive): # Define a function called "zip_extract" and accept a parameter
    with zipfile.ZipFile(zarchive, 'r') as z: # With read zarchive as "z"
        for i in z.infolist(): # For each value (i) in zarchives infolist() output
            with open(os.path.join(app.config['UPLOAD_FOLDER'], i.filename), 'wb') as f:
                f.write(z.open(i.filename, 'r').read()) # Write files in the zip file to the upload folder (/tmp/uploads) appended to our file name (this is vulnerable to the zip slip vulnerability)

@app.route('/zip_upload', methods=['POST']) # Only accept POST method to this endpoint

def zip_upload():
    try: # Error handling
        if request.files and 'zarchive' in request.files: # If a file exists in the request then
            zarchive = request.files['zarchive'] # Assign the contents of the posted file with name "zarchive" to the zarchive variable
            if zarchive and '.' in zarchive.filename and zarchive.filename.rsplit('.', 1)[1].lower() == 'zip' and zarchive.content_type == 'application/octet-stream':

# If zarchive is True (not null), and there is a "." in the filename, and then split the filename into an array, using a "." as a delimiter, check for the second value in the array, and make sure it is zip, finally, check the MIME is application/octet-stream.

                zpath = os.path.join(app.config['UPLOAD_FOLDER'], '%s.zip' % os.urandom(8).hex()) # Set the path of the zip to be /tmp/uploads + 8 random hex bytes + .zip
                zarchive.save(zpath) # Save the zip
                zip_extract(zpath) # Run the extraction zip
                return 'Zip archive uploaded and extracted!' # Return the success message
        return 'Only valid zip archives are acepted!' # Return the restriction error message
    except:

         return 'Error occured during the zip upload process!' # Return the error message

if __name__ == '__main__':

    app.run()
    
################################
##
##
