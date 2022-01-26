import zipfile
import os
from flask import send_file,Flask,send_from_directory

app = Flask(__name__)

@app.route('/download_files')
def download_all():
    # Zip file Initialization and you can change the compression type
    zipfolder = zipfile.ZipFile('Audiofiles.zip','w', compression = zipfile.ZIP_STORED)

    # zip all the files which are inside in the folder
    for root,dirs, files in os.walk('sortoutaudio/'):
        for file in files:
            zipfolder.write('sortoutaudio/'+file)
    zipfolder.close()

    return send_file('Audiofiles.zip',
            mimetype = 'zip',
            attachment_filename= 'Audiofiles.zip',
            as_attachment = True)

    # Delete the zip file if not needed
    os.remove("Audiofiles.zip")

if __name__ == '__main__':
    app.run(host = '0.0.0.0', port = 8000 , debug= False, threaded = True)
    
############################
##
##
