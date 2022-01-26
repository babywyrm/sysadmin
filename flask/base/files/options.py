from flask import Flask,send_file,send_from_directory

app = Flask(__name__)

# The absolute path of the directory containing images for users to download
app.config["CLIENT_IMAGES"] = "E:/AudiotoText/Flask_File_Downloads/filedownload/files/image"

# The absolute path of the directory containing CSV files for users to download
app.config["CLIENT_CSV"] = "E:/AudiotoText/Flask_File_Downloads/filedownload/files/csv"

# The absolute path of the directory containing PDF files for users to download
app.config["CLIENT_PDF"] = "E:/AudiotoText/Flask_File_Downloads/filedownload/files/pdf"

@app.route('/get-csv/<csv_filename>',methods = ['GET','POST'])
def get_csv(csv_filename):

    try:
        return send_from_directory(app.config["CLIENT_CSV"], filename=csv_filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)


@app.route('/get-pdf/<pdf_filename>',methods = ['GET','POST'])
def get_pdf(pdf_filename):

    try:
        return send_from_directory(app.config["CLIENT_PDF"], filename=pdf_filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)


@app.route("/get-image/<path:image_name>",methods = ['GET','POST'])
def get_image(image_name):

    try:
        return send_from_directory(app.config["CLIENT_IMAGES"], filename=image_name, as_attachment=True)
    except FileNotFoundError:
        abort(404)



if __name__ == '__main__':
    app.run(host='0.0.0.0',port = 8000, threaded = True, debug = True)
    
    
####################
##
