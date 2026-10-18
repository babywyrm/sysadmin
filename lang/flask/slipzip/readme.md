

## https://stackoverflow.com/questions/27337013/how-to-send-zip-files-in-the-python-flask-framework

How to send zip files in the python Flask framework?
Asked 7 years, 2 months ago
Active 2 years, 8 months ago
Viewed 33k times

Report this ad

31


11
I have a flask server that grabs binary data for several different files from a database and puts them into a python 'zipfile' object. I want to send the generated zip file with my code using flask's "send_file" method.

I was originally able to send non-zip files successfully by using the BytesIO(bin) as the first argument to send_file, but for some reason I can't do the same thing with my generated zip file. It gives the error:

'ZipFile' does not have the buffer interface.

How do I send this zip file object to the user with Flask?

This is my code:

@app.route("/getcaps",methods=['GET','POST'])
def downloadFiles():
    if request.method == 'POST':
        mongo = MongoDAO('localhost',27017)
        identifier = request.form['CapsuleName']
        password = request.form['CapsulePassword']
        result = mongo.getCapsuleByIdentifier(identifier,password)
        zf = zipfile.ZipFile('capsule.zip','w')
        files = result['files']
        for individualFile in files:
            data = zipfile.ZipInfo(individualFile['fileName'])
            data.date_time = time.localtime(time.time())[:6]
            data.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(data,individualFile['fileData'])
        return send_file(BytesIO(zf), attachment_filename='capsule.zip', as_attachment=True)
    return render_template('download.html')
python
http
flask
zipfile
Share
Improve this question
Follow
edited Dec 11 '17 at 22:56

dreftymac
29k2525 gold badges111111 silver badges174174 bronze badges
asked Dec 6 '14 at 21:54

idungotnosn
1,92144 gold badges2727 silver badges3535 bronze badges
2
See also: stackoverflow.com/questions/26513542/… – 
dreftymac
 Dec 11 '17 at 22:57
Add a comment
1 Answer

50

BytesIO() needs to be passed bytes data, but a ZipFile() object is not bytes-data; you actually created a file on your harddisk.

You can create a ZipFile() in memory by using BytesIO() as the base:

memory_file = BytesIO()
with zipfile.ZipFile(memory_file, 'w') as zf:
    files = result['files']
    for individualFile in files:
        data = zipfile.ZipInfo(individualFile['fileName'])
        data.date_time = time.localtime(time.time())[:6]
        data.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(data, individualFile['fileData'])
memory_file.seek(0)
return send_file(memory_file, attachment_filename='capsule.zip', as_attachment=True)
The with statement ensures that the ZipFile() object is properly closed when you are done adding entries, causing it to write the required trailer to the in-memory file object. The memory_file.seek(0) call is needed to 'rewind' the read-write position of the file object back to the start.

Share
Improve this answer
Follow
answered Dec 6 '14 at 21:57

Martijn Pieters♦
939k257257 gold badges37173717 silver badges31333133 bronze badges
How would I do this when I just have files = ['filename1', 'filename2'] i.e. files on the server site which I would like to zip and send? – 
Cleb
 Jul 14 '18 at 21:03
3
@Cleb: you mean you have complete filenames in strings and those files exist on disk? Then use the zf.write() method to add the data from those files to the ZipFile object. – 
Martijn Pieters
♦
 Jul 14 '18 at 22:42
Thanks, that's indeed what I ended up with (also using this answer to get only the files and avoid the entire directory structure). – 
Cleb
 Jul 14 '18 at 23:07
1
@MartijnPieters I tried your piece of code and I generate an archive but which seems invalid. 7zip for exemple, is telling me that the file cannot be opened as an archive. Do you have any idea about that? – 
Alexandre D.
 Dec 4 '19 at 17:21 
@AlexandreD.: sorry, I don't know how else you treated your binary data; this answer deals specifically with keeping the zipfile object in memory, not on disk. – 
Martijn Pieters
♦
 Dec 4 '19 at 17:37
Does the memory free up after send_file function is executed or do we need to do something for that?@MartijnPieters – 
Aniket Bote
 Jul 13 '21 at 7:58 
@AniketBote: if your function created the memory_file and didn't do anything else than pass it to send_file(), it'll be freed once send_file() completes. – 
Martijn Pieters
♦
 Jul 16 '21 at 20:13
Add a comment
