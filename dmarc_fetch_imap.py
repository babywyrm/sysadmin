#!/usr/bin/python3

#
#
#############################
import imaplib
import email
import os
import zipfile

##################################################
##################################################

server = 'mail.feanor.net'
user = 'administrator@feanor.net'
password = 'fuckingSLU4696969'
outputdir = '/root/DMARC_FETCH/OUTPUT'
subject = 'Report domain:' #subject line of the emails you want to download attachments from

# connects to email client through IMAP
def connect(server, user, password):
    m = imaplib.IMAP4_SSL(server)
    m.login(user, password)
    m.select()
    return m

# downloads attachment for an email id, which is a unique identifier for an
# email, which is obtained through the msg object in imaplib, see below 
# subjectQuery function. 'emailid' is a variable in the msg object class.


def downloaAttachmentsInEmail(m, emailid, outputdir):
    resp, data = m.fetch(emailid, "(BODY.PEEK[])")
    email_body = data[0][1]
    mail = email.message_from_bytes(email_body)
    if mail.get_content_maintype() != 'multipart':
        return
    for part in mail.walk():
        if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
            open(outputdir + '/' + part.get_filename(), 'wb').write(part.get_payload(decode=True))

# download attachments from all emails with a specified subject line
# as touched upon above, a search query is executed with a subject filter,
# a list of msg objects are returned in msgs, and then looped through to 
# obtain the emailid variable, which is then passed through to the above 
# downloadAttachmentsinEmail function

def subjectQuery(subject):
    m = connect(server, user, password)
    m.select("Inbox")
    typ, msgs = m.search(None, '(SUBJECT "' + subject + '")')
    msgs = msgs[0].split()
    for emailid in msgs:
        downloaAttachmentsInEmail(m, emailid, outputdir)

subjectQuery(subject)

###########################################

dir_name = '/root/DMARC_FETCH/OUTPUT'
extension = ".zip"

os.chdir(dir_name) # change directory from working dir to dir with files

for item in os.listdir(dir_name): # loop through items in dir
    if item.endswith(extension): # check for ".zip" extension
        file_name = os.path.abspath(item) # get full path of files
        zip_ref = zipfile.ZipFile(file_name) # create zipfile object
        zip_ref.extractall(dir_name) # extract file to dir
        zip_ref.close() # close file

##        os.remove(file_name) # delete zipped file


############################################
