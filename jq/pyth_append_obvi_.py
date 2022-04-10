1. How to append JSON to file in Python

In Python, appending JSON to a file consists of the following steps:

    Read the JSON in Python dict or list object.
    Append the JSON to dict (or list) object by modifying it.
    Write the updated dict (or list) object into the original file.

2. Python program to append to a JSON file

The users.json file has a list of 2 users. We will append a third user into it.

users.json
[
    {
        "Name": "Person_1",
        "Age": 11,
        "Email": "11@gmail.com"
    },
    {
        "Name": "Person_2",
        "Age": 22,
        "Email": "22@gmail.com"
    }
]

Appending to the File
import json
from os import path
 
filename = 'c:/temp/users.json'
listObj = []
 
# Check if file exists
if path.isfile(filename) is False:
  raise Exception("File not found")
 
# Read JSON file
with open(filename) as fp:
  listObj = json.load(fp)
 
# Verify existing list
print(listObj)

print(type(listObj))
 
listObj.append({
  "Name": "Person_3",
  "Age": 33,
  "Email": "33@gmail.com"
})
 
# Verify updated list
print(listObj)
 
with open(filename, 'w') as json_file:
    json.dump(listObj, json_file, 
                        indent=4,  
                        separators=(',',': '))
 
print('Successfully appended to the JSON file')

The updated JSON file is:

users.json
[
    {
        "Name": "Person_1",
        "Age": 11,
        "Email": "11@gmail.com"
    },
    {
        "Name": "Person_2",
        "Age": 22,
        "Email": "22@gmail.com"
    },
    {
        "Name": "Person_3",
        "Age": 33,
        "Email": "33@gmail.com"
    }
]

3. AttributeError: ‘dict’ object has no attribute ‘append’

We may get this error if the JSON object read from the json.load() method is of type dict.

The above example reads a JSON list [...] so the loaded object is of type list. If you are reading a file that has JSON object {...} then the loaded object will be of type dictionary and the above code will give AttributeError.

{'Name': 'Person_1', 'Age': 11, 'Email': '11@gmail.com'}
<class 'dict'>
Traceback (most recent call last):
  File "C:\temp\temp.py", line 20, in <module>
    listObj.append({
AttributeError: 'dict' object has no attribute 'append'
