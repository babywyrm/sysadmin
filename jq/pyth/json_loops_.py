
#######################
#######################  

def replace_recurse(it):
    if isinstance(it, list):
        return [
            replace_recurse(entry) if entry.get('type', 'A') == 'A' else entry
            for entry in it
        ]
    if isinstance(it, dict):
        return {
            k: (v + '_001' if k.startswith('Id') else replace_recurse(v))
            for k, v in it.items()
        }
    return it
  
#######################
#######################  
  
  The straight forward way:

for obj in json:
    if obj['id'] == 2:
        obj['name'] = 'something'
Objects are mutable, so you're directly mutating the object here. This is the simplest way. The typical Javascript equivalent would be:

json.forEach(obj => {
    if (obj.id == 2) {
        obj.name = 'something';
    }
});
The slightly more condensed version:

for obj in (o for o in json if o['id'] == 2):
    obj['name'] = 'something'
This inlines a generator expression which pre-filters the objects to loop over. Alternatively:

for obj in filter(lambda o: o['id'] == 2, json):
    obj['name'] = 'something'
Somewhat equivalent to:

json.filter(o => o.id == 2).forEach(obj => obj.name = 'something')
The even more condensed version:

json = [{**obj, 'name': 'something' if obj['id'] == 2 else obj['name']} for obj in json]
This is a list comprehension which builds a new object and new list, somewhat equivalent to:

json = json.map(o => ({...obj, name: obj.id == 2 ? 'something' : obj.name}))
You decide what you find most readable…

#######################
#######################

#!/usr/bin/env python3

import json

with open('ex.json') as json_file:
    data = json.load(json_file)

    for path in data['paths']:
        for method in data['paths'][path]:
                if data['paths'][path][method]['responses']['x-amazon-apigateway-integration']['uri'].find("test123.elb.us-east-1.amazonaws.com") > 0:
                    data['paths'][path][method]['responses']['x-amazon-apigateway-integration']['responses']['connectionId'] = 'xed763'

    print(json.dumps(data, indent=4))
    
#######################
#######################

def nested_replace( structure, original, new ):
    if type(structure) == list:
        return [nested_replace( item, original, new) for item in structure]

    if type(structure) == dict:
        return {key : nested_replace(value, original, new)
                     for key, value in structure.items() }

    if structure == original:
        return new
    else:
        return structure

d = [ 'replace', {'key1': 'replace', 'key2': ['replace', 'don\'t replace'] } ]
new_d = nested_replace(d, 'replace', 'now replaced')
print(new_d)
['now replaced', {'key1': 'now replaced', 'key2': ['now replaced', "don't replace"]}]
    
#######################
#######################    
    
import json    
def fixup(self, a_dict:dict, k:str, subst_dict:dict) -> dict:
"""
function inspired by another answers linked below
""" 
    for key in a_dict.keys():
        if key == k:
            for s_k, s_v in subst_dict.items():
                a_dict[key] = a_dict[key].replace("{{"+s_k+"}}",s_v)
        elif type(a_dict[key]) is dict:
            fixup(a_dict[key], k, subst_dict)
# ...
file_path = "my/file/path"
if path.exists(file_path):
   with open(file_path, 'rt') as f:
   json_dict = json.load(f)
   fixup(json_dict ["json_file_content"],"key_to_find",json_dict ["properties"])
   print(json_dict) # json with variables resolved
else:
   print("file not found")    

######################################
######################################

https://stackoverflow.com/questions/53077503/how-to-find-and-replace-a-part-of-a-value-in-json-file
    ########
    ########

How to find and replace a part of a value in json file
Asked 3 years, 8 months ago
Modified 2 months ago
Viewed 54k times

Report this ad

14


3
I have a json file that I am using as a Dictionary in python. The json file is really long with 10k+ records. I need to replace the $home part in the "iscategorical" with the value of "id". After making the changes, I want to save this file so that I can use it again as a dictionary. Thank you for the help. Here is a sample:

{
"maps": [
    {
        "id": "xyzp",
        "iscategorical": "/u/$home/app/home"
    },
    {
        "id": "trtn",
        "iscategorical": "/u/app/$home/user"
    }
]}
python
json
python-3.x
Share
Follow
asked Oct 31, 2018 at 6:28
user avatar
Mona
26311 gold badge22 silver badges1010 bronze badges
Does the "id": always precede the "iscategorical": key? – 
tripleee
 Oct 31, 2018 at 6:44
When you say that you are using the given json file as Dictionary, seems to me that it loads without issues. If so, you should be able to travel the list of dictionaries, perform the substitution, and redump it to file. Let me see if I can write a solution for this. – 
sal
 Oct 31, 2018 at 6:53
@tripleee the "id" doesn't always preceded the "iscategorical" key. There could be other keys in between. – 
Mona
 Oct 31, 2018 at 16:10
Add a comment
4 Answers
Sorted by:

Highest score (default)

24

I am understanding that you are able to load the file successfully, and all you want to do is replace the strings and save the structure to file again.

For this, we can traverse the list of dictionaries in the data, and modify the value of item['iscategorical'] by replacing $home with the value of item['id'].

We can then dump the modified structure back to (a new) json file.

import json
with open('data.json') as f:
    data = json.load(f)

for item in data['maps']:
    item['iscategorical'] = item['iscategorical'].replace('$home', item['id'])

with open('new_data.json', 'w') as f:
    json.dump(data, f)
Share
Follow
answered Oct 31, 2018 at 7:09
user avatar
sal
3,39511 gold badge99 silver badges2121 bronze badges
2
This worked nicely but I had to put a try and except. Thanks for the help! – 
Mona
 Nov 1, 2018 at 6:32
Glad to help. Cheers! – 
sal
 Nov 1, 2018 at 15:00
Add a comment

Report this ad

5

Your question seems similar to - Parsing values from a JSON file? . However for your case below snippet should work.

import json

with open('idata.json') as infile:
  data = json.load(infile)

for elem in data["maps"]:
  elem['iscategorical']=elem['iscategorical'].replace('$home',elem['id'])

with open('odata.json', 'w') as outfile:
    json.dump(data, outfile)
Share
Follow
edited Oct 31, 2018 at 7:16
answered Oct 31, 2018 at 7:10
user avatar
Jai
14199 bronze badges
Add a comment

2

If it's a file, one thing you can do is load the file in and read line by line.

for everyline, you can use regex to find and replace. Then you can either overwrite the file or write onto a new file.

For example,

line.replace('$home', 'id')
Alternatively, you can load the json python in and convert it into a string. Then replace the text using the regex. Finally, converts back to Python dictionary using json.load(). However, 10k line is too long. I think reading a file, line-by-line, would be a better solutions.

EDIT: Here is the code sample.

from tempfile import mkstemp
from shutil import move
from os import fdopen, remove

def replace(file_path, pattern, subst):
    #Create temp file
    fh, abs_path = mkstemp()
    with fdopen(fh,'w') as new_file:
        with open(file_path) as old_file:
            for line in old_file:
                new_file.write(line.replace(pattern, subst))
    #Remove original file
    remove(file_path)
    #Move new file
    move(abs_path, file_path)

replace('./text.txt', '$home', 'id')
Share
Follow
edited Oct 31, 2018 at 6:58
answered Oct 31, 2018 at 6:41
user avatar
NgoCuong
1,76911 gold badge1010 silver badges88 bronze badges
Add a comment

Report this ad

0

"The JSON file is really long with 10k+ records" -Try this way it should help for large files.

input.json
{"maps":[{"id":"xyzp","iscategorical":"/u/$home/app/home"},{"id":"trtn","iscategorical":"/u/app/$home/user"}]}
import json
with open('input.json') as f:
    data = json.load(f)
my_list = []

def get_some_data():
    for item in data['maps']:
        yield(item['id'], item['iscategorical'])

for id, iscat in get_some_data():
    temp_dict = {}
    temp_dict['id'] = id
    temp_dict['iscategorical'] = iscat.replace('$home', id)
    my_list.append(temp_dict)

maps_dict = {}
maps_dict['maps'] = my_list
with open('output.json', 'w') as f:
    json.dump(maps_dict, f)
output.json:
{"maps": [{"id": "xyzp", "iscategorical": "/u/**xyzp**/app/home"}, {"id": "trtn", "iscategorical": "/u/app/**trtn**/user"}]}
