
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
