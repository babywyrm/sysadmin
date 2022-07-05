
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
