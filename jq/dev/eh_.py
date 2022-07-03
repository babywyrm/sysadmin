import json

#########
## somehow I broke this
#########
#########

file1 = 'pets.json'
file2 = 'slim.json'

########################
########################

# input file for d1
with open(file2, 'r', encoding='utf-8') as f:    
    d1 = json.load(f)

# input file for d2
with open(file1, 'r', encoding='utf-8') as f:
    d2 = json.load(f)

# output file
with open("combined.json", 'w', ) as f:
    # update values in d2 with values from d1
    for key in d2:
        try:
            # raise an KeyError if d1 doesn't have the key
            d2[key] = d1[key]
      ##elif: 
      ##      d2[key].append(d1[key]) 
        except KeyError:
            pass
   
 
    json.dump(d2, f, ensure_ascii=False, indent=4)

print(d2)

########################
########################
