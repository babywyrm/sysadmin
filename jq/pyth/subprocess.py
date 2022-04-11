
https://stackoverflow.com/questions/38220370/is-there-a-way-to-execute-jq-from-python
  
###############################
###############################

The sh module makes it easy invoke a jq subprocess from python. e.g.

import sh
cmd = sh.jq('-M', '{Name:.name, address:.address[0][1].street}', 'filename.json')
print "cmd returned >>%s<<" % cmd.stdout

Share
Improve this answer
Follow
answered Aug 28, 2017 at 3:14
user avatar
jq170727
10.9k33 gold badges3838 silver badges5252 bronze badges

    Furthermore, to run jq on data in a string: print(jq("-M", ".", _in='{ "a": 3 }').stdout.decode()) (That's Python 3) – 
    tobych
    May 29, 2019 at 21:50 

    @tobych - that should be sh.jq(...) – 
    peak
    Aug 18, 2020 at 6:00

Add a comment
2

    Can I execute this command from a python script

Yes, using subprocess. Example:

jsonFile = '/path/to/your/filename.json'
jq_cmd = "/bin/jq '{Name:.name, address:.address[0][1].street}' " + jsonFile
jq_proc = subprocess.Popen(jq_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

# read JSON object, convert to string, store as a dictionary

jDict = json.loads(jq_proc.stdout.read())
jq_proc.stdout.close()

    If it can be done, then how would I loop through for the nested array elements in the sample data give above (address[][].street)

It would help to see a JSON data set with a few records. For looping through JSON sets in python with jq, it is easy to get a count of the objects and then iterate. A slight bit of overhead but it makes the code easy to understand.

# count number of JSON records from the root level

jq_cmd = "/bin/jq '. | length' " + jsonFile
jq_proc = subprocess.Popen(jq_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

jObjCount = int(jq_proc.stdout.read())
jq_proc.stdout.close()

# iterate over each root level JSON record

for ix in range(jObjCount):

  jq_cmd = "jq '. | .[" + str(ix) + "]' " + jsonFile 
  jq_proc = subprocess.Popen(jq_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

  # read object, convert to string, store as a python dictionary

  jDict = json.loads(jq_proc.stdout.read())

  # iterate over nested objects within a root level object    
  # as before, count number items but here for each root level JSON object

  jq_cmd = "/bin/jq '. | .[" + str(ix) + "].sub_Item_Key | length' " + jsonFile
  jq_proc = subprocess.Popen(jq_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
  jItemCount = int(jq_proc.stdout.read())
  jq_proc.stdout.close()

  for jx in range(jItemCount):

     jq_cmd = "/bin/jq '. | .[" + str(ix) + "].sub_Item_Key[" + str(jx) + "]' " + jsonFile
     jq_proc = subprocess.Popen(jq_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

     # read JSON item, convert to string, store as a python dictionary

     jItemDict = json.loads(jq_proc.stdout.read())

Enjoy!
Share
Improve this answer
Follow
edited Jul 30, 2016 at 20:10
answered Jul 30, 2016 at 20:03
user avatar
endurogizer
6,30611 gold badge77 silver badges55 bronze badges
Add a comment
1

Yes. Using plumbum.

from plumbum.cmd import jq, cat

(cat["filename.json"] | jq ["{Name:.name, address:.address[0][1].street}"])()

The result of the above command is a JSON object, that can be parsed to a Python object using json.loads.

You might also be interested in jello, which is like jq but uses Python as query language.
Share
Improve this answer
                                                                                                        
##
##
###
