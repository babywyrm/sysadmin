###########
#########################

https://stackoverflow.com/questions/39070919/updating-a-deep-key-in-a-nested-json-file

#########################
###########

updating a deep key in a Nested JSON file
Asked 5 years, 11 months ago
Modified 5 years, 11 months ago
Viewed 4k times

Report this ad

0


I have a json file which looks like this:

{
    "email": "abctest@xxx.com", 
    "firstName": "name01", 
    "surname": "Optional"
    "layer01": {
        "key1": "value1", 
        "key2": "value2", 
        "key3": "value3", 
        "key4": "value4", 
        "layer02": {
            "key1": "value1", 
            "key2": "value2"
        }, 
        "layer03": [
            {
                "inner_key01": "inner value01"
            }, 
            {
                "inner_key02": "inner_value02"
            }
        ]
    }, 
    "surname": "Required only$uid"
}
am expecting a update request as:

{
                "email": "XYZTEST@gmail.com",
                "firstName": "firstName",
                "layer01.key3": "newvalue03",
                "layer01.layer02.key1": "newvalue01"
            },
the deeper keys are separated using "."

am using python2.7. Can anyone advice me on this.. am really stuck at this!!

this is what i was working with:

def updateTemplate(self,templatename, data):
    template= self.getTemplatedata(templatename) # gets the python object with the data from original file

    for ref in data:
        k= ref
        keys= ref.split(".")
        temp= template
        if len(keys)>1:
            temp= template[keys[0]]
            for i in range(1,lens(keys)-1):
                print keys[i]
                if type(temp) is dict:
                    temp =temp[keys[i]]



            temp[keys[len(keys)-1]]= data[k]
            print temp

            template.update(temp)        
        else:
            template[k]= data[k]   
    print template  
update added a whole new key in the template object. I need to update the key in last temp to template object

the template object displayed this:

{   u'email': u'abctest@xxx.com',
    u'firstName': u'Valid AU$uid',
    u'key1': u'value1',
    u'key2': u'value2',
    u'key3': u'value03',
    u'key4': u'value4',
    u'layer01': {   u'key1': u'value1',
                    u'key2': u'value2',
                    u'key3': u'value03',
                    u'key4': u'value4',
                    u'layer02': {   u'key1': u'value01', u'key2': u'value2'},
                    u'layer03': [   {   u'inner_key01': u'inner value01'},
                                    {   u'inner_key02': u'inner_value02'}]},
    u'layer02': {   u'key1': u'value01', u'key2': u'value2'},
    u'layer03': [   {   u'inner_key01': u'inner value01'},
                    {   u'inner_key02': u'inner_value02'}],
    u'surname': u'Required only$uid'}
python
json
Share
Follow
edited Aug 23, 2016 at 7:12
user avatar
Julien
12.9k44 gold badges2727 silver badges5151 bronze badges
asked Aug 22, 2016 at 3:16
user avatar
Vineeth
311 silver badge77 bronze badges
Show your attempts please. – 
Julien
 Aug 22, 2016 at 3:20
i have edited the question with my code appended at the end,.. please look into it – 
Vineeth
 Aug 22, 2016 at 3:28
It seems to work for me. What's not working for you? You say "update added a whole new key in the template object" but this isn't possible with Python dictionaries: keys are unique. – 
Cameron Lee
 Aug 22, 2016 at 4:01
i have posted the output also now.... its adding new nested keys to my object – 
Vineeth
 Aug 22, 2016 at 4:46 
@JulienBernu Can u help me with this?... because.. at the end of the iteration what i have is temp with the deepest dictionary details only.. if i pass that to the template object in update, it will add it is unique in the top layer.. – 
Vineeth
 Aug 23, 2016 at 7:09
Show 1 more comment
2 Answers
Sorted by:

Highest score (default)

0

Your algorithm is really close but there's a few things in it that complicate things unnecessarily. This makes it easy to miss the key line that's causing the problem:

template.update(temp) 
temp is the child-most dictionary of the template but here you set the original template to have all it's children too. Comment this line out and it should work.

Some of the things that I cleaned up to make this line easier to find:

Don't hardcode the case where there's only one element in the keys list. The loop can handle it.
In Python, there's a nice shorthand for keys[len(keys)-1]: keys[-1]. See Negative index to Python list
Instead of using enumerate and checking if the type of temp is a dict, simply don't loop over the last key (this could change the behaviour a bit for other input)
Using pprint. It pretty prints things like lists and dictionaries.
Put together, a simplified version looks like this:

import pprint

def updateTemplate(self, templatename, data):
    template = self.getTemplatedata(templatename) # gets the python object with the data from original file

    for ref in data:
        keys = ref.split(".")
        temp = template
        for key_part in keys[:-1]:
            temp = temp[key_part]
        temp[keys[-1]] = data[ref] # Because dictionaries are mutable, this updates template too

    pprint.pprint(template)  
Hope this helps.

Share
Follow
edited May 23, 2017 at 11:47
user avatar
CommunityBot
111 silver badge
answered Aug 25, 2016 at 4:59
user avatar
Cameron Lee
81388 silver badges1111 bronze badges
Thanks for the solution. I was able to solve this using Pydash. very simple with that.!! – 
Vineeth
 Aug 26, 2016 at 5:34
Add a comment

Report this ad

0

As much as I'd like to help you out, I find your code confusing, but I'll do my best. Here it goes

For starters, by temp= template do you mean to do temp= copy.deepcopy(template)? Remember to import copy Reference

I get that template is a dictionary, but what do you want to achieve by referencing template to temp, tweaking temp then adding

template.update(temp)

temp to template which in fact temp is a reference to template?

How about we scrap the code and start off fresh.

i.e. Input is

{
    "email": "XYZTEST@gmail.com",
    "firstName": "firstName",
    "layer01.key3": "newvalue03",
    "layer01.layer02.key1": "newvalue01"
}
Existing data is:

{
    "email": "abctest@xxx.com", 
    "firstName": "name01", 
    "surname": "Optional"
    "layer01": {
        "key1": "value1", 
        "key2": "value2", 
        "key3": "value3", 
        "key4": "value4", 
        "layer02": {
            "key1": "value1", 
            "key2": "value2"
        }, 
        "layer03": [
            {
                "inner_key01": "inner value01"
            }, 
            {
                "inner_key02": "inner_value02"
            }
        ]
    }, 
    "surname": "Required only$uid"
}
Expected Output:

{
    "email": "XYZTEST@gmail.com", 
    "firstName": "firstName", 
    "surname": "Optional"
    "layer01": {
        "key1": "value1", 
        "key2": "value2", 
        "key3": "newvalue03", 
        "key4": "value4", 
        "layer02": {
            "key1": "newvalue01", 
            "key2": "value2"
        }, 
        "layer03": [
            {
                "inner_key01": "inner value01"
            }, 
            {
                "inner_key02": "inner_value02"
            }
        ]
    }, 
    "surname": "Required only$uid"
}
Kindly confirm if this is the result your expecting, so I can help you with your brainstorming.

Share
Follow
answered Aug 23, 2016 at 7:59
user avatar
Eduard
63411 gold badge88 silver badges2424 bronze badges
This is exactly what i was expecting. – 
Vineeth
 Aug 26, 2016 at 5:32
was doing some R&D on working with Dictionaries using python. Came across 'pydash'. it actually solved my problem. With it i can access the deep nodes directly by "." eg: layer01.layer02.key...... – 
Vineeth
 Aug 26, 2016 at 5:33
Add a comment
