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


########################################
########################################

Working with JSON data in Python
March 30, 2021 by Aveek Das
ApexSQL pricing
In this article, I am going to write about the various ways we can work with JSON data in Python. JSON stands for Java Script Object Notation and has become one of the most important data formats to store and transfer data across various systems. This is due to its easy-to-understand structure and also because it is very lightweight. You can easily write simple and nested data structures using JSON and it can be read by programs as well. In my opinion, JSON is much more human-readable as compared to XML, although both are used to store and transfer data. In modern web applications, by default JSON is being used to transfer information.

Understanding the JSON data structure
First, let’s begin by understanding how JSON looks and how to deal with it.

A sample JSON structure

Figure 1 – A sample JSON structure

In the figure above you can see a sample data structure that is represented in JSON. The sample is a representation of this article. The top-level node of the sample is data under which a list is created by using the [] braces. Inside the [] braces, you can have multiple JSON nodes or strings as required. To keep things simple, I have only used one item on the list. The next items inside the list are the type, id, attributes, and author in regards to the article submitted. The attributes and author are nested objects that can be further expanded to title, description, created, updated and id, name respectively.

By having a quick glance at the overall data structure it is easy to determine the relationships between the article and the author and as such very easy to understand by both humans and machines.

Concept of serialization and deserialization of the JSON
So far, we have understood how JSON looks like and how can we interpret a JSON data structure. Now, we should understand how can we use this data in python and do operations as required. While dealing with JSON, we often come across two terms known as Serialization and Deserialization of data. The basic format of writing JSON is just a string data type that contains data in key-value pairs. In order for the machine to understand this string, it needs to be converted into an object which can be then consumed by the interpreter. The process of converting a string JSON into a python object is called Deserialization and the process of converting a python object back to JSON is called Serialization.

Let’s now understand and try to do this using python.

https://gist.github.com/aveek22/4dffd4379d33104381ffca5fe10b6cba

Console output from the above snippet 

Figure 2 – Console output from the above snippet

If you see the code above, you will notice that I have imported the JSON module into the script. This is the default module provided by Python to deal and work with JSON data. You can read more about this library from the official documentation. There are four basic methods in this library as follows:

json.dump – This method is used to serialize a python object from the memory into a JSON formatted stream that can be written to a file
json.dumps – This is used to serialize the python objects in the memory to a string that is in the JSON format. The difference between both of these is that in the former, a stream of data is produced while the latter creates a string data type
json.load – You can use this method to load data from a JSON file that exists on the file system. It parses the file and then deserializes the data into a python object
json.loads – This is similar to json.load, the only difference is it can read a string that contains data in the JSON format
From my experience, I can say that you will be using the json.loads and json.dumps quite more frequently as compared to their streaming data counterparts. An important point worth mentioning is that the JSON library works only with the built-in python data types like string, integer, list, dictionaries, etc. In case you would want to work with a custom data type, then we would first need to convert the custom datatype to a python dictionary object and then serialize it to JSON data format.

Using Pandas to read JSON data
So far, we have learned about working with the JSON library in python to work with JSON data types. Now let us also take a look around the Pandas library in python and how to read and write data using Pandas. As you might be aware, Pandas is extensively used in the field of data science to analyze existing data and discover insights from the underlying data.

https://gist.github.com/aveek22/c7fc11b226504420c6ec980534a94ba5

If you run the code above, you will get the data loaded into a Pandas dataframe.

JSON Data loaded as Pandas Dataframe 
Figure 3 – JSON Data loaded as Pandas Dataframe

As you can see in the figure above, the read_json() method in Pandas reads the JSON from the string or a file and then converts it into a Pandas dataframe. This method also accepts several other parameters of which I will be discussing the most important ones in the following section.

path – The first parameter accepted by this method is the path or the name of the JSON formatted string. Instead of specifying a variable name, you can directly provide the JSON string as an argument and it will still work fine
orient – This parameter is used to define the format in which the JSON string is available. The most common values accepted for this parameter are records, index, columns, values, etc
typ – This defines the type of data that should be returned by the method. By default, it returns a dataframe, but can also be set to return a series instead of a dataframe
So far, we have seen how to read JSON formatted data using Pandas. Now, let us also understand how to export data from Pandas dataframe back to JSON. Basically, we are going to serialize a Pandas dataframe to a JSON string.

https://gist.github.com/aveek22/cd96bcef996d45db7c03059918b7bc69

Converting Pandas DataFrame to JSON
Figure 4 – Converting Pandas DataFrame to JSON

As you can see in the figure above, when we execute the above snippet, the Pandas dataframe gets converted into a JSON string which is then printed to the console. This is done with the to_json() method available in Pandas that help us to convert existing data to JSON string. The important parameters accepted by this method are discussed as follows.

path – This parameter is somewhat different from the one that we have seen in the previous section. This is an optional parameter in which it will write the JSON data after serializing it
orient – This is used to define the format in which the data has to be exported. There are several values for this parameter like records, split, index, columns, values etc. By default, if the method is passed on to a dataframe, the columns are selected
You can follow the official documentation from Pandas to learn more about handling JSON data with Pandas.

Conclusion
In this article, we have seen what JSON is and how to work with JSON data in python using various libraries. JSON is a rich data structure and can be used in almost every modern application in the recent world. Also, it is easily understood and read by humans as well as machines and as a result, has gained a lot of popularity with the developers. JSON data can be structured, semi-structured, or completely unstructured. It is also used in the responses generated by the REST APIs and represents objects in key-value pairs just like the python dictionary object.


