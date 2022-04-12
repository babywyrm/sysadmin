Using JQ in python like using it through cli
Asked 1 year, 4 months ago
Modified 1 year, 4 months ago
Viewed 2k times
Report this ad
2
1

I have some cli commands that run through an api and then pass to jq like so

cat json.txt | jq '.members[] | [.name] 

But now i am trying to do some logic in python and then pipe it out to jq, but i can't figure out how to do it even in a similar way to the above.

I read through the documentation for jq module in python, but i just can't get it to work, can someone please help me out with this?
python
jq
Share
Improve this question
Follow
edited Nov 30, 2020 at 19:21
user avatar
flaxel
3,29144 gold badges1313 silver badges2626 bronze badges
asked Nov 30, 2020 at 13:50
user avatar
Stanley LEsniak
4755 bronze badges

    Why should your Python script have to know about that? Either pipe the output to JQ yourself (python3 whatever.py | jq '...') or just write the logic you'd apply using JQ in the Python script. – 
    jonrsharpe
    Nov 30, 2020 at 13:51 

You know what i didn't even think about doing it like that, good idea. But i would also like to learn how to do it within python if possible? – 
Stanley LEsniak
Nov 30, 2020 at 13:53
It is possible, you can use e.g. subprocess. There are quite a few posts about that already. – 
jonrsharpe
Nov 30, 2020 at 13:55

    There are at least two python wrappers for jq. Please specify which you've tried and what you've tried. – 
    peak
    Nov 30, 2020 at 16:36
    @peak i have tried the pyjq module and tried this but that just kept erroring out pyjq.all('.members[] | {"name": .name}' and then i also tried jmespath and did the following but that just returned none, jmespath.search("members[*]", data) – 
    Stanley LEsniak
    Nov 30, 2020 at 16:55

Show 1 more comment
2 Answers
Sorted by:
6

After: pip3 install pyjq

the following runs without problems:

import pyjq
print(pyjq.all( ".members[] | [.name]", {"members": [ {"name": "foo"} ]} ))

Output:

[['foo']]

Documentation

The documentation for pyjq is at https://pypi.org/project/pyjq/

Note in particular the url optional argument.
Share
Improve this answer
Follow
answered Nov 30, 2020 at 18:04
user avatar
peak
86.1k1414 gold badges119119 silver badges144144 bronze badges

    why would I use this rather than pypi.org/project/jq – 
    MrR
    Jan 25, 2021 at 0:04

Add a comment
-1

Using subprocess module:

import subprocess

cmd=["cat", "json.txt", "|", "jq", "'.members[]", "|", "[.name]"]
result = subprocess.check_output(cmd, shell=True)

print(result)

Share
Improve this answer
Follow
answered Nov 30, 2020 at 13:57
user avatar
programmer365
13.5k33 gold badges1111 silver badges3030 bronze badges

    appreciate your response, i tested that out and it works fine, but i wanted to do the process within python like using the jq module, if anyone has any experience with using that module. – 
    Stanley LEsniak
    Nov 30, 2020 at 14:24

