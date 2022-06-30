import requests, json
open('output.txt', 'w').close()
with open('towns.txt') as f:
    lines = f.readlines()
    length = len(lines)
    i = 0
    while i < length:
        for j in range(i, length):
            begin = lines[i].strip('\n')
            end = lines[j].strip('\n')
            headers = {'content-type': 'application/x-www-form-urlencoded'}
            payload = {'from': begin, 'to': end, 'class': 1}
            r = requests.post("http://taxi-avrora-krim.ru/php/upload-price.php", data=payload, headers=headers, verify=False)
            #print(lines[i].rstrip('\n'), end=',')
            #print(lines[j].rstrip('\n'), end=',')
            #data = json.loads(r.text)
            #print(data['price'])
            with open('output.txt', 'a') as of:
                data = json.loads(r.text)
                t_output = lines[i].rstrip('\n')
                n_output = lines[j].rstrip('\n')
                p_output = data['price']
                print(f"{t_output}, {n_output}, {p_output}", file=of)

        i += 1

################
################

import random as random
g = int(input("How many enemies are there?: "))
gengar_attack = [1, 2, 3]
HP = 35
while HP > 0 and g != 0:
    gac = random.random()
    pac = random.random()
    if gac > 0.5:
        ga = random.choice(gengar_attack)
        HP = HP - ga
        print("Gengar hits Pikachu and deals " + str(ga) + " damage!")
        pac = random.random()
        if pac > 0.6:
            print("Pikachu hits Gengar and defeats him!")
            g = g - 1
    elif pac > 0.6:
        print("Pikachu hits Gengar and defeats him!")
        g = g - 1
if HP <= 0:
    print("Oh no! Pikachu fainted!")
if g == 0:
    print("Pikachu defeated all the Gengars!")
    print("He has " + str(HP) + " HP left!")
    

################
################    

### CREATING LOOP TO GO THROUGH PAGES ###

results = [] #variable to store loop results
for i in range (4): #goes through 4 pages (0-3)
    url = 'https://clutch.co/it-services/msp?page={}'.format(i) #passes the number inside range through the {}
    session = HTMLSession() 
    resp = session.get(url)
    resp.html.render() #RENDERS INCASE ITS JAVASCRIPT SITE
    soup = BeautifulSoup(resp.html.html, features='lxml')
    print(url) #shows what page you are on as it is looping
    agencies = soup.find_all(class_='company-name')
    for a in agencies:
        text = (a.text)
        results.append(text)

print(results)

################
################

I have tried a lot to avoid these nested for loops, but no success.

Avoiding nested for loops

Returns values from a for loop in python

import requests
import json

r = requests.get('https://api.coinmarketcap.com/v1/ticker/')
j = r.json()


for item in j:
    item['id']
    n = item['id']
    url = 'https://api.coinmarketcap.com/v1/ticker/%s' %n
    req = requests.get(url)
    js = req.json()
    for cool in js:
        print n
        print cool['rank']
Please let me know if more information is needed.

python
loops
for-loop
nested
Share
Follow
edited Jun 9, 2017 at 16:12
user avatar
mechanical_meat
156k2424 gold badges218218 silver badges212212 bronze badges
asked Jun 9, 2017 at 16:07
user avatar
Master
311 bronze badge
3
Sometimes you need nested for loops. This looks like one of those times. – 
mechanical_meat
 Jun 9, 2017 at 16:13
I am getting a lot of data and having nested for loop is too time consuming :( I understand your point though. Thank you for the feedback. – 
Master
 Jun 9, 2017 at 16:20
To avoid writing a nested loop, you could create a function to parse js that contains the inner for loop. Note that this would still technically contain nested loops, but your code will at least appear flatter. – 
Jared Goguen
 Jun 9, 2017 at 16:20 
2
@Master The reason of getting rid of nested for-loop is usually to make it more readable or easier to maintain. It will seldom improve speed. – 
kennytm
 Jun 9, 2017 at 16:21
@Master Are you requesting the same url repeatedly? It looks like the only way to reduce complexity/time would be to reduce the number of requests. If each request is unique, I'm not sure how you could do that. – 
Jared Goguen
 Jun 9, 2017 at 16:21 
Show 1 more comment
2 Answers
Sorted by:

Highest score (default)

1

Question
I have too many loops in loops and want a python way of cleaning it up

Answer
Yes, there is a python way of cleaning up loops-in-loops to make it look better but there will still be loops-in-loops under-the-covers.

import requests
import json

r = requests.get('https://api.coinmarketcap.com/v1/ticker/')
j = r.json()

id_list = [item['id'] for item in j]

for n in id_list:
    url = 'https://api.coinmarketcap.com/v1/ticker/%s' %n
    req = requests.get(url)
    js = req.json()
    print "\n".join([ n+"\n"+item['rank'] for item in js ])
Insight from running this
After running this specific code, I realize that your are actually first retrieving the list of tickers in order of rank using

r = requests.get('https://api.coinmarketcap.com/v1/ticker/')
and then using

url = 'https://api.coinmarketcap.com/v1/ticker/%s' %n
to get the rank.

So long as the https://api.coinmarketcap.com/v1/ticker/ continues to return the items in order of rank you could simplify your code like so

import requests
import json

r = requests.get('https://api.coinmarketcap.com/v1/ticker/')
j = r.json()

id_list = [item['id'] for item in j]

result = zip(id_list,range(1,len(id_list)+1) )

for item in result :
print item[0]
print item[1]
                                                                              
                      
                                                                              
################
################   

