# ppchecker
#
https://github.com/morph3/ppchecker#readme
#
##
##
#
Simple Prototype Pollution Checker tool. 

Executes some basic prototype pollution payloads and checks if the site is vulnerable to prototype pollution. You can also feed urls with parameter and check if the parameters are vulnerable as well.

Everytime this script runs, it starts a browser with puppeter. It starts opening new tabs with urls with the limit of the given concurrency. After the prototype pollution check is completed, tab gets terminated. This approach is not very good on big wordlists as tabs may have issues when loading. Extereme amounts of tabs being opened might occur and therefore a crash might happen. So if you want to feed this tool a big wordlist please take a look at [Additional](https://github.com/morph3/ppchecker/blob/main/README.md#additional) section. Also reachable urls are prefered because of the reason I explained.

# Example Run

[![asciicast](https://asciinema.org/a/425330.svg)](https://asciinema.org/a/425330)

# Example Usages

```
python3 ppchecker.py -l urls.txt -c 30
python3 ppchecker.py -l urls.txt -c 20 -d 
python3 ppchecker.py -u http://ctf.m3.wtf/pplab3.html -c 20
python3 ppchecker.py -u 'https://morph3sec.com/index.html?foo=' -c 20
```


# Additional

If you are going to work on big wordlists I suggest you to use the command below to distribute the load equally.

```
cat urls.txt | xargs -I% -P 50 sh -c 'python3 ppchecker.py -u "%"'
```



##
##
#
Prototype pollution
#
##
##

Exposing the default prototype by calling unsafe recursive functions with untrusted data as input
Prototype pollution: the basics
What is prototype pollution?
Prototype pollution is an injection attack that targets JavaScript runtimes. With prototype pollution, an attacker might control the default values of an object's properties. This allows the attacker to tamper with the logic of the application and can also lead to denial of service or, in extreme cases, remote code execution.

After reading the above definition, there are probably at least a dozen questions that spring to mind. What does it actually mean to “override object attributes at runtime”? How can it affect the security of my application? And, most importantly, how do I protect my code against this attack?

About this lesson
Prototype pollution can be complex, so we will walk through it in three steps.

You will use prototype pollution to compromise a vulnerable API
You will learn more about JavaScript prototypes and how prototype pollution works
And, you will learn how to fix and prevent prototype pollution in your applications

FUN FACT
Not an isolated case
Prototype pollution vulnerabilities have been found and fixed in many popular JavaScript libraries, including jQuery, lodash, express, minimist, hoek… and the list goes on. When a prototype pollution vulnerability was discovered in jQuery, jQuery was--at that time--being used in 74% of all websites. Talk about scary!

Prototype pollution in action
Let’s demonstrate how a prototype pollution attack may play out in the real world. A company called startup.io, which we might recognize from the other lessons, finally acquired users for its products. Obliged by .io in its name, startup.io decided to release an API that allows users to manage data the company holds via the app.

Unfortunately, stressed by looming deadlines and chased by ever-demanding stakeholders, startup.io engineers did a bad job of securing their API. They never had time to schedule a meeting with their AppSec team to help with the design and they later ignored all the issues reported by the security scanners. As a result, their API contains many bugs and vulnerabilities--one of which is prototype pollution.

This is obviously bad for startup.io--but good news for us because with it we can compromise their API. Let’s focus on two API endpoints that startup.io exposes:

An HTTP POST on https://api.startup.io/users/:userId that allows updating data for a user with userId
An HTTP GET on https://api.startup.io/users/:userId/role that allows retrieving the security role that a given user is currently assigned to (either admin or user)
Vulnerable API
Let’s try to escalate our privileges to adminhood by tampering with the application logic. Then, let’s try to bring down the whole API with a denial of service attack.

All examples assume we are already authorized, and any authorization headers are omitted for readability. To interact with the API, we will be using an embedded terminal window like the one below.

Let’s examine how the HTTP POST endpoint works by sending a valid request. We read in the docs that the endpoint allows us to change the text in the “about” section that's displayed on our user’s profile page. We are good at sanitizing database code, so we want our “about” section to say “Database sanitization expert”.

Copy and paste the following into the terminal and hit enter:

curl -H "Content-Type: application/json" -X POST -d '{"about": "Database sanitization expert"}' https://api.startup.io/users/1337

We should get a JSON response with the data stored about the user, with the “about” text updated:

{ name: "Robert", surname: "Tables", about: "Database sanitization expert" }

Next, let’s see how the HTTP GET endpoint works by sending another valid request.

Copy and paste the following into the terminal and hit enter:

curl -X GET https://api.startup.io/users/1337/role

We should get back JSON with the default role our user is assigned:

{ role: "user" }

Demo terminal
Hacking #1: naive, failed attempt
Now that we know how the API works, let’s see if we can modify our role and set it to admin. Try setting the role attribute to admin directly via a POST request.

Copy and paste the following into the terminal and hit enter:

curl -H "Content-Type: application/json" -X POST -d '{"role": "admin"}' https://api.startup.io/users/1337 && curl -X GET https://api.startup.io/users/1337/role

We should get the following output:

{ role: "user" }

Alas, this simple approach did not work. The role attribute stubbornly remains set to user. However, our quest to transcend to adminhood is not over yet!

Demo terminal
Hacking #2: privilege escalation with prototype pollution
Earlier, we discovered that prototype pollution might allow us to override any attribute defined on any object in the application. Perhaps the vulnerability could allow us to change the role attribute? Let’s try again--but this time let’s add a magical (for the time being) __proto__ prefix to the attribute we are setting.

Copy and paste the following into the terminal and hit enter:

curl -H "Content-Type: application/json" -X POST -d '{"about": {"__proto__": {"role": "admin"}}}' https://api.startup.io/users/1337 && curl -X GET https://api.startup.io/users/1337/role

And we should get:

{ role: "admin" }

BOOM! We’ve successfully managed to elevate ourselves to adminhood by sending a mysterious payload {"about": {"__proto__": {"role": "admin"}}} to the backend.

But wait, what is this magical __proto__ prefix and why did it work? Don’t worry, we’ll discuss that more in the next section of this lesson. But before we do that, let’s bring this whole buggy API down.

Demo terminal
Hacking #3: bringing down the whole API
In our previous attack, we managed to change the role attribute to whatever we wanted. But wait, aren’t JavaScript functions also stored as attributes on their respective objects? Could we possibly use the same tampering technique to override a function?

Let’s try to override one! What function is likely called by any program written in JavaScript? Well, one of the best candidates is the toString function! Let’s try to override the function with something meaningless, maybe a programmer dad joke?

Copy and paste the following into the terminal and hit enter:

curl -H "Content-Type: application/json" -X POST -d '{"about": {"__proto__": {"toString": "Two bytes meet. The first byte asks: Are you ill? The second byte replies: No, just feeling a bit off."}}}' https://api.startup.io/users/1337

And we should get as an output:

500 Internal Server Error

The API is down. Turns out that we can override a function!

What happened here? We will dive into the code a bit later. For now, we can deduce that we were able to override the toString method, just like we did before with the role attribute. Whenever the JavaScript runtime invokes toString() it expects it to be a method. But, it is no longer a method after our change (it is a dad joke now, i.e. a string literal), so the whole web server crashes, resulting in 500 errors.

Demo terminal
Prototype pollution under the hood
What is a prototype in JavaScript?
To understand why our attacks worked, we need to take a slight detour and explain what JavaScript prototypes are.

When we create an empty object in JavaScript (for example, const obj = {}), the created object already has many attributes and methods defined for it, for instance, the toString method. Have you ever wondered where all these attributes and methods come from? The answer is the prototype.

Many object-oriented languages, for example Java, use classes as blueprints for object creation. Each object belongs to a class, and classes are organized in parent-child hierarchies. When we call the toString method on an object, the language runtime will look for the toString method defined on the class a given object belongs to. If it cannot find such a definition, it will look for it in the parent class, then its parent class, until it hits the top of the class hierarchy.

JavaScript, instead, is a prototype-based object-oriented programming language. Each object is linked to a “prototype”. When we invoke the toString method on an object, JavaScript will first check to see if we explicitly defined the method for the given object. If we haven’t, it will look for its definition on the object’s prototype.

Just a normal JavaScript object
DO THIS
Code:
12
const a = {};
console.log(typeof a.__proto__);
Missing attributes come from the prototype
DO THIS
Code:
12345
const a = {};
a.__proto__.someFunction = function () {
  console.log("Hello from the prototype!")
};
a.someFunction();
The shared default prototype
DO THIS
Code:
123
const a = {};
const b = new Object();
console.log(a.__proto__ === b.__proto__);
Setting attributes on a shared prototype
DO THIS
Code:
1234
const a = {};
const b = new Object();
a.__proto__.x = 1337;
console.log(b.x);
Prototype pollution explained
The bottom line is--if we modify a prototype shared by two or more objects, all objects will reflect this modification! They don’t even have to be in the same scope or otherwise related. And remember, most objects by default share the same prototype--so if we change the prototype of just one of these objects, we can change the behaviour of all of them!

What if a malicious person can change (or “pollute”) a prototype shared by multiple objects? In fact, this is what we did when we compromised startup.io’s API in the previous section. Remember, the payloads we sent to the server were:

{"about": {"__proto__":"{"role": "admin"}}}

{"about": {"__proto__": {"toString": "Two bytes meet. The first byte asks: Are you ill? The second byte replies: No, just feeling a bit off."}}}

We polluted the role and toString attributes of the default shared prototype object by sending a specially crafted HTTP POST request. To see how that attack worked, consider the code of the GET and POST HTTP request handlers:

A prototype pollution attack where a hacker sends a malicious payload to the backend server, and an unsafe merge function recursively merges that payload with a backend object
A prototype pollution attack where a hacker sends a malicious payload to the backend server, and an unsafe merge function recursively merges that payload with a backend object

123456789101112
async function updateUser(userId, requestBody) {
  const userData = await db.loadUserData(userId);
  merge(userData, requestBody);

  log("Saving userData " + userData.toString());
  await db.saveUserData(userId, userData);
  return userData;
}

async function getRole(userId) {

The updateUser method handles the HTTP POST request. The input requestBody is the payload we sent to the server.

Scan your code & stay secure with Snyk - for FREE!
Did you know you can use Snyk for free to verify that your code
doesn't include this or other vulnerabilities?

Prototype pollution mitigation
Solution: Use safe open source libraries when recursively setting object's properties
The merge function that startup.io wrote aimed to update one object with all attributes of another object. As we saw when we toured the code in the last section, the merge function is recursive and merrily merges all properties from its second input--even when it contains untrusted data with dubious keys such as __proto__.

Merging two objects is not the only functionality that can expose the code to a prototype pollution attack—any function which recursively sets nested properties can create an attack vector. Other common examples in the JavaScript ecosystem include: deep cloning (e.g. lodash cloneDeep), setting nested properties (e.g. lodash set), or creating objects by recursively "zipping" properties with values (e.g. lodash zipObjectDeep).

Always be sure to sanitize untrusted input when recursively setting nested properties. Don’t do this yourself! Even the best developers can easily get this wrong. Instead, use a library such as lodash, which is extremely popular and has excellent community support and a track record of promptly fixing security issues.

A prototype pollution mitigation, where a hacker tries to send a malicious input, but a safe merge function is used, preventing the malicious input from affecting the prototype
A prototype pollution mitigation, where a hacker tries to send a malicious input, but a safe merge function is used, preventing the malicious input from affecting the prototype

1234567
async function updateUser(userId, requestBody) {
  const userData = await db.loadUserData(userId);
  merge(userData, requestBody);

  await db.saveUserData(userId, userData);
  return userData;
}
123456789
import safeMerge from 'lodash.merge';

async function updateUser(userId, requestBody) {
  const userData = await db.loadUserData(userId);
  safeMerge(userData, requestBody);

  await db.saveUserData(userId, userData);
  return userData;
}
To decide which libraries to trust, use Snyk Advisor! Snyk Advisor provides information on a given package's popularity, community support, and security. Also, check your open source libraries with vulnerability scanners such as Snyk, which will notify you about all new vulnerabilities discovered in any libraries you are using, and will help you mitigate them easily.


FUN FACT
It is hard to get right
Mitigating prototype pollution attacks is hard. While implementing a recursive merge function, lodash developers made sure a key with the value __proto__ would not be copied from one object to another. Unfortunately, it later turned out that prototype pollution is also possible through other properties, e.g. constructor.prototype (check this fix commit to learn how lodash developers dealt with that issue).

The lesson to learn here is that proper sanitization of user input is extremely hard. Whenever you can, use a battle-tested library to do the work for you.

Solution: Create objects without prototypes: Object.create(null)
Another way to avoid prototype pollution is to consider using the Object.create() method instead of the object literal {} or the object constructor new Object() when creating new objects. This way, we can set the prototype of the created object directly via the first argument passed to Object.create(). If we pass null, the created object will not have a prototype and therefore cannot be polluted.

123456
async function updateUser(userId, requestBody) {
  const userData = await db.loadUserData(userId);
  merge(userData, requestBody);

  await db.saveUserData(userId, userData);
  return userData;
}
12345678
async function updateUser(userId, requestBody) {
  const userData = await db.loadUserData(userId);

  const saveToDatabase = Object.create(null);
  merge(saveToDatabase, userData);
  merge(saveToDatabase, requestBody);

  await db.saveUserData(userId, saveToDatabase);
  return saveToDatabase;
}
Solution: Prevent any changes to the prototype: use Object.freeze()
JavaScript comes with an Object.freeze() method, which we can use to prevent any changes to the attributes of an object. Since the prototype is just an object, we can freeze it, too. We can freeze the default prototype by invoking Object.freeze(Object.prototype), which prevents the default prototype from getting polluted.

Alternatevly you can simply install nopp npm package which freezes all common object prototypes automatically.

1234567
async function updateUser(userId, requestBody) {
  const userData = await db.loadUserData(userId);
  merge(userData, requestBody);

  await db.saveUserData(userId, userData);
  return userData;
}
12345678910
// call once in ‘main.js’ or similar
Object.freeze(Object.prototype);

async function updateUser(userId, requestBody) {
  const userData = await db.loadUserData(userId);
  merge(userData, requestBody);

  await db.saveUserData(userId, userData);
  return userData;
}
How do you mitigate prototype pollution?
To mitigate prototype pollution vulnerabilities in your codebase use popular open-source libraries when you need to recursively set nested properties on an object. Check which libraries to use with Snyk Advisor, and always make sure that the library you choose is free of vulnerabilities with scanners such as Snyk. To harden your code further, use Object.create(null) to avoid using prototypes altogether, or use Object.freeze(Object.prototype) to prevent any changes to the shared prototype.

Keep learning
To learn more about prototype pollution, check out our blog posts:

Read about how our security research team discovered prototype pollution in lodash and minimist
Check out our coverage on prototype pollution findings in jQuery and express
Finally, if you would like to dive deeper into prototype pollution, be sure to read this detailed report on prototype pollution written by Security Researcher, Olivier Arteau. He has found and responsibly disclosed many prototype pollution vulnerabilities in the most common JavaScript libraries.

