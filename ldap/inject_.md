
Introduction to LDAP Injection

Lightweight Directory Access Protocol (LDAP) is a protocol used to access directory servers such as Active Directory (AD). In particular, LDAP queries can retrieve information from directory servers. Web applications may use LDAP for integration with AD or other directory services for authentication or data retrieval purposes. If user input is inserted into LDAP queries without proper sanitization, LDAP Injection vulnerabilities can arise.
LDAP Foundations

Before jumping into LDAP injection, we must establish a baseline about LDAP terminology and syntax.
LDAP terminology

Let us start by establishing important LDAP terminology:

    A Directory Server (DS) is the entity that stores data, similar to a database server, though the way data is stored is different. An example of a DS is OpenLDAP
    An LDAP Entry holds data for an entity and consists of three main components:
        The Distinguished Name (DN) is a unique identifier for the entry that consists of multiple Relative Distinguished Names (RDNs). Each RDN consists of key-value pairs. An example DN is uid=admin,dc=hackthebox,dc=com, which consists of three comma-separated RDNs
        Multiple Attributes that store data. Each attribute consists of an attribute type and a set of values
        Multiple Object Classes which consist of attribute types that are related to a particular type of object, for instance, Person or Group

LDAP defines Operations, which are actions the client can initiate. These include:

    Bind Operation: Client authentication with the server
    Unbind Operation: Close the client connection to the server
    Add Operation: Create a new entry
    Delete Operation: Delete an entry
    Modify Operation: Modify an entry
    Search Operation: Search for entries matching a search query

LDAP Search Filter Syntax

LDAP search queries are called search filters. A search filter may consist of multiple components, each needing to be enclosed in parentheses (). Each base component consists of an attribute, an operand, and a value to search for. LDAP defines the following base operands:
Name 	Operand 	Example 	Example Description
Equality 	= 	(name=Kaylie) 	Matches all entries that contain a name attribute with the value Kaylie
Greater-Or-Equal 	>= 	(uid>=10) 	Matches all entries that contain a uid attribute with a value greater-or-equal to 10
Less-Or-Equal 	<= 	(uid<=10) 	Matches all entries that contain a uid attribute with a value less-or-equal to 10
Approximate Match 	~= 	(name~=Kaylie) 	Matches all entries that contain a name attribute with approximately the value Kaylie

Note: The LDAP specification does not define how approximate matching should be implemented. This leads to inconsistencies between different LDAP implementations such that the same search filter can yield different results.

To construct more complex search filters, LDAP further supports the following combination operands:
Name 	Operand 	Example 	Example Description
And 	(&()()) 	(&(name=Kaylie)(title=Manager)) 	Matches all entries that contain a name attribute with the value Kaylie and a title attribute with the value Manager
Or 	(|()()) 	(|(name=Kaylie)(title=Manager)) 	Matches all entries that contain a name attribute with the value Kaylie or a title attribute with the value Manager
Not 	(!()) 	(!(name=Kaylie)) 	Matches all entries that contain a name attribute with a value different from Kaylie

Note: And and Or filters support more than two arguments. For instance, (&(attr1=a)(attr2=b)(attr3=c)(attr4=d)) is a valid search filter.

Furthermore, we can display True and False like so:
Name 	Filter
True 	(&)
False 	(|)

Lastly, LDAP supports an asterisk as a wildcard, such that we can define wildcard search filters like the following:
Example 	Example Description
(name=*) 	Matches all entries that contain a name attribute
(name=K*) 	Matches all entries that contain a name attribute that begins with K
(name=*a*) 	Matches all entries that contain a name attribute that contains an a

For more details on search filters, check out RFC 4515.
Common Attribute Types

Here are some common attribute types that we can search for. The list is non-exhaustive. Furthermore, LDAP server instances may implement custom attribute types that can be used in their search filters.
Attribute Type 	Description
cn 	Full Name
givenName 	First name
sn 	Last name
uid 	User ID
objectClass 	Object type
distinguishedName 	Distinguished Name
ou 	Organizational Unit
title 	Title of a Person
telephoneNumber 	Phone Number
description 	Description
mail 	Email Address
street 	Address
postalCode 	Zip code
member 	Group Memberships
userPassword 	User password

For a detailed overview of LDAP attribute types, check out RFC 2256.


# Prevent



LDAP Injection Prevention

After discussing different ways to exploit LDAP injection vulnerabilities, let us discuss how to prevent them.
General Remarks

While many web developers are aware of SQL injection vulnerabilities due to the common use of SQL databases in web applications, LDAP injection is a much rarer type of vulnerability, and thus there is less awareness about it. Therefore, LDAP injection vulnerabilities potentially exist whenever LDAP integration is used in web applications, even though there are simple countermeasures. To prevent LDAP injection vulnerabilities, the following special characters need to be escaped:

    The parenthesis ( needs to be escaped as \28
    The parenthesis ) needs to be escaped as \29
    The asterisk * needs to be escaped as \2a
    The backslash \ needs to be escaped as \5c
    The null byte needs to be escaped as \00

PHP Example

In many languages, there are predefined functions that implement LDAP escaping for us. In PHP, this function is called ldap_escape. Check out the documentation here.

As an example, let us consider the following simplified code that is vulnerable to LDAP injection:
Code: php
```
// ldap connection
const LDAP_HOST = "localhost";
const LDAP_PORT = 389;
const LDAP_DC = "dc=example,dc=htb";
const LDAP_DN = "cn=ldapuser,dc=example,dc=htb";
const LDAP_PASS = "ldappassword";

// connect to server
$conn = ldap_connect(LDAP_HOST, LDAP_PORT);
if (!$conn) {
    exit('LDAP connection failed');
}

// bind operation
ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
$bind = ldap_bind($conn, LDAP_DN, LDAP_PASS);
if (!$bind) {
    exit('LDAP bind failed');
}

// search operation
$filter = '(&(cn=' . $_POST['username'] . ')(userPassword=' . $_POST['password'] . '))';
$search = ldap_search($conn, LDAP_DC, $filter);
$entries = ldap_get_entries($conn, $search);

if ($entries['count'] > 0) {
    // successful login
    <SNIP>
} else {
    // login failed
    <SNIP>
}
```
In the search operation, the web application inserts user input without any sanitization, leading to LDAP injection as we have seen and exploited in the last couple of sections. To prevent this, we simply need to call the function ldap_escape when inserting the user input into the search filter. The corresponding line of code should thus look like this:
Code: php
```
$filter = '(&(cn=' . ldap_escape($_POST['username']) . ')(userPassword=' . ldap_escape($_POST['password']) . '))';
```
Best Practices

While proper sanitization prevents LDAP injection entirely, there are some further best practices we should follow whenever LDAP is used in a web application. First, we should give the account used to bind to the DS the least privileges required to perform the search operation for our specific task. This limits the amount of data an attacker can access in the event of an LDAP injection vulnerability.

Furthermore, when using LDAP for authentication, it is more secure to perform a bind operation with the credentials provided by the user instead of performing a search operation. Since the DS checks the credentials when performing a bind operation, we delegate the authentication process to the DS to handles it for us. This way, there is no LDAP search filter where LDAP injection can occur. To do this, we need to change our example code above to look like this:
Code: php
```
// ldap connection
const LDAP_HOST = "localhost";
const LDAP_PORT = 389;
const LDAP_DC = "dc=example,dc=htb";

// user credentials
$dn = "cn=" . ldap_escape($_POST['username'], "", LDAP_ESCAPE_DN) . ",dc=example,dc=htb";
$pw = $_POST['password'];

// connect to server
$conn = ldap_connect(LDAP_HOST, LDAP_PORT);
if (!$conn) {
    exit('LDAP connection failed');
}

// bind operation
ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
$bind = ldap_bind($conn, $dn, $pw);
if ($bind) {
    // successful login
    <SNIP>
} else {
    // login failed
    <SNIP>
}
```

Lastly, anonymous authentication, also called anonymous binds, should be disabled on the DS so that only authenticated users can perform any operation.

