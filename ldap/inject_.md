
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
