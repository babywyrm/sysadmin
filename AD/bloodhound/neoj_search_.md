Cypher Queries
 
Cypher Queries can be entered into the neo4j console, accessible at http://localhost:7474. These often return text-based content. There's a max of 1000 displayed rows within the console, however each query result can be downloaded as a CSV for more in depth analysis. When pasting, replace all instances of "EXAMPLE.COM" with the domain name that you are operating on. These are from a wide range of sources. A lot of them came or were inspired by discussions on the Bloodhound Slack.
 
Basic
 
Generate list of all operating systems

```
MATCH (c:Computer)
RETURN DISTINCT(c.operatingsystem)
```

Find all Windows 7 computers

```
MATCH (c:Computer)
WHERE toUpper(c.operatingsystem) CONTAINS "SERVER"
RETURN c
``` 

Return any group where the name of the group contains the string "ADM".

```
MATCH (g:Group)
WHERE g.name =~ '(?i).*ADM.*'
RETURN g.name
```

Find every OU that contains the string "CITRIX".

```
MATCH (o:OU)
WHERE o.name =~ "(?i).*CITRIX.*"
RETURN o
``` 

Return cross domain 'HasSession' relationships

```
MATCH p=((S:Computer)-[r:HasSession*1]->(T:User))
WHERE NOT S.domain = T.domain
RETURN p
```

Intermediate
 

Find all computers with sessions from users of a different domain (Looking for cross-domain compromise opportunities).

```
MATCH (c:Computer)-[:HasSession]->(u:User {domain:'EXAMPLE.COM'})
WHERE NOT c.domain = u.domain
RETURN u.name,COUNT(c)
```

Find all users trusted to perform constrained delegation, return in order of the number of target computers. 

```
MATCH (u:User)-[:AllowedToDelegate]->(c:Computer)
RETURN u.name,COUNT(c)
ORDER BY COUNT(c) DESC
```

Return each OU in the database in order of the number of computers in that OU. 

```
MATCH (o:OU)-[:Contains]->(c:Computer)
RETURN o.name,o.guid,COUNT(c)
ORDER BY COUNT(c) DESC
```

Return the name of every computer in the database where at least one SPN for the computer contains the string "MSSQL".

```
MATCH (c:Computer)
WHERE ANY (x IN c.serviceprincipalnames WHERE toUpper(x) CONTAINS "MSSQL")
RETURN c.name,c.serviceprincipalnames
ORDER BY c.name ASC
```

Find groups with both users and computers that belong to the group. 

```
MATCH (c:Computer)-[r:MemberOf*1..]->(groupsWithComps:Group)
WITH groupsWithComps
MATCH (u:User)-[r:MemberOf*1..]->(groupsWithComps)
RETURN DISTINCT(groupsWithComps) as groupsWithCompsAndUsers
```

Return each OU in the database that contains a Server computer. Return rows where the columns are the name of the OU, the name of the computer, and the operating system of the computer. Neo4j web console only.

```
MATCH (o:OU)-[:Contains]->(c:Computer)
WHERE toUpper(o.name) CONTAINS "SERVER"
RETURN o.name,c.name,c.operatingsystem
```

Get a count of computers that do not have admins

```
MATCH (n)-[r:AdminTo]->(c:Computer)
WITH COLLECT(c.name) as compsWithAdmins
MATCH (c2:Computer) WHERE NOT c2.name in compsWithAdmins
RETURN COUNT(c2)
```

Get the names of computers without admins, sorted in alphabetical order

```
MATCH (n)-[r:AdminTo]->(c:Computer)
WITH COLLECT(c.name) as compsWithAdmins
MATCH (c2:Computer) WHERE NOT c2.name in compsWithAdmins
RETURN c2.name
ORDER BY c2.name ASC
```

Return username and number of computers that username is admin for

```
MATCH (U:User)-[r:MemberOf|:AdminTo*1..]->(C:Computer)
WITH U.name as n, COUNT(DISTINCT(C)) as c
RETURN n,c
ORDER BY c DESC
```

Show all users that are administrator on more than one machine

```
MATCH (U:User)-[r:MemberOf|:AdminTo*1..]->(C:Computer)
WITH U.name as n, COUNT(DISTINCT(C)) as c
WHERE c>1
RETURN n
```

Show groups with most local admin

```
MATCH (g:Group)
WITH g
OPTIONAL MATCH (g)-[r:AdminTo]->(c:Computer)
WITH g,COUNT(c) as expAdmin
OPTIONAL MATCH (g)-[r:MemberOf*1..]->(a:Group)-[r2:AdminTo]->(c:Computer)
WITH g,expAdmin,COUNT(DISTINCT(c)) as unrolledAdmin
RETURN g.name,expAdmin,unrolledAdmin, expAdmin + unrolledAdmin as totalAdmin
ORDER BY totalAdmin DESC
```

List of unique users with a path (no "GetChanges" path, no "CanRDP") to a Group tagged as "highvalue"

```
MATCH (u:User)
MATCH (g:Group {highvalue: True})
MATCH p = shortestPath((u:User)-[r:AddMember|AdminTo|AllExtendedRights|AllowedToDelegate|Contains|ExecuteDCOM|ForceChangePassword|GenericAll|GenericWrite|GetChangesAll|GpLink|HasSession|MemberOf|Owns|ReadLAPSPassword|TrustedBy|WriteDacl|WriteOwner*1..]->(g))
RETURN DISTINCT(u.name),u.enabled
order by u.name
```

Show the number of users that have admin rights on each computer, in descending order

```
MATCH (c:Computer)
OPTIONAL MATCH (u1:User)-[:AdminTo]->(c)
OPTIONAL MATCH (u2:User)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c)
WITH COLLECT(u1) + COLLECT(u2) AS tempVar,c
UNWIND tempVar AS admins
RETURN c.name AS computerName,COUNT(DISTINCT(admins)) AS adminCount
ORDER BY adminCount DESC
```

Advanced
Find users who are not marked as "Sensitive and Cannot Be Delegated" that have Administrative access to a computer, and where those users have sessions on servers with Unconstrained Delegation enabled. 

```
MATCH (u:User {sensitive:false})-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c1:Computer)
WITH u,c1
MATCH (c2:Computer {unconstraineddelegation:true})-[:HasSession]->(u)
RETURN u.name AS user,c1.name AS AdminTo,c2.name AS TicketLocation
ORDER BY user ASC
```

Same as above, but only returns the list of users.

```
MATCH (u:User {sensitive:false})-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c1:Computer)
WITH u,c1
MATCH (c2:Computer {unconstraineddelegation:true})-[:HasSession]->(u)
RETURN DISTINCT(u.name)
```

Find any computer that is NOT a domain controller that is trusted to perform unconstrained delegation.

```
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group)
WHERE g.objectsid ENDS WITH "-516"
WITH COLLECT(c1.name) AS domainControllers
MATCH (c2:Computer {unconstraineddelegation:true})
WHERE NOT c2.name IN domainControllers
RETURN c2.name,c2.operatingsystem
ORDER BY c2.name ASC
```

Find every instance of a computer account having local admin rights on other computers. Return in descending order of the number of computers the computer account has local admin rights on. 

```
MATCH (c1:Computer)
OPTIONAL MATCH (c1)-[:AdminTo]->(c2:Computer)
OPTIONAL MATCH (c1)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c3:Computer)
WITH COLLECT(c2) + COLLECT(c3) AS tempVar,c1
UNWIND tempVar AS computers
RETURN c1.name,COUNT(DISTINCT(computers))
ORDER BY COUNT(DISTINCT(computers)) DESC
```

Return all users which can Return to any system, if they belong to adm or svr accounts

```
MATCH (c:Computer)
MATCH (n:User)-[r:MemberOf]->(g:Group)  WHERE g.name = 'DOMAIN ADMINS@EXAMPLE.COM'
optional match (g:Group)-[:CanRDP]->(c)
OPTIONAL MATCH (u1:User)-[:CanRDP]->(c) where u1.enabled = true and u1.name contains 'ADM' OR u1.name contains 'SVR'
OPTIONAL MATCH (u2:User)-[:MemberOf*1..]->(:Group)-[:CanRDP]->(c) where u2.enabled = true and u2.name contains 'ADM' OR u2.name contains 'SVR'
WITH COLLECT(u1) + COLLECT(u2) + collect(n) as tempVar,c
UNWIND tempVar as users
RETURN c.name,COLLECT(users.name) as usernames
ORDER BY usernames  desc
```

Stats percentage of enabled users that have a path to a high value group

```
MATCH (u:User {domain:'EXAMPLE.COM',enabled:True})
MATCH (g:Group {domain:'EXAMPLE.COM'})
WHERE g.highvalue = True
WITH g, COUNT(u) as userCount
MATCH p = shortestPath((u:User {domain:'EXAMPLE.COM',enabled:True})-[*1..]->(g))
RETURN toint(100.0 * COUNT(distinct u) / userCount)
```

What permissions does Everyone/Authenticated users/Domain users/Domain computers have?

```
MATCH p=(m:Group)- [r:AddMember|AdminTo|AllExtendedRights|AllowedToDelegate|CanRDP|Contains|ExecuteDCOM|ForceChangePassword|GenericAll|GenericWrite|GetChanges|GetChangesAll|HasSession|Owns|ReadLAPSPassword|SQLAdmin|TrustedBy|WriteDACL|WriteOwner|AddAllowedToAct|AllowedToAct]->(t) 
WHERE
m.objectsid ENDS WITH '-513' OR
m.objectsid ENDS WITH '-515' OR
m.objectsid ENDS WITH 'S-1-5-11' OR
m.objectsid ENDS WITH 'S-1-1-0' 
RETURN m.name,TYPE(r),t.name,t.enabled
```
