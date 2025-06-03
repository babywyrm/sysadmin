# BloodHound Cypher Queries Cheat Sheet

##
#
https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
#
https://m4lwhere.medium.com/the-ultimate-guide-for-bloodhound-community-edition-bhce-80b574595acf
#
##

For use in the 'CYPHER' tab of the BloodHound GUI.
Remember to replace 'CERTIFICATE.HTB' with your target domain (all caps) where necessary.
Object names (users, computers, groups) in queries usually need to be exact, including capitalization and the '@DOMAIN.HTB' suffix.

---

### Initial Enumeration & Overview

These queries help you get a basic understanding of the domain and its inhabitants.

**1. Count All Nodes (Objects) in the Graph**
*Quick check to confirm data is loaded and get total count.*
```cypher
MATCH (n) RETURN count(n) AS TotalNodes;
```

**2. List All Domains**
*See all domains ingested (useful in multi-domain environments).*
```cypher
MATCH (d:Domain) RETURN d.name AS DomainName;
```

**3. List All Users (Basic Properties & Potential Initial Access)**
*See usernames, last logon, and if AS-REP Roasting is possible.*
```cypher
MATCH (u:User) RETURN u.name AS UserName, u.lastlogon AS LastLogon, u.donotreqpreauth AS ASREPRoastable, u.enabled AS EnabledStatus, u.description AS Description ORDER BY UserName LIMIT 1000;
```

**4. List All Computers (Basic Properties & OS Info)**
*See computer names, OS, and initial access indicators.*
```cypher
MATCH (c:Computer) RETURN c.name AS ComputerName, c.operatingsystem AS OS, c.enabledRDP AS RDPAccess, c.enabledPSRemoting AS PSRemotingAccess, c.lastlogon AS LastLogon ORDER BY ComputerName LIMIT 1000;
```

**5. List All Groups (Basic Properties & Descriptions)**
*Overview of groups and their purposes (often revealed in description).*
```cypher
MATCH (g:Group) RETURN g.name AS GroupName, g.description AS Description ORDER BY GroupName LIMIT 1000;
```

**6. List All Organizational Units (OUs)**
*Understand the domain's hierarchical structure.*
```cypher
MATCH (ou:OU) RETURN ou.name AS OULocation ORDER BY OULocation LIMIT 100;
```

**7. Find All Domain Controllers**
*Essential targets, often named 'DC01', 'DC02', etc.*
```cypher
MATCH (c:Computer {primarygroupid:516}) RETURN c.name AS DomainControllerName ORDER BY DomainControllerName; // 516 is Domain Controllers group RID
```

**8. Identify High-Value Groups (Besides DAs)**
*Look for groups like 'Schema Admins', 'Enterprise Admins', 'Account Operators', 'Backup Operators', etc.*
```cypher
MATCH (g:Group) WHERE g.name CONTAINS 'ADMINS' OR g.name CONTAINS 'OPERATORS' RETURN g.name AS PotentialHighValueGroup, g.description AS Description ORDER BY g.name LIMIT 50;
```

**9. Find Computers with AdminCount Set (High-Privilege Users)**
*Indicates a user has been part of a protected group and their permissions are guarded by AdminSDHolder.*
```cypher
MATCH (c:Computer {admincount:true}) RETURN c.name AS AdminCountComputer;
```

---

### Attack Paths & Privilege Escalation

These queries are designed to find direct and indirect paths to compromise.

**10. Find Shortest Paths to Domain Admins (from any non-DA node)**
*The classic, most important query. Excludes Domain Admins group itself as a start node.*
```cypher
MATCH p=shortestPath((n)-[*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'})) WHERE NOT n = g RETURN p;
```

**11. Find Shortest Paths from a Specific Compromised User to Domain Admins**
*Simulate compromise: Replace 'SARA.B@CERTIFICATE.HTB' with your initial compromised user.*
```cypher
MATCH p=shortestPath((u:User {name:'SARA.B@CERTIFICATE.HTB'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'})) RETURN p;
```

**12. Find Shortest Paths to Enterprise Admins (often forest root)**
*For broader scope in multi-domain/forest environments.*
```cypher
MATCH p=shortestPath((n)-[*1..]->(g:Group {name:'ENTERPRISE ADMINS@CERTIFICATE.HTB'})) WHERE NOT n = g RETURN p;
```

**13. Find All Direct Domain Admins (Users & Groups)**
*See who is directly part of the Domain Admins group.*
```cypher
MATCH (n)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}) RETURN n.name AS DirectDomainAdmin;
```

**14. Find Kerberoastable Accounts**
*Users with SPNs. Get their TGS-REP hash for offline cracking.*
```cypher
MATCH (u:User {hasSPN:true, donotreqpreauth:false, enabled:true}) RETURN u.name AS KerberoastableAccount, u.serviceprincipalnames AS SPNs ORDER BY u.name LIMIT 1000;
```

**15. Find AS-REP Roastable Accounts**
*Users not requiring preauthentication. Get their TGT hash for offline cracking.*
```cypher
MATCH (u:User {donotreqpreauth:true, enabled:true}) RETURN u.name AS ASREPRoastableAccount ORDER BY u.name LIMIT 1000;
```

**16. Find Users with ForceChangePassword Privilege on Admins**
*Users who can force password change on a target admin account.*
```cypher
MATCH (u:User)-[:ForceChangePassword]->(t:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}) RETURN u.name AS AttackerUser, t.name AS TargetAdmin;
```

**17. Find Users Who Can WriteDACL/WriteOwner/GenericAll/GenericWrite on Domain Controller**
*Extremely critical privileges directly on the DC, allowing full control.*
```cypher
MATCH (u:User)-[r:WriteDACL|WriteOwner|GenericAll|GenericWrite]->(c:Computer {primarygroupid:516}) RETURN u.name AS Attacker, type(r) AS RelationshipType, c.name AS TargetDC;
```

**18. Find Users with Control over Specific OU/Container (e.g., 'Users' OU)**
*Control over an OU allows creating users, deleting, or modifying objects within it.*
```cypher
MATCH (u:User)-[r:GenericAll|GenericWrite|WriteDACL|WriteOwner|AddMember]->(ou:OU {name:'USERS@CERTIFICATE.HTB'}) RETURN u.name AS ControllingUser, type(r) AS Privilege, ou.name AS TargetOU;
```

**19. Find Unrolled Group Memberships for a Specific Group (e.g., 'Domain Admins')**
*See all members, direct and indirect, of a group.*
```cypher
MATCH (n)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}) RETURN n.name AS MemberName, n.type AS MemberType;
```

---

### Lateral Movement & Post-Exploitation

Queries to find ways to move around the network and escalate privileges after initial access.

**20. Find All Active Sessions (LoggedOn Users)**
*Users currently logged into computers. Potential for credential dumping.*
```cypher
MATCH p=(u:User)-[:HasSession]->(c:Computer) RETURN p LIMIT 1000;
```

**21. Find Computers with Admin Rights on Other Computers (AdminTo)**
*A common lateral movement path via local administrator rights.*
```cypher
MATCH p=(c1:Computer)-[:AdminTo]->(c2:Computer) RETURN p LIMIT 1000;
```

**22. Find Computers where RDP is Enabled**
*Identify potential targets for Remote Desktop Protocol access.*
```cypher
MATCH (c:Computer {enabledRDP:true}) RETURN c.name AS RDPAccessibleComputer LIMIT 1000;
```

**23. Find Computers where PSRemoting is Enabled**
*Identify potential targets for PowerShell Remoting.*
```cypher
MATCH (c:Computer {enabledPSRemoting:true}) RETURN c.name AS PSRemotingAccessibleComputer LIMIT 1000;
```

**24. Find Users with Explicit RDP Access to Computers**
*Users directly granted RDP access, not just local admins.*
```cypher
MATCH p=(u:User)-[:CanRDP]->(c:Computer) RETURN p LIMIT 1000;
```

**25. Find Users with Explicit PSRemoting Access to Computers**
*Users directly granted PSRemoting access.*
```cypher
MATCH p=(u:User)-[:CanPSRemote]->(c:Computer) RETURN p LIMIT 1000;
```

**26. Find Computers Running Specific Services (e.g., 'SQL', 'WEB')**
*Useful for targeting specific roles/software. (Requires collection of services)*
```cypher
MATCH (c:Computer) WHERE c.description CONTAINS 'SQL' RETURN c.name, c.description LIMIT 100; // Adjust WHERE clause
```

**27. Find Delegated Users/Computers (Often via GPO/ACLs)**
*Look for users/computers that have been granted delegation rights.*
```cypher
MATCH (u)-[:AllowedToDelegate]->(t) RETURN u.name AS DelegatingPrincipal, t.name AS DelegatedTarget LIMIT 100;
```

**28. Find Users with Constrained Delegation (TGS_REQ) to DCs**
*High-value delegation if you can compromise such a user.*
```cypher
MATCH (u:User)-[:AllowedToDelegate]->(c:Computer {primarygroupid:516}) RETURN u.name AS UserWithDelegation, c.name AS DelegatedDC;
```

**29. Find Users with Unconstrained Delegation**
*Compromise of such a user allows impersonation of any user authenticating to their host.*
```cypher
MATCH (u:User {unconstraineddelegation:true}) RETURN u.name AS UnconstrainedDelegationUser;
```

**30. Find Domain Controllers vulnerable to Coercion (e.g., PetitPotam/PrinterBug)**
*DCs that can be coerced to authenticate to an attacker, enabling NTLM relay.*
```cypher
MATCH (c:Computer {primarygroupid:516})-[:CoerceToTGT]->(d:Domain) RETURN c.name AS CoercibleDC, d.name AS Domain;
```

---

### ACL & Object Control Vulnerabilities

These focus on misconfigured permissions on Active Directory objects.

**31. Find GenericAll on Any Object (Most Powerful ACL)**
*Allows complete control over the target.*
```cypher
MATCH p=(u)-[:GenericAll]->(t) RETURN p LIMIT 1000;
```

**32. Find WriteDACL on Any Object**
*Allows modifying permissions on the target (can grant self privileges).*
```cypher
MATCH p=(u)-[:WriteDACL]->(t) RETURN p LIMIT 1000;
```

**33. Find WriteOwner on Any Object**
*Allows taking ownership of the target (can then grant self privileges).*
```cypher
MATCH p=(u)-[:WriteOwner]->(t) RETURN p LIMIT 1000;
```

**34. Find AddMember on Critical Groups (e.g., Domain Admins)**
*Allows directly adding users to high-privileged groups.*
```cypher
MATCH p=(u)-[:AddMember]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}) RETURN p;
```

**35. Find DCSync Privileges**
*Allows an attacker to synchronize replication with a DC, effectively dumping all hashes. Note: This query uses `AllExtendedRights` which includes `DS-Replication-Get-Changes-All`.*
```cypher
MATCH p=(u)-[r:GenericAll|GenericWrite|WriteDACL|WriteOwner|AllExtendedRights|ForceChangePassword]->(d:Domain) RETURN p LIMIT 100;
```

**36. Find GPOs with Local Admin Rights**
*Identifies Group Policy Objects that grant local administrator privileges on machines.*
```cypher
MATCH (gpo:GPO) WHERE gpo.localadmins = TRUE RETURN gpo.name AS GPO_Name, gpo.displayname AS DisplayName;
```

**37. Find Computers Impacted by a Specific GPO**
*Replace 'Your_GPO_Name'.*
```cypher
MATCH p=(gpo:GPO {name:'Your_GPO_Name'})-[r:GPLink]->(ou:OU)-[:Contains*0..]->(c:Computer) RETURN p LIMIT 1000;
```

---

### Defensive & Advanced Analysis

Useful for blue teaming, hardening, or more niche attack scenarios.

**38. Find Stale Accounts (Enabled users not logged on recently)**
*Potential for unused accounts that might have weak/compromised passwords. Older than 90 days.*
```cypher
MATCH (u:User {enabled:true}) WHERE u.lastlogon < (datetime().epochSeconds - 7776000) RETURN u.name AS StaleUser, datetime({epochSeconds: u.lastlogon}) AS LastLogonTime ORDER BY LastLogonTime LIMIT 1000; // Older than 90 days (90 * 24 * 60 * 60 seconds)
```

**39. Find Password Never Expires Accounts**
*Good targets for persistence or if a password spray is planned.*
```cypher
MATCH (u:User {passwordneverexpires:true, enabled:true}) RETURN u.name AS UserWithNoPwdExpiration LIMIT 1000;
```

**40. Find Enabled Users with No LastLogonTimestamp (Accounts never logged into or old)**
```cypher
MATCH (u:User {enabled:true}) WHERE u.lastlogonTimestamp IS NULL RETURN u.name AS NeverLoggedOnUser LIMIT 1000;
```

**41. Find Empty Groups**
*Groups with no direct or indirect members, often candidates for cleanup.*
```cypher
MATCH (g:Group) WHERE NOT (g)<-[:MemberOf*1..]-() RETURN g.name AS EmptyGroup LIMIT 1000;
```

**42. Find Accounts with Very Old Passwords (based on PasswordLastSet attribute)**
*This is a heuristic, looking at time since last password set, not actual length. Older than 1 year.*
```cypher
MATCH (u:User) WHERE (datetime().epochSeconds - u.pwdlastset) > 31536000 RETURN u.name AS OldPasswordUser, datetime({epochSeconds: u.pwdlastset}) AS PasswordLastSetDate ORDER BY PasswordLastSetDate LIMIT 1000; // Older than 1 year (365 * 24 * 60 * 60 seconds)
```

**43. Find Users Who Can Add Members to Important Groups (e.g., Helpdesk can add to IT)**
*Good for horizontal privilege escalation. Excludes Domain/Enterprise Admins.*
```cypher
MATCH p=(u:User)-[:AddMember]->(g:Group) WHERE NOT g.name CONTAINS 'DOMAIN ADMINS' AND NOT g.name CONTAINS 'ENTERPRISE ADMINS' RETURN p LIMIT 1000;
```

**44. Find Accounts That Are Not Enabled (Should be disabled if not needed)**
```cypher
MATCH (u:User {enabled:false}) RETURN u.name AS DisabledUser LIMIT 1000;
```

**45. Find Stale Computers (Not logged on recently)**
*Adjust the date as needed.*
```cypher
MATCH (c:Computer) WHERE c.lastlogon < datetime({year:2024, month:1, day:1}).epochSeconds RETURN c.name AS StaleComputer, datetime({epochSeconds: c.lastlogon}) AS LastLogonTime LIMIT 1000; // Adjust date
```

---

### More Advanced & Custom Queries

**46. Find Paths from any User to any Administrator Group (more general than just Domain Admins)**
```cypher
MATCH p=shortestPath((u:User)-[*1..]->(g:Group) WHERE g.name ENDS WITH '@CERTIFICATE.HTB' AND (g.name CONTAINS 'ADMINS' OR g.name CONTAINS 'ADMINISTRATORS') RETURN p LIMIT 1000;
```

**47. Find Paths from a Specific User to a Specific Target User/Computer**
*Replace 'ATTACKER@CERTIFICATE.HTB' and 'TARGET@CERTIFICATE.HTB'.*
```cypher
MATCH p=shortestPath((attacker {name:'ATTACKER@CERTIFICATE.HTB'})-[*1..]->(target {name:'TARGET@CERTIFICATE.HTB'})) RETURN p;
```

**48. Find Users with Any Dangerous Privilege on a Specific Computer**
*Replace 'TARGETCOMPUTER.CERTIFICATE.HTB'.*
```cypher
MATCH (u:User)-[r:AdminTo|CanRDP|CanPSRemote|GenericAll|GenericWrite|WriteDACL|WriteOwner|ForceChangePassword]->(c:Computer {name:'TARGETCOMPUTER.CERTIFICATE.HTB'}) RETURN u.name AS PrivilegedUser, type(r) AS Privilege, c.name AS TargetComputer;
```

**49. Enumerate All Users Who Can Control Other Users (GenericAll, GenericWrite, AllExtendedRights)**
```cypher
MATCH (u:User)-[r:GenericAll|GenericWrite|AllExtendedRights]->(t:User) RETURN u.name AS ControllingUser, type(r) AS Privilege, t.name AS TargetUser LIMIT 1000;
```

**50. Find Service Accounts Not Managed By Microsoft**
*Service accounts that are usually custom and often misconfigured.*
```cypher
MATCH (u:User) WHERE u.description IS NOT NULL AND u.description <> '' AND NOT u.description CONTAINS 'Microsoft' AND NOT u.description CONTAINS 'Windows' AND u.serviceprincipalnames IS NOT NULL RETURN u.name, u.description, u.serviceprincipalnames LIMIT 1000;
```

**51. Find Domain Users with WriteProperty on Self (Password reset on self)**
*These users often have special reset privileges over their own accounts.*
```cypher
MATCH (u:User)-[r:WriteProperty]->(u) WHERE r.isacl = TRUE AND r.property = 'pwdlastset' RETURN u.name;
```

**52. Find Password Sprayable Accounts**
*Find enabled user accounts that haven't been logged into recently, often good targets for password spraying if password complexity is low. Less than 1 week ago or never logged on.*
```cypher
MATCH (u:User {enabled:true}) WHERE u.lastlogonTimestamp IS NULL OR u.lastlogonTimestamp < (datetime().epochSeconds - 604800) RETURN u.name AS PasswordSprayTarget, u.lastlogon AS LastLogonTime LIMIT 1000; // lastlogon < 1 week ago
```

**53. Find Accounts That Can Access the Unprivileged Users OU**
*Often a good starting point for internal enumeration.*
```cypher
MATCH (u)-[r]->(ou:OU {name: 'USERS@CERTIFICATE.HTB'}) RETURN u.name AS UserWithAccess, type(r) AS RelationshipType, ou.name AS TargetOU LIMIT 100;
```

**54. Find GPOs granting RDP/PSRemoting/LocalAdmin**
*More general GPO query to find various risky settings applied via GPO.*
```cypher
MATCH (gpo:GPO) WHERE gpo.rdp OR gpo.psremote OR gpo.localadmins RETURN gpo.name AS GPO_Name, gpo.rdp AS RDPEnabled, gpo.psremote AS PSRemotingEnabled, gpo.localadmins AS LocalAdminsConfigured;
```
