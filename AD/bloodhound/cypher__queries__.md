# BloodHound v7.x.x Cypher Queries Cheat Sheet

# For use in the 'CYPHER' tab of the BloodHound GUI.
# Remember to replace 'CERTIFICATE.HTB' with your target domain (all caps) where necessary.
# Object names (users, computers, groups) in queries usually need to be exact, including capitalization and the '@DOMAIN.HTB' suffix.

# --- SECTION 1: INITIAL ENUMERATION & OVERVIEW ---
# These queries help you get a basic understanding of the domain and its inhabitants.

# 1.1 Count All Nodes (Objects) in the Graph
#    - Quick check to confirm data is loaded and get total count.
MATCH (n) RETURN count(n) AS TotalNodes;

# 1.2 List All Domains
#    - See all domains ingested (useful in multi-domain environments).
MATCH (d:Domain) RETURN d.name AS DomainName;

# 1.3 List All Users (Basic Properties & Potential Initial Access)
#    - See usernames, last logon, and if AS-REP Roasting is possible.
MATCH (u:User) 
RETURN 
    u.name AS UserName, 
    u.lastlogon AS LastLogon, 
    u.donotreqpreauth AS ASREPRoastable, 
    u.enabled AS EnabledStatus,
    u.description AS Description
ORDER BY UserName 
LIMIT 1000;

# 1.4 List All Computers (Basic Properties & OS Info)
#    - See computer names, OS, and initial access indicators.
MATCH (c:Computer) 
RETURN 
    c.name AS ComputerName, 
    c.operatingsystem AS OS, 
    c.enabledRDP AS RDPAccess, 
    c.enabledPSRemoting AS PSRemotingAccess,
    c.lastlogon AS LastLogon
ORDER BY ComputerName 
LIMIT 1000;

# 1.5 List All Groups (Basic Properties & Descriptions)
#    - Overview of groups and their purposes (often revealed in description).
MATCH (g:Group) 
RETURN 
    g.name AS GroupName, 
    g.description AS Description 
ORDER BY GroupName 
LIMIT 1000;

# 1.6 List All Organizational Units (OUs)
#    - Understand the domain's hierarchical structure.
MATCH (ou:OU) RETURN ou.name AS OULocation ORDER BY OULocation LIMIT 100;

# 1.7 Find All Domain Controllers
#    - Essential targets, often named 'DC01', 'DC02', etc.
MATCH (c:Computer {primarygroupid:516}) RETURN c.name AS DomainControllerName ORDER BY DomainControllerName; # 516 is Domain Controllers group RID

# 1.8 Identify High-Value Groups (Besides DAs)
#    - Look for groups like 'Schema Admins', 'Enterprise Admins', 'Account Operators', 'Backup Operators', etc.
MATCH (g:Group) 
WHERE g.name CONTAINS 'ADMINS' OR g.name CONTAINS 'OPERATORS' 
RETURN g.name AS PotentialHighValueGroup, g.description AS Description 
ORDER BY g.name LIMIT 50;

# 1.9 Find Computers with AdminCount Set (High-Privilege Users)
#    - Indicates a user has been part of a protected group and their permissions are guarded by AdminSDHolder.
MATCH (c:Computer {admincount:true}) RETURN c.name AS AdminCountComputer;


# --- SECTION 2: ATTACK PATHS & PRIVILEGE ESCALATION ---
# These queries are designed to find direct and indirect paths to compromise.

# 2.1 Find Shortest Paths to Domain Admins (from any non-DA node)
#    - The classic, most important query. Excludes Domain Admins group itself as a start node.
MATCH p=shortestPath((n)-[*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}))
WHERE NOT n = g
RETURN p;

# 2.2 Find Shortest Paths from a Specific Compromised User to Domain Admins
#    - Simulate compromise: Replace 'SARA.B@CERTIFICATE.HTB' with your initial compromised user.
MATCH p=shortestPath((u:User {name:'SARA.B@CERTIFICATE.HTB'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}))
RETURN p;

# 2.3 Find Shortest Paths to Enterprise Admins (often forest root)
#    - For broader scope in multi-domain/forest environments.
MATCH p=shortestPath((n)-[*1..]->(g:Group {name:'ENTERPRISE ADMINS@CERTIFICATE.HTB'}))
WHERE NOT n = g
RETURN p;

# 2.4 Find All Direct Domain Admins (Users & Groups)
#    - See who is directly part of the Domain Admins group.
MATCH (n)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}) RETURN n.name AS DirectDomainAdmin;

# 2.5 Find Kerberoastable Accounts
#    - Users with SPNs. Get their TGS-REP hash for offline cracking.
MATCH (u:User {hasSPN:true, donotreqpreauth:false, enabled:true}) 
RETURN 
    u.name AS KerberoastableAccount, 
    u.serviceprincipalnames AS SPNs 
ORDER BY u.name LIMIT 1000;

# 2.6 Find AS-REP Roastable Accounts
#    - Users not requiring preauthentication. Get their TGT hash for offline cracking.
MATCH (u:User {donotreqpreauth:true, enabled:true}) 
RETURN u.name AS ASREPRoastableAccount 
ORDER BY u.name LIMIT 1000;

# 2.7 Find Users with ForceChangePassword Privilege on Admins
#    - Users who can force password change on a target admin account.
MATCH (u:User)-[:ForceChangePassword]->(t:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}) 
RETURN u.name AS AttackerUser, t.name AS TargetAdmin;

# 2.8 Find Users Who Can WriteDACL/WriteOwner/GenericAll/GenericWrite on Domain Controller
#    - Extremely critical privileges directly on the DC, allowing full control.
MATCH (u:User)-[r:WriteDACL|WriteOwner|GenericAll|GenericWrite]->(c:Computer {name:'DC01.CERTIFICATE.HTB'}) 
RETURN u.name AS Attacker, type(r) AS RelationshipType, c.name AS TargetDC;

# 2.9 Find Users with Control over Specific OU/Container (e.g., 'Users' OU)
#    - Control over an OU allows creating users, deleting, or modifying objects within it.
MATCH (u:User)-[r:GenericAll|GenericWrite|WriteDACL|WriteOwner|AddMember]->(ou:OU {name:'USERS@CERTIFICATE.HTB'})
RETURN u.name AS ControllingUser, type(r) AS Privilege, ou.name AS TargetOU;

# 2.10 Find Unrolled Group Memberships for a Specific Group (e.g., 'Domain Admins')
#     - See all members, direct and indirect, of a group.
MATCH (n)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}) 
RETURN n.name AS MemberName, n.type AS MemberType;


# --- SECTION 3: LATERAL MOVEMENT & POST-EXPLOITATION ---
# Queries to find ways to move around the network and escalate privileges after initial access.

# 3.1 Find All Active Sessions (LoggedOn Users)
#    - Users currently logged into computers. Potential for credential dumping.
MATCH p=(u:User)-[:HasSession]->(c:Computer) RETURN p LIMIT 1000;

# 3.2 Find Computers with Admin Rights on Other Computers (AdminTo)
#    - A common lateral movement path via local administrator rights.
MATCH p=(c1:Computer)-[:AdminTo]->(c2:Computer) RETURN p LIMIT 1000;

# 3.3 Find Computers where RDP is Enabled
#    - Identify potential targets for Remote Desktop Protocol access.
MATCH (c:Computer {enabledRDP:true}) RETURN c.name AS RDPAccessibleComputer LIMIT 1000;

# 3.4 Find Computers where PSRemoting is Enabled
#    - Identify potential targets for PowerShell Remoting.
MATCH (c:Computer {enabledPSRemoting:true}) RETURN c.name AS PSRemotingAccessibleComputer LIMIT 1000;

# 3.5 Find Users with Explicit RDP Access to Computers
#    - Users directly granted RDP access, not just local admins.
MATCH p=(u:User)-[:CanRDP]->(c:Computer) RETURN p LIMIT 1000;

# 3.6 Find Users with Explicit PSRemoting Access to Computers
#    - Users directly granted PSRemoting access.
MATCH p=(u:User)-[:CanPSRemote]->(c:Computer) RETURN p LIMIT 1000;

# 3.7 Find Computers Running Specific Services (e.g., 'SQL', 'WEB')
#    - Useful for targeting specific roles/software. (Requires collection of services)
MATCH (c:Computer) WHERE c.description CONTAINS 'SQL' RETURN c.name, c.description LIMIT 100; # Adjust WHERE clause

# 3.8 Find Delegated Users/Computers (Often via GPO/ACLs)
#    - Look for users/computers that have been granted delegation rights.
MATCH (u)-[:AllowedToDelegate]->(t) RETURN u.name AS DelegatingPrincipal, t.name AS DelegatedTarget LIMIT 100;

# 3.9 Find Users with Constrained Delegation (TGS_REQ) to DCs
#    - High-value delegation if you can compromise such a user.
MATCH (u:User)-[:AllowedToDelegate]->(c:Computer {name:'DC01.CERTIFICATE.HTB'}) RETURN u.name AS UserWithDelegation, c.name AS DelegatedDC;

# 3.10 Find Users with Unconstrained Delegation
#     - Compromise of such a user allows impersonation of *any* user authenticating to their host.
MATCH (u:User {unconstraineddelegation:true}) RETURN u.name AS UnconstrainedDelegationUser;

# 3.11 Find Domain Controllers vulnerable to Coercion (e.g., PetitPotam/PrinterBug)
#     - DCs that can be coerced to authenticate to an attacker, enabling NTLM relay.
MATCH (c:Computer {primarygroupid:516})-[:CoerceToTGT]->(d:Domain) RETURN c.name AS CoercibleDC, d.name AS Domain;


# --- SECTION 4: ACL & OBJECT CONTROL VULNERABILITIES ---
# These focus on misconfigured permissions on Active Directory objects.

# 4.1 Find GenericAll on Any Object (Most Powerful ACL)
#    - Allows complete control over the target.
MATCH p=(u)-[:GenericAll]->(t) RETURN p LIMIT 1000;

# 4.2 Find WriteDACL on Any Object
#    - Allows modifying permissions on the target (can grant self privileges).
MATCH p=(u)-[:WriteDACL]->(t) RETURN p LIMIT 1000;

# 4.3 Find WriteOwner on Any Object
#    - Allows taking ownership of the target (can then grant self privileges).
MATCH p=(u)-[:WriteOwner]->(t) RETURN p LIMIT 1000;

# 4.4 Find AddMember on Critical Groups (e.g., Domain Admins)
#    - Allows directly adding users to high-privileged groups.
MATCH p=(u)-[:AddMember]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}) RETURN p;

# 4.5 Find DCSync Privileges
#    - Allows an attacker to synchronize replication with a DC, effectively dumping all hashes.
MATCH p=(u)-[:GenericAll|GenericWrite|WriteDACL|WriteOwner|AllExtendedRights|ForceChangePassword]->(d:Domain)
WHERE 'DS-Replication-Get-Changes' IN r.Rights OR 'DS-Replication-Get-Changes-All' IN r.Rights OR 'DS-Replication-Get-Changes-In-Filtered-Set' IN r.Rights
RETURN p LIMIT 100;

# 4.6 Find GPOs with Local Admin Rights
#    - Identifies Group Policy Objects that grant local administrator privileges on machines.
MATCH (gpo:GPO) WHERE gpo.localadmins = TRUE RETURN gpo.name AS GPO_Name, gpo.displayname AS DisplayName;

# 4.7 Find Computers impacted by a Specific GPO
#     - Replace 'Your_GPO_Name'
MATCH p=(gpo:GPO {name:'Your_GPO_Name'})-[r:GPLink]->(ou:OU)-[:Contains*0..]->(c:Computer) RETURN p LIMIT 1000;


# --- SECTION 5: DEFENSIVE & ADVANCED ANALYSIS ---
# Useful for blue teaming, hardening, or more niche attack scenarios.

# 5.1 Find Stale Accounts (Enabled users not logged on recently)
#    - Potential for unused accounts that might have weak/compromised passwords.
MATCH (u:User {enabled:true}) 
WHERE u.lastlogon < (datetime().epochSeconds - 7776000) # Older than 90 days (90 * 24 * 60 * 60 seconds)
RETURN u.name AS StaleUser, datetime({epochSeconds: u.lastlogon}) AS LastLogonTime 
ORDER BY LastLogonTime LIMIT 1000;

# 5.2 Find Password Never Expires Accounts (enabled and non-disabled)
#    - Good targets for persistence or if a password spray is planned.
MATCH (u:User {passwordneverexpires:true, enabled:true}) RETURN u.name AS UserWithNoPwdExpiration LIMIT 1000;

# 5.3 Find Enabled Users with No LastLogonTimestamp (Accounts never logged into or old)
MATCH (u:User {enabled:true}) WHERE u.lastlogonTimestamp IS NULL RETURN u.name AS NeverLoggedOnUser LIMIT 1000;

# 5.4 Find Empty Groups
#    - Groups with no direct or indirect members, often candidates for cleanup.
MATCH (g:Group) WHERE NOT (g)<-[:MemberOf*1..]-() RETURN g.name AS EmptyGroup LIMIT 1000;

# 5.5 Find Accounts with Very Long Passwords (based on PasswordLastSet attribute - not actual password length)
#     - This is a heuristic. It's looking at time since last password set, not actual length.
MATCH (u:User) 
WHERE (datetime().epochSeconds - u.pwdlastset) > 31536000 # Older than 1 year (365 * 24 * 60 * 60 seconds)
RETURN u.name AS OldPasswordUser, datetime({epochSeconds: u.pwdlastset}) AS PasswordLastSetDate 
ORDER BY PasswordLastSetDate LIMIT 1000;

# 5.6 Find Users Who Can Add Members to Important Groups (e.g., Helpdesk can add to IT)
#     - Good for horizontal privilege escalation.
MATCH p=(u:User)-[:AddMember]->(g:Group) 
WHERE NOT g.name CONTAINS 'DOMAIN ADMINS' AND NOT g.name CONTAINS 'ENTERPRISE ADMINS'
RETURN p LIMIT 1000;

##
##

# BloodHound v7.x.x Cypher Queries Cheat Sheet
# For use in the 'CYPHER' tab of the BloodHound GUI.
# Replace 'CERTIFICATE.HTB' with your target domain (all caps) where necessary.

# --- BASIC ENUMERATION & OVERVIEW ---

# 1. Count All Nodes (Objects) in the Graph
#    - Quick check to see if data is loaded.
MATCH (n) RETURN count(n) AS TotalNodes;

# 2. List All Users (Basic Properties)
#    - See usernames, last logon, and if AS-REP Roasting is possible.
MATCH (u:User) RETURN u.name AS UserName, u.lastlogon AS LastLogon, u.donotreqpreauth AS ASREPRoastable, u.enabled AS EnabledStatus ORDER BY UserName LIMIT 1000;

# 3. List All Computers (Basic Properties)
#    - See computer names, OS, and if RDP/PSRemoting are enabled.
MATCH (c:Computer) RETURN c.name AS ComputerName, c.operatingsystem AS OS, c.enabledRDP AS RDPAccess, c.enabledPSRemoting AS PSRemotingAccess ORDER BY ComputerName LIMIT 1000;

# 4. List All Groups (Basic Properties)
#    - Overview of groups.
MATCH (g:Group) RETURN g.name AS GroupName, g.description AS Description ORDER BY GroupName LIMIT 1000;

# 5. List All Domains
#    - See all domains ingested.
MATCH (d:Domain) RETURN d.name AS DomainName LIMIT 10;

# 6. List All Organizational Units (OUs)
#    - Understand the domain's structure.
MATCH (ou:OU) RETURN ou.name AS OULocation LIMIT 100;

# --- PRIMARY ATTACK PATHS ---

# 7. Find Shortest Paths to Domain Admins (from any non-DA node)
#    - Your bread and butter. Finds the quickest ways to DA.
MATCH p=shortestPath((n)-[*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}))
WHERE NOT n = g
RETURN p;

# 8. Find Shortest Paths from a Specific Compromised User to Domain Admins
#    - Simulates starting from a user you've compromised (e.g., 'SARA.B@CERTIFICATE.HTB').
#    - Replace 'SARA.B@CERTIFICATE.HTB' with your initial foothold.
MATCH p=shortestPath((u:User {name:'SARA.B@CERTIFICATE.HTB'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}))
RETURN p;

# 9. Find Shortest Paths to Enterprise Admins (often root of forest)
#    - If you're in a multi-domain/forest environment.
MATCH p=shortestPath((n)-[*1..]->(g:Group {name:'ENTERPRISE ADMINS@CERTIFICATE.HTB'}))
WHERE NOT n = g
RETURN p;

# 10. Find Shortest Paths to High-Value Targets (e.g., specific sensitive servers/users)
#     - Replace 'SENSITIVESERVER@CERTIFICATE.HTB' or 'SENSIBLEUSER@CERTIFICATE.HTB'
MATCH p=shortestPath((n)-[*1..]->(t {name:'SENSITIVESERVER@CERTIFICATE.HTB'}))
WHERE NOT n = t
RETURN p;

# --- PRIVILEGE ESCALATION & INITIAL ACCESS ---

# 11. Find All Kerberoastable Accounts
#     - Users with SPNs that can be requested by any authenticated user for offline cracking.
MATCH (u:User {hasSPN:true, donotreqpreauth:false}) RETURN u.name AS KerberoastableAccount, u.serviceprincipalnames AS SPNs LIMIT 1000;

# 12. Find All AS-REP Roastable Accounts
#     - Users that do not require Kerberos preauthentication. Get their TGTs without password.
MATCH (u:User {donotreqpreauth:true}) RETURN u.name AS ASREPRoastableAccount LIMIT 1000;

# 13. Find Users with ForceChangePassword on Admins
#     - Users who can force password change on a target account, possibly leading to DA.
MATCH (u:User)-[:ForceChangePassword]->(t:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@CERTIFICATE.HTB'}) RETURN u.name AS AttackerUser, t.name AS AdminTarget;

# 14. Find Password Never Expires Accounts
#     - Good candidates for persistence/less frequent password changes.
MATCH (u:User {passwordneverexpires:true, enabled:true}) RETURN u.name AS UserWithNoPwdExpiration LIMIT 1000;

# 15. Find Users Who Can WriteDACL/WriteOwner/GenericAll/GenericWrite on Domain Controller
#     - Extremely critical privileges directly on the DC.
MATCH (u:User)-[r:WriteDACL|WriteOwner|GenericAll|GenericWrite]->(c:Computer {name:'DC01.CERTIFICATE.HTB'}) RETURN u.name AS Attacker, type(r) AS RelationshipType, c.name AS TargetDC;

# 16. Find Sensitive GPOs (Local Admins / RDP / PSRemoting)
#     - GPOs that grant privileges to hosts when linked to OUs.
MATCH (gpo:GPO) WHERE (gpo.localadmins OR gpo.rdp OR gpo.psremote) RETURN gpo.name AS GPO_Name, gpo.localadmins AS LocalAdmins, gpo.rdp AS RDPEnabled, gpo.psremote AS PSRemotingEnabled LIMIT 1000;

# --- LATERAL MOVEMENT & SESSIONS ---

# 17. Find All Active Sessions (Users logged into computers)
#     - Good for credential harvesting or token impersonation.
MATCH p=(u:User)-[:HasSession]->(c:Computer) RETURN p LIMIT 1000;

# 18. Find Computers with Admin Rights on Other Computers (AdminTo)
#     - Allows lateral movement between workstations/servers.
MATCH p=(c1:Computer)-[:AdminTo]->(c2:Computer) RETURN p LIMIT 1000;

# 19. Find Computers where RDP is Enabled
#     - Potential targets for Remote Desktop Protocol access.
MATCH (c:Computer {enabledRDP:true}) RETURN c.name AS RDPAccessibleComputer LIMIT 1000;

# 20. Find Computers where PSRemoting is Enabled
#     - Potential targets for PowerShell Remoting.
MATCH (c:Computer {enabledPSRemoting:true}) RETURN c.name AS PSRemotingAccessibleComputer LIMIT 1000;

# 21. Find Users with Explicit RDP Access to Computers
#     - Users directly granted RDP access.
MATCH p=(u:User)-[:CanRDP]->(c:Computer) RETURN p LIMIT 1000;

# --- DELEGATION & IMPERSONATION ---

# 22. Find Users with Constrained Delegation to Domain Controllers
#     - Highly dangerous if you can compromise such a user.
MATCH p=(u:User)-[:AllowedToDelegate]->(c:Computer {name:'DC01.CERTIFICATE.HTB'}) RETURN p LIMIT 1000;

# 23. Find Users with Unconstrained Delegation
#     - Compromise of such a user allows impersonation of *any* user authenticating to their host.
MATCH (u:User {unconstraineddelegation:true}) RETURN u.name AS UnconstrainedDelegationUser LIMIT 1000;

# 24. Find Domain Controllers vulnerable to Coercion (e.g., PetitPotam/PrinterBug)
#     - DCs that can be coerced to authenticate to an attacker, enabling NTLM relay.
MATCH (c:Computer {name:'DC01.CERTIFICATE.HTB'})-[:CoerceToTGT]->(d:Domain) RETURN c.name AS CoercibleDC, d.name AS Domain;

# --- DEFENSIVE / CLEANUP QUERIES ---

# 25. Find Accounts That Are Not Enabled (Should be disabled if not needed)
MATCH (u:User {enabled:false}) RETURN u.name AS DisabledUser LIMIT 1000;

# 26. Find Stale Computers (Not logged on recently)
MATCH (c:Computer) WHERE c.lastlogon < datetime({year:2024, month:1, day:1}) RETURN c.name AS StaleComputer, c.lastlogon AS LastLogonTime LIMIT 1000; # Adjust date

# 27. Find Empty Groups (If not used, should be removed for cleanliness)
MATCH (g:Group) WHERE NOT (g)<-[:MemberOf]-() RETURN g.name AS EmptyGroup LIMIT 1000;

# --- MORE ADVANCED / CUSTOM QUERIES ---

# 28. Find Paths from any User to any Administrator Group (more general than just Domain Admins)
MATCH p=shortestPath((u:User)-[*1..]->(g:Group) WHERE g.name ENDS WITH '@CERTIFICATE.HTB' AND (g.name CONTAINS 'ADMINS' OR g.name CONTAINS 'ADMINISTRATORS') RETURN p LIMIT 1000;

# 29. Find Paths from a Specific User to a Specific Target User/Computer
#     - Replace 'ATTACKER@CERTIFICATE.HTB' and 'TARGET@CERTIFICATE.HTB'
MATCH p=shortestPath((attacker {name:'ATTACKER@CERTIFICATE.HTB'})-[*1..]->(target {name:'TARGET@CERTIFICATE.HTB'})) RETURN p;

# 30. Find Users with Any Dangerous Privilege on a Specific Computer
#     - Replace 'TARGETCOMPUTER.CERTIFICATE.HTB'
MATCH (u:User)-[r:AdminTo|CanRDP|CanPSRemote|GenericAll|GenericWrite|WriteDACL|WriteOwner|ForceChangePassword]->(c:Computer {name:'TARGETCOMPUTER.CERTIFICATE.HTB'}) RETURN u.name AS PrivilegedUser, type(r) AS Privilege, c.name AS TargetComputer;

# 31. Enumerate All Users Who Can Control Other Users (GenericAll, GenericWrite, AllExtendedRights)
MATCH (u:User)-[r:GenericAll|GenericWrite|AllExtendedRights]->(t:User) RETURN u.name AS ControllingUser, type(r) AS Privilege, t.name AS TargetUser LIMIT 1000;

# 32. Find Service Accounts Not Managed By Microsoft
#     - Service accounts that are usually custom, and often misconfigured
MATCH (u:User) WHERE u.description IS NOT NULL AND u.description <> '' AND NOT u.description CONTAINS 'Microsoft' AND NOT u.description CONTAINS 'Windows' AND u.serviceprincipalnames IS NOT NULL RETURN u.name, u.description, u.serviceprincipalnames LIMIT 1000;

# 33. Find Domain Users with WriteProperty on Self (Password reset on self)
#     - These users often have special reset privileges over their own accounts
MATCH (u:User)-[r:WriteProperty]->(u) WHERE r.isacl = TRUE AND r.property = 'pwdlastset' RETURN u.name;

# 34. Find Password Sprayable Accounts
#     - Find enabled user accounts that haven't been logged into recently, often good targets for password spraying if password complexity is low
MATCH (u:User {enabled:true}) WHERE u.lastlogonTimestamp IS NULL OR u.lastlogonTimestamp < (datetime().epochSeconds - 604800) RETURN u.name AS PasswordSprayTarget, u.lastlogon AS LastLogonTime LIMIT 1000; # lastlogon < 1 week ago

# 35. Find Accounts That Can Access the Unprivileged Users OU
#     - Often a good starting point for internal enumeration
MATCH (u)-[r]->(ou:OU {name: 'USERS@CERTIFICATE.HTB'}) RETURN u.name AS UserWithAccess, type(r) AS RelationshipType, ou.name AS TargetOU LIMIT 100;
