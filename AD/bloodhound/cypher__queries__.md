# BloodHound v7.x.x Cypher Queries Cheat Sheet ( Beta Edition )
# For use in the 'CYPHER' tab of the BloodHound GUI.
# Replace 'TARGET.EDU' with your target domain (all caps) where necessary.

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
