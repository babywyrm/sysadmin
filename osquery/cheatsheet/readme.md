##
#
https://gist.github.com/githubfoam/0babb95da5845b8d4ee41f5711de637a
#
##

SELECT * FROM block_devices;

SELECT * FROM users WHERE gid < 65534 AND uid >= 1000;

# finds all users who have actual login shells 
SELECT * FROM users WHERE shell NOT LIKE '%false' AND shell NOT LIKE '%true';
SELECT * FROM users WHERE shell="/bin/bash"

#Querying the socket_events table
SELECT pid, remote_address AS address, 
  remote_port AS port, family, path, time AS timestamp
FROM socket_events
WHERE remote_address <> ""
  AND remote_port != 0
  AND pid > 0;

#all the open socket connections in use by processes on the system
# all the inbound and outbound connections to and from running processes
SELECT pos.pid, local_address, local_port, 
  remote_address, remote_port, family, protocol, 
  COALESCE(NULLIF(pos.path,''), p.path) AS path
FROM process_open_sockets AS pos
INNER JOIN processes AS p ON p.pid = pos.pid
WHERE remote_address <> ""
  AND remote_port != 0
  AND pos.pid > 0
LIMIT 5;

#open ports on a system
SELECT DISTINCT p.pid, p.name, l.port
FROM listening_ports AS l
JOIN processes ON l.pid = p.pid
WHERE l.address = '0.0.0.0';

# Search for the browser extensions running Chrome.The following query eliminates duplicates, and shows all extensions for all users
SELECT DISTINCT c.name, u.username
FROM users u
JOIN chrome_extensions c USING (uid)
ORDER BY c.name;

#Shows who is currently logged in to a system.
SELECT liu.*, p.name, p.cmdline, p.cwd, p.root
FROM logged_in_users liu, processes p
WHERE liu.pid = p.pid;

#listening ports
SELECT p.name, address, port, family, protocol, 
  COALESCE(NULLIF(pos.path,''), p.path) AS path
FROM listening_ports AS pos
INNER JOIN processes AS p ON p.pid = pos.pid
WHERE address <> ""
  AND port != 0
  AND pos.pid > 0
LIMIT 5;

#information about the specified file on disk
SELECT file.path, users.username AS owner,
groups.groupname AS groups,
datetime(file.btime,'unixepoch') AS created,
datetime(file.mtime,'unixepoch') AS last_mod,
ROUND((file.size * 10e-7),4) AS size_mb
FROM file
JOIN users USING (uid)
JOIN groups USING (gid)
WHERE path LIKE '/home/%/Downloads/%%'
ORDER BY last_mod DESC;

#shell_history,search for the executed commands on the system.
SELECT uid,
username,
shell,
command
FROM users
JOIN shell_history USING (uid);

#sudo rules present on a system.
SELECT * FROM sudoers;
SELECT * FROM sudoers WHERE rule_details LIKE '%ALL';

#querying the last table
select * from last ;

#IPTables firewall
select * from iptables ;
select chain, policy, src_ip, dst_ip from iptables ;

#type of jobs are scheduled in crontab
select command, path from crontab ;

#files on the system that are setuid-enabled
select * from suid_bin ;

#list of loaded kernel modules
select name, used_by, status from kernel_modules where status="Live" ;

#find backdoors on the server is to run a query that lists all the listening ports
select * from listening_ports ;

# file activity on the server
select target_path, action, uid from file_events ;

# audited socket events
sudo osqueryi --audit_allow_config=true --audit_allow_sockets=true --audit_persist=true --disable_events=false

#CTI, DFIR, Debian
Finding new processes listening on network ports; malware listens on port to provide command and control (C&C) or direct shell access,query periodically and diffing with the last ‘known good’
osquery> SELECT DISTINCT process.name, listening.port, listening.address, process.pid FROM processes AS process JOIN listening_ports AS listening ON process.pid = listening.pid;

Finding suspicious outbound network activity; any processes that do not fit within whitelisted network behavior, e.g. a process scp’ing traffic externally when it should only perform HTTP(s) connections outbound
osquery> select s.pid, p.name, local_address, remote_address, family, protocol, local_port, remote_port from process_open_sockets s join processes p on s.pid = p.pid where remote_port not in (80, 443) and family = 2;

Finding processes that are running whose binary has been deleted from the disk;any process whose original binary has been deleted or modified;attackers leave a malicious process running but delete the original binary on disk.
osquery> SELECT name, path, pid FROM processes WHERE on_disk = 0;

Finding new kernel modules which was loaded; query periodically and diffing against older results,kernel modules can be checked against a whitelist/blacklist , rootkits
osquery> select name from kernel_modules;

view a list of loaded kernel modules; query periodically and compare its output against older results to see if anything’s changed
osquery> select name, used_by, status from kernel_modules where status="Live" ;

Finding malware that have been scheduled to run at specific intervals
osquery> select command, path from crontab ;

Finding backdoored binaries; files on the system that are setuid-enabled, any that are not supposed to be on the system, query periodically and compare its results against older results so that you can keep an eye on any additions.
osquery> select * from suid_bin ;

Finding backdoors; query that lists all the listening ports, output includes those ports that the server should be listening on
osquery> select * from listening_ports ;

all recent file activity on the server
osquery> select target_path, action, uid from file_events ;

osquery> .show

view mode of query results
osquery> .mode csv
osquery> .mode list
osquery> .mode column
osquery> .mode line

list all available tables
osquery> .tables

query table "file_events" if exists
osquery> .schema file_events

osquery> .schema users
CREATE TABLE users(`uid` BIGINT, `gid` BIGINT, `uid_signed` BIGINT, `gid_signed` BIGINT, `username` TEXT, `description` TEXT, `directory` TEXT, `shell` TEXT, `uuid` TEXT, `type` TEXT HIDDEN, `is_hidden` INTEGER HIDDEN, PRIMARY KEY (`uid`, `username`)) WITHOUT ROWID;

osquery> .schema processes
CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `path` TEXT, `cmdline` TEXT, `state` TEXT, `cwd` TEXT, `root` TEXT, `uid` BIGINT, `gid` BIGINT, `euid` BIGINT, `egid` BIGINT, `suid` BIGINT, `sgid` BIGINT, `on_disk` INTEGER, `wired_size` BIGINT, `resident_size` BIGINT, `total_size` BIGINT, `user_time` BIGINT, `system_time` BIGINT, `disk_bytes_read` BIGINT, `disk_bytes_written` BIGINT, `start_time` BIGINT, `parent` BIGINT, `pgroup` BIGINT, `threads` INTEGER, `nice` INTEGER, `is_elevated_token` INTEGER HIDDEN, `elapsed_time` BIGINT HIDDEN, `handle_count` BIGINT HIDDEN, `percent_processor_time` BIGINT HIDDEN, `upid` BIGINT HIDDEN, `uppid` BIGINT HIDDEN, `cpu_type` INTEGER HIDDEN, `cpu_subtype` INTEGER HIDDEN, `phys_footprint` BIGINT HIDDEN, PRIMARY KEY (`pid`)) WITHOUT ROWID;
osquery>

show details about the system hardware
osquery> SELECT * FROM system_info;

osquery> SELECT * FROM os_version;
osquery> SELECT * FROM kernel_info;
osquery> SELECT * FROM kernel_modules LIMIT 5;

Checking Repository and Packages

osquery> SELECT * FROM apt_sources;
osquery> SELECT name, base_uri, release, maintainer, components FROM apt_sources ORDER BY name;
osquery> SELECT * FROM deb_packages;
osquery> SELECT name, version FROM deb_packages ORDER BY name;
osquery> SELECT name, version FROM deb_packages WHERE name="unzip";

List the users
osquery> SELECT * FROM users;
who else other than you is logged into the system now
osquery> select * from logged_in_users ;
previous logins
osquery> select * from last ;

If there’s no output, then it means the IPTables firewall has not been configured.
osquery> select * from iptables ;
osquery> select chain, policy, src_ip, dst_ip from iptables ;

Get The Process Name, Port, and PID for All Processes
osquery> SELECT DISTINCT processes.name, listening_ports.port, processes.pid FROM listening_ports JOIN processes USING (pid);

top 10 most active processes count, name
osquery> select count(pid) as total, name from processes group by name order by total desc limit 10;

top 10 largest processes by resident memory size
osquery> select pid, name, uid, resident_size from processes order by resident_size desc limit 10;

osquery> select pid, name,cmdline from processes where uid=1002;

osquery> SELECT address FROM etc_hosts WHERE hostnames = 'localhost';
osquery> SELECT * FROM arp_cache;

osquery> select time, severity, message from syslog ;

Centos osquery,list of all installed RPM packages
osquery> .all rpm_packages;
SELECT * FROM block_devices;

SELECT * FROM users WHERE gid < 65534 AND uid >= 1000;

# finds all users who have actual login shells 
SELECT * FROM users WHERE shell NOT LIKE '%false' AND shell NOT LIKE '%true';
SELECT * FROM users WHERE shell="/bin/bash"

#Querying the socket_events table
SELECT pid, remote_address AS address, 
  remote_port AS port, family, path, time AS timestamp
FROM socket_events
WHERE remote_address <> ""
  AND remote_port != 0
  AND pid > 0;

#all the open socket connections in use by processes on the system
# all the inbound and outbound connections to and from running processes
SELECT pos.pid, local_address, local_port, 
  remote_address, remote_port, family, protocol, 
  COALESCE(NULLIF(pos.path,''), p.path) AS path
FROM process_open_sockets AS pos
INNER JOIN processes AS p ON p.pid = pos.pid
WHERE remote_address <> ""
  AND remote_port != 0
  AND pos.pid > 0
LIMIT 5;

#open ports on a system
SELECT DISTINCT p.pid, p.name, l.port
FROM listening_ports AS l
JOIN processes ON l.pid = p.pid
WHERE l.address = '0.0.0.0';

# Search for the browser extensions running Chrome.The following query eliminates duplicates, and shows all extensions for all users
SELECT DISTINCT c.name, u.username
FROM users u
JOIN chrome_extensions c USING (uid)
ORDER BY c.name;

#Shows who is currently logged in to a system.
SELECT liu.*, p.name, p.cmdline, p.cwd, p.root
FROM logged_in_users liu, processes p
WHERE liu.pid = p.pid;

#listening ports
SELECT p.name, address, port, family, protocol, 
  COALESCE(NULLIF(pos.path,''), p.path) AS path
FROM listening_ports AS pos
INNER JOIN processes AS p ON p.pid = pos.pid
WHERE address <> ""
  AND port != 0
  AND pos.pid > 0
LIMIT 5;

#information about the specified file on disk
SELECT file.path, users.username AS owner,
groups.groupname AS groups,
datetime(file.btime,'unixepoch') AS created,
datetime(file.mtime,'unixepoch') AS last_mod,
ROUND((file.size * 10e-7),4) AS size_mb
FROM file
JOIN users USING (uid)
JOIN groups USING (gid)
WHERE path LIKE '/home/%/Downloads/%%'
ORDER BY last_mod DESC;

#shell_history,search for the executed commands on the system.
SELECT uid,
username,
shell,
command
FROM users
JOIN shell_history USING (uid);

#sudo rules present on a system.
SELECT * FROM sudoers;
SELECT * FROM sudoers WHERE rule_details LIKE '%ALL';

#querying the last table
select * from last ;

#IPTables firewall
select * from iptables ;
select chain, policy, src_ip, dst_ip from iptables ;

#type of jobs are scheduled in crontab
select command, path from crontab ;

#files on the system that are setuid-enabled
select * from suid_bin ;

#list of loaded kernel modules
select name, used_by, status from kernel_modules where status="Live" ;

#find backdoors on the server is to run a query that lists all the listening ports
select * from listening_ports ;

# file activity on the server
select target_path, action, uid from file_events ;

# audited socket events
sudo osqueryi --audit_allow_config=true --audit_allow_sockets=true --audit_persist=true --disable_events=false

#CTI, DFIR, Debian
Finding new processes listening on network ports; malware listens on port to provide command and control (C&C) or direct shell access,query periodically and diffing with the last ‘known good’
osquery> SELECT DISTINCT process.name, listening.port, listening.address, process.pid FROM processes AS process JOIN listening_ports AS listening ON process.pid = listening.pid;

Finding suspicious outbound network activity; any processes that do not fit within whitelisted network behavior, e.g. a process scp’ing traffic externally when it should only perform HTTP(s) connections outbound
osquery> select s.pid, p.name, local_address, remote_address, family, protocol, local_port, remote_port from process_open_sockets s join processes p on s.pid = p.pid where remote_port not in (80, 443) and family = 2;

Finding processes that are running whose binary has been deleted from the disk;any process whose original binary has been deleted or modified;attackers leave a malicious process running but delete the original binary on disk.
osquery> SELECT name, path, pid FROM processes WHERE on_disk = 0;

Finding new kernel modules which was loaded; query periodically and diffing against older results,kernel modules can be checked against a whitelist/blacklist , rootkits
osquery> select name from kernel_modules;

view a list of loaded kernel modules; query periodically and compare its output against older results to see if anything’s changed
osquery> select name, used_by, status from kernel_modules where status="Live" ;

Finding malware that have been scheduled to run at specific intervals
osquery> select command, path from crontab ;

Finding backdoored binaries; files on the system that are setuid-enabled, any that are not supposed to be on the system, query periodically and compare its results against older results so that you can keep an eye on any additions.
osquery> select * from suid_bin ;

Finding backdoors; query that lists all the listening ports, output includes those ports that the server should be listening on
osquery> select * from listening_ports ;

all recent file activity on the server
osquery> select target_path, action, uid from file_events ;

osquery> .show

view mode of query results
osquery> .mode csv
osquery> .mode list
osquery> .mode column
osquery> .mode line

list all available tables
osquery> .tables

query table "file_events" if exists
osquery> .schema file_events

osquery> .schema users
CREATE TABLE users(`uid` BIGINT, `gid` BIGINT, `uid_signed` BIGINT, `gid_signed` BIGINT, `username` TEXT, `description` TEXT, `directory` TEXT, `shell` TEXT, `uuid` TEXT, `type` TEXT HIDDEN, `is_hidden` INTEGER HIDDEN, PRIMARY KEY (`uid`, `username`)) WITHOUT ROWID;

osquery> .schema processes
CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `path` TEXT, `cmdline` TEXT, `state` TEXT, `cwd` TEXT, `root` TEXT, `uid` BIGINT, `gid` BIGINT, `euid` BIGINT, `egid` BIGINT, `suid` BIGINT, `sgid` BIGINT, `on_disk` INTEGER, `wired_size` BIGINT, `resident_size` BIGINT, `total_size` BIGINT, `user_time` BIGINT, `system_time` BIGINT, `disk_bytes_read` BIGINT, `disk_bytes_written` BIGINT, `start_time` BIGINT, `parent` BIGINT, `pgroup` BIGINT, `threads` INTEGER, `nice` INTEGER, `is_elevated_token` INTEGER HIDDEN, `elapsed_time` BIGINT HIDDEN, `handle_count` BIGINT HIDDEN, `percent_processor_time` BIGINT HIDDEN, `upid` BIGINT HIDDEN, `uppid` BIGINT HIDDEN, `cpu_type` INTEGER HIDDEN, `cpu_subtype` INTEGER HIDDEN, `phys_footprint` BIGINT HIDDEN, PRIMARY KEY (`pid`)) WITHOUT ROWID;
osquery>

show details about the system hardware
osquery> SELECT * FROM system_info;

osquery> SELECT * FROM os_version;
osquery> SELECT * FROM kernel_info;
osquery> SELECT * FROM kernel_modules LIMIT 5;

Checking Repository and Packages

osquery> SELECT * FROM apt_sources;
osquery> SELECT name, base_uri, release, maintainer, components FROM apt_sources ORDER BY name;
osquery> SELECT * FROM deb_packages;
osquery> SELECT name, version FROM deb_packages ORDER BY name;
osquery> SELECT name, version FROM deb_packages WHERE name="unzip";

List the users
osquery> SELECT * FROM users;
who else other than you is logged into the system now
osquery> select * from logged_in_users ;
previous logins
osquery> select * from last ;

If there’s no output, then it means the IPTables firewall has not been configured.
osquery> select * from iptables ;
osquery> select chain, policy, src_ip, dst_ip from iptables ;

Get The Process Name, Port, and PID for All Processes
osquery> SELECT DISTINCT processes.name, listening_ports.port, processes.pid FROM listening_ports JOIN processes USING (pid);

top 10 most active processes count, name
osquery> select count(pid) as total, name from processes group by name order by total desc limit 10;

top 10 largest processes by resident memory size
osquery> select pid, name, uid, resident_size from processes order by resident_size desc limit 10;

osquery> select pid, name,cmdline from processes where uid=1002;

osquery> SELECT address FROM etc_hosts WHERE hostnames = 'localhost';
osquery> SELECT * FROM arp_cache;

osquery> select time, severity, message from syslog ;

Centos osquery,list of all installed RPM packages
osquery> .all rpm_packages;
