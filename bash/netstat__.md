


On OS X, the process id along with a lot of other info can be can be shown using the verbose `-v` flag:
  * `sudo netstat -anlv |grep -e Address -e LISTEN` - will display the LISTENing processes along with the column header
  
This variant outputs a comman-delimited list of the processes that are LISTENing:
  * `sudo netstat -anlv |grep  -e LISTEN | awk '{print $9}'| sort -nu| tr "\n" "," | sed s/,$//`
  
This can also be done using `lsof` - perhaps easier because it displays both the Command and PID:
  * `sudo lsof -iTCP -sTCP:LISTEN -n -P`

  
```
sudo lsof -iTCP -sTCP:LISTEN -n -P | awk 'NR>1 {print $9, $1, $2}' | sed 's/.*://' | while read port process pid; do echo "Port $port: $(ps -p $pid -o command= | sed 's/^-//') (PID: $pid)"; done | sort -n
```


1. Find and Kill a Process by Name:
```
pgrep -f "process_name" | xargs -r kill -9
```

Explanation: Finds all processes matching "process_name" and forcefully kills them.
2. Show Disk Usage of Directories at the Root Level:
```
du -sh /* 2>/dev/null | sort -h
```

Explanation: Displays the size of each directory in the root directory, sorted by size.
3. Monitor a Command’s Output in Real-Time:
```
watch -n 1 'command_to_monitor'
```

Explanation: Runs the specified command every second, updating the output in real-time.
4. Find Files Modified in the Last X Minutes:
```
find /path/to/search -type f -mmin -X
```
Explanation: Finds files in the specified path modified in the last X minutes.
5. Backup a File with a Timestamp:
```
cp filename{,.bak.$(date +%F-%T)}
```
Explanation: Creates a backup of filename with a timestamp appended to it.
6. Get External IP Address:
```
curl -s ifconfig.me
```
Explanation: Fetches your external IP address using an online service.
7. List Files with Permissions, Sizes, and Timestamps:
```
ls -lh --time-style=+"%Y-%m-%d %H:%M:%S"
```
Explanation: Lists files with detailed info including human-readable sizes and custom timestamp format.
8. Check the Top 10 Processes by Memory Usage:
```
ps aux --sort=-%mem | head -n 11
```
Explanation: Lists the top 10 processes consuming the most memory.
9. Show All Open Files by a Specific User:
```
lsof -u username
```
Explanation: Lists all open files for the specified user.
10. Extract IP Addresses from a Log File:

```bash
grep -oP '(\d{1,3}\.){3}\d{1,3}' logfile | sort | uniq -c | sort -nr
```
- **Explanation:** Finds and counts unique IP addresses in a log file, sorted by frequency.
11. Get the 10 Largest Files in a Directory and Subdirectories:
bash
Copy code
```bash
find /path/to/dir -type f -exec du -h {} + | sort -rh | head -n 10
```
- **Explanation:** Lists the 10 largest files in the specified directory and its subdirectories.
12. List Active Network Connections with Process Info:
javascript
Copy code
```bash
sudo netstat -tunlp
```
- **Explanation:** Displays active TCP/UDP connections along with process information.
13. Recursively Change File Extensions in a Directory:
r
Copy code
```bash
find /path/to/dir -name "*.old" -exec rename 's/\.old$/\.new/' {} +
```
- **Explanation:** Recursively changes file extensions from `.old` to `.new` in the specified directory.
14. Monitor File Changes in a Directory in Real-Time:
go
Copy code
```bash
inotifywait -m /path/to/dir
```
- **Explanation:** Monitors the specified directory for changes in real-time.
15. List Open Network Ports and Associated Processes:
swift
Copy code
```bash
sudo ss -tuln | awk 'NR>1 {print $4, $1, $7}' | sed 's/.*://; s/:.*//' | sort -n
```
- **Explanation:** Lists open network ports along with the protocol and process ID.
- 
