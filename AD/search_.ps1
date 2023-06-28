# Powershell script designed to be run on Windows 7 workstations and above. 

# Gets the following information which is useful in a pentest:
#  * A list of domain users (useful for finding intersting comments
#  * A list of shares in the domain (typically includes all Windows workstations/servers connected to the domain)
#  * A list of ACLs for each share, in a nice HTML table that can be copy/pasted into Word
#  * A list of files/directories in the root of each share
#  * A full recursive directory listing of each share (useful for finding interesting file names)
#  * A search for files containing specific strings. This often takes a long long time, hence is optional
 
$dir = "$env:temp\search"
$listingsdir = "$dir\dirlistings"
$date = Get-Date -UFormat "%Y%m%d_%H%M_%S"
$logfile = "$dir\log_$date.out"
$sharefile = "$dir\shares_$date.out"
$shareauditfile = "$dir\share_audit_$date.html"
$usersfile = "$dir\users_$date.out"
$passwordfile = "$dir\passwordsearch_$date.out"
$timeout = 4
# Change the following to $FALSE if you don't want to search for passwords
$dopasswordsearch = $TRUE

# Regex for optional password search
$filestosearch = ("*.txt","*.vbs","*.bat","*.xlsx","*.xls","*.docx","*.doc","*.sql","*.conf","*.ini","*.reg")
$pattern = ("user","pass","svc\.","admin")

# Simple logging funciton
function log ($message) {
    $message
    $message | Out-File -Append $logfile
}

md -ErrorAction SilentlyContinue -Path $dir
log -message "Output directory: $dir"

# Dumping users
log -message "Using WMIC to get a list of users ..."
wmic useraccount > $usersfile
log -message "WMIC completed."

# The 'net view' command
log -message "Running net view ..." 
$nv = net view
log -message "Net view completed." 

# An array to store all shares (strings)
$shares = @()

# An array to store all share objects
$shareobjects = @()

# Loop through the servers
foreach ($line in $nv) {
    # Extract the server names from the net view command
    if ($line -match "\\\\([^ ]+) ") {
        $server = $matches[1]

        log -message "Querying $server for shares ..."
		
	# List shares, killing the net view if it takes too long
        # NB we're using net view here, as it works nice with low privs on old boxes
        $job = start-job -ArgumentList $server { param($server) net view \\$server /all}
        sleep $timeout
        $result = Receive-Job -Job $job
        Stop-Job -Job $job

        log -message "Query of $server complete."
	foreach ($share in $result) {
	    if ($share -match "([^ ]+) +Disk +") {
		$name =  $matches[1]
		log -message "Found share \\$server\$name"
		$shares += "\\$server\$name"
		"\\$server\$name" | Out-File -Append $sharefile
	    }
	}
    }
}

foreach ($share in $shares) {

    if (Test-path $share) {
        $acl = get-acl $share | select -expandproperty access | out-string
    }
    else {
        $acl = "No Access"
        continue
    }
    
    log -message "Getting directory listing from the root of the share..."
    $files = Get-ChildItem -ErrorAction SilentlyContinue $share | select -expandproperty name  | out-string
    
    $shareobject = new-object -typename PSObject -Property @{
    'share' = $share
    'files' = $files
    'acl' = $acl
    }
    
    $shareobjects += $shareobject
    
    log -message "Doing full directory listing of $share..."
    $sharefilename = "$listingsdir" + ($share -replace "\\", "_") + "_$date.txt"
    dir -ErrorAction SilentlyContinue -recurse $share | Select -ExpandProperty FullName | Out-File $sharefilename
    log -message "Directory listing of $share completed."
}

# Making pretty HTML output...
# Order the properties of the object, so the output table is created correctly
$shareobjects = $shareobjects | select share,files,acl
# Change the table cells to include <pre> tags
$shareobjects | convertto-html | foreach {if($_ -like "*<td>*") {$_ -replace "<td>","<td><pre>"} elseif ($_ -like "*</td>*") {$_ -replace "</td>","</pre></td>"} else {$_} }| out-file $shareauditfile

# Optional password search
if ($dopasswordsearch) {
    log -message "Doing optional password search ..."
    foreach ($share in $shares) { 
        log -message "Finding passwords in $share ..."
        get-childitem  -path $share -ErrorAction SilentlyContinue -include $filestosearch -recurse | select-string -pattern $pattern | select -unique path | format-table -hidetableheaders | out-file -Append $passwordfile
    }
    log -message "Password search complete."
}

#####
#####

A collection of PowerShell scripts for finding unused files
directory-summary.ps1
function directory-summary($dir=".") { 
  get-childitem $dir | 
    % { $f = $_ ; 
        get-childitem -r $_.FullName | 
           measure-object -property length -sum | 
             select @{Name="Name";Expression={$f}},Sum}
}
Get-NeglectedFiles.ps1
Function Get-NeglectedFiles

{

 Param([string[]]$path,

       [int]$numberDays)

 $cutOffDate = (Get-Date).AddDays(-$numberDays)

 Get-ChildItem -Path $path -r |

 Where-Object {$_.LastAccessTime -le $cutOffDate}

}
usage.md
in powershell load the scripts:

directory-summary {path} where {path} is the path to get folder size of
Get-NeglectedFiles -path c:\fso -numberDays 60 | select name, lastaccesstime
delete files older than 60 days: dir |? {$_.CreationTime -lt (get-date).AddDays(-60)} | del

##
##
