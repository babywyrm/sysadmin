#requires -version 5.1
#requires -module ActiveDirectory

# Learn more about PowerShell: http://jdhitsolutions.com/blog/essential-powershell-resources/

Function Get-ADChange {
    [cmdletbinding()]
    [outputtype("ADChange")]
    [alias("gadc")]

    Param (
        [Parameter(Position = 0, HelpMessage = "Enter a last modified datetime for AD objects. The default is the last 4 hours.")]
        [ValidateNotNullOrEmpty()]
        [datetime]$Since = ((Get-Date).AddHours(-4)),
        [Parameter(HelpMessage = "Specify the types of objects to query.")]
        [ValidateSet("User","Group","Computer","OU")]
        [ValidateNotNullOrEmpty()]
        [string[]]$Category = "User",
        [Parameter(HelpMessage = "Include deleted objects if the AD Recycle Bin feature has been enabled.")]
        [switch]$IncludeDeletedObjects,
        [Parameter(HelpMessage = "Specifies an Active Directory path to search under.")]
        [string]$SearchBase,
        [Parameter(HelpMessage = "Specifies the Active Directory Domain Services domain controller to query. The default is your Logon server.")]
        [alias("DC")]
        [ValidateNotNullorEmpty()]
        #[ArgumentCompleter({(Get-ADDomain).ReplicaDirectoryServers})]
        [string]$Server = $env:LOGONSERVER.SubString(2),
        [Parameter(HelpMessage = "Specify an alternate credential for authentication.")]
        [alias("runas")]
        [pscredential]$Credential,
        [ValidateSet("Negotiate", "Basic")]
        [string]$AuthType
    )

    #an internal version number for this function
    $ver = [version]"1.2.0"
    Function _ConvertToLDAPTime {
        #a private helper function to convert a date time object into a LDAP query-compatible value
        Param([datetime]$Date)
        $offset = (Get-TimeZone).baseUtcOffset
        #values must be formatted with leading zeros to the specified number of decimal places
        $tz = "{0:d2}{1:d2}" -f $offset.hours,$offset.Minutes
        "{0:yyyyMMddhhmmss}.0{1}" -f $date,$tz
    }

    Write-Verbose "[$(Get-Date)] Starting $($MyInvocation.MyCommand) version $ver"
    Write-Verbose "[$(Get-Date)] Using these bound parameters:"
    $PSBoundParameters | Out-String | Write-Verbose

    #display some runtime metadata with Verbose output
    Write-Verbose "[$(Get-Date)] Running as: $($env:USERDOMAIN)\$($env:USERNAME) from $env:COMPUTERNAME"
    Write-Verbose "[$(Get-Date)] Operating System: $(Get-ItemPropertyValue -path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -name ProductName)"
    Write-Verbose "[$(Get-Date)] PowerShell: v$($PSVersionTable.PSVersion)"

    #get the current datetime to use as a reporting date for the changed objects
    $ReportDate = Get-Date
    #build a hashtable of parameters to splat to Get-ADObject
    $getParams = @{
        ErrorAction = 'Stop'
        Server      = $Server
        Properties  = 'WhenCreated','WhenChanged','Description','DisplayName'
    }

    $params = "Credential", "AuthType","SearchBase","IncludeDeletedObjects"
    ForEach ($param in $params) {
       if ($PSBoundParameters.ContainsKey($param)) {
            Write-Verbose "[$(Get-Date)] Adding parameter $param"
            $getParams.Add($param,$PSBoundParameters.Item($param))
        }
    }

    if ($Credential.username) {
         Write-Verbose "[$(Get-Date)] Using alternate credentials for $($credential.username)"
    }
    if ($SearchBase) {
        Write-Verbose "[$(Get-Date)] Searching from $SearchBase"
    }
    if ($IncludeDeleted) {
        Write-Verbose "[$(Get-Date)] Including deleted items in the search"
    }

    Write-Verbose "[$(Get-Date)] Filtering for changed objects since '$since' from $($server.toUpper())"

    #define a list to hold search results
    $items = [System.Collections.Generic.list[object]]::new()

    #convert the $Since value to an LDAP compatible value
    $dt = _ConvertToLDAPTime -Date $Since

    Try {
        #go through each category
        foreach ($objClass in $Category) {
        <#
            filtering on object types using an LDAP filter because Computer is derived from the User class
            and I want to be able to distinguish between the two. Instead of a single complex filtering query based on
            object types or categories, I'll just run the query for each requested objectclass.
        #>
            Switch ($objclass) {
                "User"     { $ldap = "(&(WhenChanged>=$dt)(objectclass=user)(!(objectclass=computer)))" }
                "Computer" { $ldap = "(&(WhenChanged>=$dt)(objectclass=computer))"}
                "Group"    { $ldap = "(&(WhenChanged>=$dt)(objectclass=group))"}
                "OU"       { $ldap = "(&(WhenChanged>=$dt)(objectclass=organizationalunit))"}
            }
            Write-Verbose "[$(Get-Date)] Using LDAP filter $ldap"
            $getparams["LDAPFilter"] = $ldap
            Get-ADObject @getParams | Foreach-Object { $items.Add($_)}
        }
    }
    Catch {
        Write-Warning "[$(Get-Date)] Failed to query Active Directory. $($_.Exception.Message)."
    }

    if ($items.count -gt 0) {
        Write-Verbose "[$(Get-Date)] Found $($items.count) items."
        #add custom properties and insert a new type name
        foreach ($item in $items) {
            if ($item.WhenCreated -ge $since) {
                $isNew = $True
            }
            else {
                $isNew = $false
            }
            #create a custom object based on each search result
            [PSCustomObject]@{
                PSTypeName        = "ADChange"
                ObjectClass       = $item.ObjectClass
                ObjectGuid        = $item.ObjectGuid
                DistinguishedName = $item.DistinguishedName
                Name              = $item.Name
                DisplayName       = $item.DisplayName
                Description       = $item.Description
                WhenCreated       = $item.WhenCreated
                WhenChanged       = $item.WhenChanged
                IsNew             = $IsNew
                IsDeleted         = $item.Deleted
                Container         = $item.distinguishedname.split(",", 2)[1]
                DomainController  = $Server.toUpper()
                ReportDate        = $ReportDate
            }
        } #foreach item
    }
    else {
        Write-Warning "[$(Get-Date)] No changed objects found that match your criteria."
    }

    Write-Verbose "[$(Get-Date)] Ending $($MyInvocation.MyCommand)"
} #end function

#define a default set of properties
Update-TypeData -TypeName ADChange -DefaultDisplayPropertySet DistinguishedName,WhenCreated,WhenChanged,IsNew,IsDeleted,ObjectClass,ReportDate -Force
#define some alias properties for the custom object
Update-TypeData -TypeName ADChange -MemberType AliasProperty -MemberName class -Value ObjectClass -Force
Update-TypeData -TypeName ADChange -MemberType AliasProperty -MemberName DN -Value DistinguishedName -Force

#load a custom formatting file which has additional custom views of container and class
#It is assumed the format file is in the same directory as this file.
Update-FormatData $PSScriptRoot\ADchange.format.ps1xml
