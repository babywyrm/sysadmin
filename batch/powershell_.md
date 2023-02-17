# A PowerShell cheatsheet

By @DanielLarsenNZ

## Comment-based help

> Windows PowerShell: Comment your way to help: <https://technet.microsoft.com/en-us/library/hh500719.aspx>

```powershell
<#
.SYNOPSIS
The synopsis goes here. This can be one line, or many.

.DESCRIPTION
The description is usually a longer, more detailed explanation of what the
script or function does. Take as many lines as you need.

.PARAMETER computername
Here, the dotted keyword is followed by a single parameter name. Don't precede
that with a hyphen. The following lines describe the purpose of the parameter

.PARAMETER filePath
Provide a PARAMETER section for each parameter that your script or function
accepts.

.EXAMPLE
There's no need to number your examples.

.EXAMPLE
PowerShell will number them for you when it displays your help text to a user.
#>
```

## Params

I collect `param` examples.

```powershell
# [CmdletBinding()] attribute allows common parameters (-Verbose, -ErrorAction, etc) to be passed through
[CmdletBinding()]
param (
    [string] $OptionalStringParam,
    [string] $OptionalStringParamWithDefault = 'Default',
    [Parameter(Mandatory = $true)] [string] $MandatoryStringParam,
    [Parameter(Mandatory = $true, HelpMessage="Enter a help message here"))] [string] $MandatoryStringParamWithHelpMessage,
    [ValidateSet('Incremental', 'Complete')] [string] $ValidateSetParam,
    [ValidateSet('Incremental', 'Complete')] [string] $ValidateSetParamWithDefault = 'Incremental',
    [switch] $SwitchParam,
    [string] $DefaultValuesCanBeExpressions = (New-Guid),
    [string] $DefaultValuesCanBeEnvVars = $ENV:BUILD_ID,
    [ValidatePattern('^https?://')] [string] $ValidatePatternsAreCool,
    [ValidateScript({ Test-Path -PathType Leaf -Path $_ })] $ValidateScriptsAreBananas
)
```

## Strings

`Split-Path` is handy.

```powershell
# Get the folder from a path
$path = 'C:\r\examples'
$folderName = Split-Path $path -Leaf #> 'examples'

# Get the path from a path+filename
$filePath = 'C:\r\examples\README.md'
$folderName = Split-Path $filePath #> 'C:\r\examples'

# Get the filename from a path+filename
$filePath = 'C:\r\examples\README.md'
$folderName = Split-Path $filePath -Leaf #> 'README.md'
```

## Arrays

Create an Array

```PowerShell
$a = "one", "two", "three"

# in an argument list this syntax may be more convenient:
Set-FooBar -Items ("one", "two", "three")
```

Append an Array

```PowerShell
# Create an array
$a = "one", "two", "three"

# Append another array. Creates a new array (yay!)
$b = $a += "four", "five", "six"
```

Array Join

```PowerShell
# create an array of strings
$a = "one", "two", "three"
# join concatenated with a comma
$a -join ','
# output = one,two,three
```

`ArrayList` is a handy type for manipulating arrays:

```PowerShell
[System.Collections.ArrayList]$a = "one", "two", "three"
$a.AddRange(("four", "five", "six"))
```

> Watch out for `Get-ChildItem` - it will return a single File if one item found, or and Array of File if
> more than one item found. To force returning an array every time, surround with an array syntax: `@( )`

```PowerShell
[System.Collections.ArrayList]$files = @( Get-ChildItem C:\Temp -recurse -include '*.bak' )

```

> Everything you wanted to know about arrays: <https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-arrays?view=powershell-7.1>

> Get-ChildItem in PowerShell: <http://www.kanasolution.com/2010/12/get-childitem-in-powershell/>

## For loops

Simple.

```powershell
for ($i = 0; $i -lt 10; $i++) 
{
    "$i"
}
```

Multiple counter variables and repeat statements!

```powershell
for (($i = 0), ($j = 0); $i -lt 10; ($i++), ($j++))
{
    "`$i:$i"
    "`$j:$j"
}
```

Multiple conditions.

```powershell
for (($i = 0), ($j = 0); $i -lt 10 -and $j -lt 10; ($i++), ($j++))
{
    "`$i:$i"
    "`$j:$j"
}
```

> 📖 https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_for?view=powershell-6

## For-each loops

Some traps for young players here... `ForEach-Object` and `foreach()` are different.

Use `foreach()` like C# or JavaScript, e.g.

```PowerShell
foreach($file in $files) {
    Write-Verbose($file)
}
```

If you pipe to `foreach` it simply acts as an alias for `ForEach-Object`. With the non-pipeline version
(`foreach()`) the `break` statement will exit the `foreach` loop. However if you break in the pipeline
version, it will exit the script(!). This can catch you out if you accidentally use the pipeline version
by using the `foreach` statement in a pipeline. Here are some examples to illustrate:

```PowerShell
# this will break to the next statement after the foreach loop:
$bakfile = $null
foreach($file in $files) {
    if ($file.Name.Contains('.bak')) {
        $bakfile
        break
    }
}

if ($bakfile -ne $null){
    Write-Host "Found $bakfile"
}

# this will exit the script
$files | ForEach-Object {
    Write-Verbose $_
    break
}

# so will this!
$files | foreach {
    Write-Verbose $_
    break
}
```

In PowerShell 4 there is a ForEach method on a Collection.

> `break` statement : <http://ss64.com/ps/break.html>

> `ForEach` method: <http://ss64.com/ps/foreach-method.html>

## ForEach parallel

This changed in PowerShell 7.

```powershell
    param (
        [string] $BaseUrl
    )
    
    "/health", "/parts", "/orders", "/dispatches", "/users" | ForEach -Parallel {  
        $response = Invoke-WebRequest -Method Get -Uri "$($using:BaseUrl)$($_)" -UseBasicParsing
        $body = ConvertFrom-Json $response.Content
        
        Write-Output "GET $($path): HTTP Status = $($response.StatusCode), version = $($body.version)"
    }
```

> 📖 https://devblogs.microsoft.com/powershell/powershell-foreach-object-parallel-feature/

## Switch statements

`switch` is _amazing_ in PowerShell.

```powershell
# Simple switch
switch ($_.type) {
    'vm' { "VM SKU = $($_.sku)" }
    'sqlDb' { "DB tier = $($_.tier)" }
    default { throw "Type ""$($_.type)"" is not supported" }
}
```

A case can evaluate an expression.

```powershell
switch ($_) {
    { $_.type -eq 'vms' -and $_.action -eq 'allow' } { "Allow VM SKUs $($_.skus)" }
    default { throw "policy type = ""$($_.type)"" action = ""$($_.action)"" is not supported." }
}
```

You can also do Regex on case matches...

> <https://technet.microsoft.com/en-us/library/ff730937.aspx>

> <https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.core/about/about_switch>

## Map

`%` is shorthand for `foreach` so you can map quite elegantly like this:

```PowerShell
$filenames = $files | % { $_.FullName }
# $filenames is an Array of string
```

> Select / map PowerShell: <http://stackoverflow.com/a/8909031>

## Ternary operator / conditional expression / inline if / `iif`

There is no ternary operator in the traditional sense. However, there is an elegant
conditional expression syntax that can be used inline with setting a variable (and
many other operations):

```powershell
$rg = if ($Prod) { 'scaffold-prod-rg' } else { 'scaffold-nonprod-rg' }
```

## Get-Random

Best named cmdlet ever! 😂

```powershell
# Generate a random number between 0 - 255
Get-Random --Maximum 255
```

## Custom objects

Better than Hash Tables!

Add properties to PSObjects that will be formatted nicely

```powershell
$result = New-Object -TypeName PSObject
$result | Add-Member -Name Command -MemberType NoteProperty -Value 'GetGroup' 
$result | Add-Member -Name DurationSeconds -MemberType NoteProperty -Value 1.01

$result | Format-Table

# Output:
Command  DurationSeconds
-------  ---------------
GetGroup            1.01
```

Add behaviour (methods) to custom objects:

```powershell
# Mock proxy.ListChildren (!)
$mockProxy = New-Object -TypeName PSObject
$mockProxy | Add-Member -Name ListChildren -MemberType ScriptMethod `
    -Value { return @( @{ Name = 'Report1'; TypeName = 'Folder' } ) }
```

> <https://stackoverflow.com/a/14836102>

As of PowerShell 5 you can use a PowerShell `class` to create objects in a similar
way as in C#: <https://trevorsullivan.net/2014/10/25/implementing-a-net-class-in-powershell-v5/>

## Files

Write the output of any command to a File

```powershell
Get-Process | Out-File -Path ./processes.txt
```

Silently remove any folder named 'obj' or 'bin'

```powershell
Remove-Item **/obj -Recurse -Force
Remove-Item **/bin -Recurse -Force
```

## .NET interop

Wrap a call to a .NET object in a `try` `catch` block to force Exceptions to terminate
(if that is the behaviour you want).

```powershell
try { $items = $proxy.ListChildren($folder, $False) } catch { throw }
```

`$items` will still be in scope even if instantiated inside the `try` block :\

> <https://stackoverflow.com/questions/17847276/is-an-exception-from-a-net-method-a-terminating-or-not-terminating-error>

## JSON

Here is a cool way to generate JSON objects (thanks petern!). First create the object 
dynamically and then use the `ConvertTo-JSON` cmdlet:

```PowerShell
$customer = @{
    Id = 'abc123'
    Email = @{
            Address = 'alice@localtest.me'
            Verified = $true
    }
    PhoneNumbers = ('555-1234', '555-1235', '555-1236')
}

ConvertTo-Json $customer
```

Output:

```JavaScript
{
    "Email":  {
                  "Verified":  true,
                  "Address":  "alice@localtest.me"
              },
    "Id":  "abc123",
    "PhoneNumbers":  [
                         "555-1234",
                         "555-1235",
                         "555-1236"
                     ]
}
```

Take the JSON result of an `az` CLI command, convert to a PowerShell object and assign the value of a property to a variable:

```powershell
$instrumentationKey = ( az monitor app-insights component create --app 'myapp-insights' `
    --location $location --resource-group $rg | ConvertFrom-Json ).instrumentationKey
```

## XML

### Load, parse and read an XML document

```powershell
[xml] $xml = Get-Content -Path $ConfigFile
Write-Output  $xml.configuration.appSettings.add | Where-Object -FilterScript { $_.key -eq 'Setting1' }
```

## Call RMDIR from PowerShell to delete `node_modules`

Deleting npm `node_modules` directories on Windows can be a pain due to the [260 character MAX_PATH limitation]. The DOS RMDIR command handles long paths _slightly_ better. You can invoke RMDIR from PowerShell like this:

```powershell
& cmd /c rmdir node_modules /s /q
```

> Tip: You can fix this problem once and for all in Windows 10 by setting `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled`

[260 character MAX_PATH limitation]:https://msdn.microsoft.com/en-us/library/aa365247%28VS.85%29.aspx?f=255&MSPPError=-2147217396#maxpath

## Invoke MSBUILD, SQLPackage, etc

This is tricky in PowerShell if you have dynamic arguments, but a nice workaround
is that the Call operator `&` takes an array of arguments, so you can do this:

```powershell
$sqlpackageExe = "$PSScriptRoot\SQLPackage.exe"

# initialise arguments
$arguments = @("/Action:Publish")

# append arguments
# NOTE: Do not double-quote arguments even if they have spaces in them
$arguments += @( `
    "/SourceFile:$DacpacFile"; `
    "/TargetServerName:$SqlServerName"; `
    "/TargetDatabaseName:$DatabaseName"; `
    )

# map and append an array of variables
$variables = name1=value1, name2=value2
$arguments += $variables | % { "/v:$_" }

# call sqlpublish with arguments
& $sqlpackageExe $arguments
```

> <http://stackoverflow.com/a/869867>

## `copy con`

```powershell
$content = @'
{
    "how": {
                "cool": "is PowerShell!"
            }
}
'@

Set-Content -Value $content -Encoding UTF8 -Path C:\ProgramData\Docker\abc123.json
```

## WinRM

Here be dragons, but once you get it working you wonder what all of the fuss was
about.

### To setup a _client_ for WinRM

```PowerShell
# The first time:
Enable-PSRemoting -Force
Set-Item "wsman:\localhost\client\trustedhosts" -Value "*" -Force  # Be  specific in Prod

# And then
$creds = Get-Credential localadmin
Enter-PSSession -Computername 10.10.1.6 -Credential $creds
```

### Copy files

```PowerShell
$session = New-PSSession -ComputerName MEMBERSRV1

# Copy file to the remote host
Copy-Item C:\test.xml -ToSession $session -Destination C:\config

# Copy file from the remote host
Copy-Item -FromSession $session -Path c:\logs\u_ex170406.log -Destination C:\Temp
```

> Matt Wrocks on WinRM: <http://www.hurryupandwait.io/blog/understanding-and-troubleshooting-winrm-connection-and-authentication-a-thrill-seekers-guide-to-adventure>
> and some tips for Windows Server 2016 Nano: <http://www.hurryupandwait.io/blog/a-packer-template-for-windows-nano-server-weighing-300mb>

> Sending Files Over WinRM: <http://www.tomsitpro.com/articles/powershell-send-files-over-winrm,2-886.html>

## Other tricks

Open a new Powershell Console Window from Powershell

```powershell
start powershell

# start in a particular folder
start powershell -WorkingDirectory c:\r
```

## More cheatsheets

PowerShell equivalents for common Linux/bash commands: <https://mathieubuisson.github.io/powershell-linux-bash/>

[other ways too]:https://blogs.technet.microsoft.com/uktechnet/2016/06/20/parallel-processing-with-powershell/
