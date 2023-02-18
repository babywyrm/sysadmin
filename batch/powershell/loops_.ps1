Elementary Powershell loop with conditions
Code_Snip_Elementary_Loop_1.ps1
$NARemotePort="0"
$NARemoteAddress="::","127.0.0.1"
$Array=""
Code_Snip_Elementary_Loop_2.ps1
ForEach ($OutIPPort in (Get-NetTCPConnection | Sort-Object -Property RemotePort)){...}
Code_Snip_Elementary_Loop_3.ps1
if ($OutIPPort.RemotePort -in $NARemotePort -or $OutIPPort.RemoteAddress -in $NARemoteAddress) {}
Code_Snip_Elementary_Loop_4.ps1
else{
    $IPName=Get-Process -id $OutIPPort.OwningProcess | Select-Object Name;
    
    $REMP=Resolve-DnsName $OutIPPort.RemoteAddress -ErrorAction SilentlyContinue | Select-Object NameHost
Code_Snip_Elementary_Loop_5.ps1
if($REMP.NameHost -eq $null) {$NameHost= "No record"} else {$NameHost=$REMP.NameHost}
Code_Snip_Elementary_Loop_6.ps1
    $Detail1= $IPName.Name
    $Detail2=$OutIPPort.OwningProcess
    $Detail3=$OutIPPort.RemoteAddress
    $Detail4=$NameHost
    $Detail5=$OutIPPort.RemotePort
Code_Snip_Elementary_Loop_7.ps1
   Write-Output "$Detail1  $Detail2  $Detail3  $Detail4  $Detail5"
Elementary_Powershell_loop_with_conditions.ps1
# License: GNU General Public License v2.0
# Author: Miguel 
# Website: www.techlogist.net
# Post: https://techlogist.net/powershell/elementary-powershell-loop-with-conditions/
# Description: Elementary Powershell loop with conditions
# OS/Language: Windows/EN-US

#Example of powershell loop with error fix
#Set the ports which will not be resolved

$NARemotePort="0"
$NARemoteAddress="::","127.0.0.1"

#Optain the properties 

ForEach ($OutIPPort in (Get-NetTCPConnection | Sort-Object -Property RemotePort)){
    
    if ($OutIPPort.RemotePort -in $NARemotePort -or $OutIPPort.RemoteAddress -in $NARemoteAddress) { }
    
    else{
    $IPName=Get-Process -id $OutIPPort.OwningProcess | Select-Object Name;
    
    $REMP=Resolve-DnsName $OutIPPort.RemoteAddress -ErrorAction SilentlyContinue | Select-Object NameHost
    
    if($REMP.NameHost -eq $null) {$NameHost= "No record"} else {$NameHost=$REMP.NameHost}

    #Define the output variables

    $Detail1=$IPName.Name
    $Detail2=$OutIPPort.OwningProcess
    $Detail3=$OutIPPort.RemoteAddress
    $Detail4=$NameHost
    $Detail5=$OutIPPort.RemotePort

    #Output the result

    Write-Output "$Detail1  $Detail2  $Detail3  $Detail4  $Detail5"

        }
    }
