Function Get-ImportProgress($ImportID)
{
 $ImportStatus = Get-EC2ImportImageTask -ImportTaskID $ImportID
 Write-Host " "
 Write-Host "Import ID:" $ImportID

 while(($ImportStatus.Status -ne "completed") -and ($ImportStatus.Status -ne "deleted") -and ($ImportStatus.StatusMessage -notmatch "ServerError"))
 {
  Write-Host " "
  Write-Host $ImportStatus.Status ":" $ImportStatus.StatusMessage " "
  $ImportStatus_Status = $ImportStatus.Status
  $ImportStatus_Message = $ImportStatus.StatusMessage

  $dotcount = 1
  while(($ImportStatus.Status -eq $ImportStatus_Status) -and ($ImportStatus.StatusMessage -eq $ImportStatus_Message))
  {
   Write-Host "." -NoNewLine
   Start-Sleep -m 500
   $dotcount++
   if($dotcount -eq 30){ Write-Host ""; $dotcount=1 }
   $ImportStatus = Get-EC2ImportImageTask -ImportTaskID $ImportID
  }
  
  $ImportStatus = Get-EC2ImportImageTask -ImportTaskID $ImportID
 }

 Write-Host " "
 if($ImportStatus.Status -eq "completed")
 {
  Write-Host "Import is complete!"
 }
 if($ImportStatus.Status -eq "deleted")
 {
  Write-Host "Import FAILED.  Image was deleted!"
  Write-Host "Error:" $ImportStatus.StatusMessage
  Stop-EC2ImportTask -ImportTaskID $ImportID
 }
 if($ImportStatus.StatusMessage -match "ServerError:")
 {
  Write-Host "Import ERROR:" $ImportStatus.StatusMessage
  Stop-EC2ImportTask -ImportTaskID $ImportID
 }
}

Function Get-FileName($initialDirectory)
{

 if(!($initialDirectory)){
  $initialDirectory = "C:\"
 }
 [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
 Out-Null

 $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
 $OpenFileDialog.initialDirectory = $initialDirectory
 $OpenFileDialog.filter = "Image files (*.ova) | *.ova"
 $OpenFileDialog.ShowDialog() | Out-Null
 $OpenFileDialog.filename
}

Set-ExecutionPolicy Unrestricted -Force
Import-Module "C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.psd1"

# Preset AWS Credentials (Optional)
$AccessKey = ""
$PrivateKey = ""
$Region = ""

# If AWS security parameters exist great, if not - ask for them
if(!($AccessKey)) { $AccessKey = Read-Host -Prompt "AWS Access Key" } else { Write-Host "AWS Access Key given." }
if(!($PrivateKey)) { $PrivateKey = Read-Host -Prompt "AWS Private Key" } else { Write-Host "AWS Private Key given." }
if(!($region)) { $region = Read-Host -Prompt "AWS Region" } else { Write-Host "AWS region given." }

Set-AWSCredentials -AccessKey $AccessKey -SecretKey $PrivateKey -StoreAs "VMImport"
Initialize-AWSDefaults -ProfileName "VMimport" -Region $region

$iamRolecheck = Get-IAMRole -RoleName "vmimport"

if(!($iamRolecheck)) {
$importServiceRole = @"
    {
    "Version":"2012-10-17",
    "Statement":[
        {
            "Sid":"",
            "Effect":"Allow",
            "Principal":{
                "Service":"vmie.amazonaws.com"
            },
            "Action":"sts:AssumeRole",
            "Condition":{
                "StringEquals":{
                "sts:ExternalId":"vmimport"
                }
            }
        }
    ]
    }
"@
"Creating IAM Role"
New-IAMRole -RoleName vmimport -AssumeRolePolicyDocument $importServiceRole
} else { Write-Host "IAM Role Already Exists." }

Write-Host "Checking for OVA file variables ..."
if(!($diskName)) {
  if(!($diskPath)) { 
    $initialPath = "C:\Users\" + [Environment]::UserName + "\Desktop"
    $file = Get-FileName -initialDirectory $initialPath
  } else { $file = Get-FileName -initialDirectory $diskPath }
$diskName = split-path $file -leaf
$diskPath = split-path $file -Parent
Echo $diskname
Echo $diskPath
}

if(!($AMIplatform)) { $AMIplatform = Read-Host -Prompt "AMI Platform type (Windows/Linux)" } else { Write-Host "Platform type set to $AMIplatform type!" }

# Regex reply to ensure proper platform type is recorded
switch -regex ($AMIplatform)
{
    '\AW\Z|\Aw\Z|\AWindows\Z|\Awindows\Z|\Awin\Z' { $AMIplatform = "Windows"; break }
    '\AL\Z|\Al\Z|\ALinux\Z|\Alinux\Z|\Anix\Z' { $AMIplatform = "Linux"; break }
    default { $AMIplatform = "Windows"; Write-Host "Platform selection invalid - Setting to default Windows platform!"; break }
}

if(!($bucketName)) { $bucketName = Read-Host -Prompt "Destination S3 Bucket: " } else { Write-Host "S3 Bucket set to $bucketName" }

$BucketQuery = Get-S3Bucket -BucketName $bucketName -Region $region

# If S3 Bucket does not exist, create it... 
if(!($BucketQuery)){
   Echo "S3 Bucket Was not there, creating..."
   New-S3bucket -BucketName $bucketName -Region $region
}
# If S3 Bucket exists, notify and keep going... 
else{ Write-Host "S3 Bucket exists!"
}

# If license type is not defined, prompt for choice...
if(!($LicenseType)) { $LicenseType = Read-Host -Prompt "License Style (A)WS or (B)YOL " }

# Once license type is decided, assign proper value to variable for later use
switch -regex ($LicenseType) {
    '\AA\Z|\AAWS\Z|\Aa\Z|\Aaws\Z' { $LicenseType = "AWS"; break}
    '\AB\Z|\ABYOL\Z|\Ab\Z|\Abyol\Z' { $LicenseType = "BYOL"; break }
    default { $LicenseType = "AWS"; write-host "Licensing selection invalid - Setting to default AWS licensing!"; break }
}

Write-Host "License type is set to : $LicenseType"

Write-S3Object -File $file -BucketName $bucketName
$userBucket = New-Object Amazon.EC2.Model.UserBucket
$userBucket.S3Bucket = $bucketName
$userBucket.S3Key = $diskName
$diskContainer = New-Object Amazon.EC2.Model.ImageDiskContainer
$diskContainer.Format = "ova"
$diskContainer.UserBucket = $userBucket
$importDate =   (Get-Date)
"Setup Import Parameters"
$params = @{
    "LicenseType"=$LicenseType
    "ClientToken"=$diskName +"_"+ $importDate
    "Description"="Import of $diskName on $importDate "
    "Platform"=$AMI_platform
    "Region"=$region
}
"Importing $diskName into EC2"
Import-EC2Image -DiskContainer $diskContainer @params | % { $ImportID = $_.ImportTaskId }

Get-ImportProgress -ImportID $ImportID
