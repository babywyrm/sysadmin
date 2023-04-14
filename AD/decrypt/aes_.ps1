
function Decrypt-AES {
    param(
        [Parameter(Mandatory=$true)]
        [string]$EncryptedText,
        
        [Parameter(Mandatory=$true)]
        [string]$Key
    )
    
    $AESProvider = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $AESProvider.Key = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $AESProvider.IV = [byte[]]@(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10)

    $Decryptor = $AESProvider.CreateDecryptor()

    $EncryptedBytes = [Convert]::FromBase64String($EncryptedText)
    $DecryptedBytes = $Decryptor.TransformFinalBlock($EncryptedBytes, 0, $EncryptedBytes.Length)
    $DecryptedText = [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)

    Write-Host $DecryptedText
}

//
//
//

$EncryptedText = "YOUR_ENCRYPTED_TEXT"
$Key = "YOUR_KEY"
Decrypt-AES -EncryptedText $EncryptedText -Key $Key

//
//
//
