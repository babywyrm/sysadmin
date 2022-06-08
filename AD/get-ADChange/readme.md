# Get-ADChange

The files in this gist are designed to query Active Directory for recently changed objects. The files should go in the same folder and make sure the .ps1xml format file is saved as `adchange.format.ps1xml`. You can then dot source the script file:

```powershell
. c:\scripts\get-adchange.ps1
```

Obviously, use the appropriate path. The script will also load the format file into your PowerShell session. You should be able to run the `Get-ADChange` command from a Windows 10 desktop that has the ActiveDirectory module installed.

```powershell
 Get-ADChange -Category user,group -Since 9:00AM -IncludeDeletedObjects
 ```

These files are explained at [https://jdhitsolutions.com/blog/powershell/8097/building-a-powershell-tool-for-active-directory-changes/](https://jdhitsolutions.com/blog/powershell/8097/building-a-powershell-tool-for-active-directory-changes/).

*_DO NOT USE IN A PRODUCTION ENVIRONMENT UNTIL YOU HAVE TESTED THOROUGHLY IN A LAB ENVIRONMENT. USE AT YOUR OWN RISK.  IF YOU DO NOT UNDERSTAND WHAT THIS SCRIPT DOES OR HOW IT WORKS, DO NOT USE IT OUTSIDE OF A SECURE, TEST SETTING._*
