# escape=`

FROM microsoft/windowsservercore

# Download Links:
ENV sql_express_download_url "https://go.microsoft.com/fwlink/?linkid=829176"
ENV sa_password="P@ssw0rd"

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

RUN cmd /c ipconfig
RUN cmd /c nslookup www.google.com 

RUN Invoke-WebRequest -Uri $env:sql_express_download_url -OutFile sqlexpress.exe ; `
    Start-Process -Wait -FilePath .\sqlexpress.exe -ArgumentList /qs, /x:setup ; `
    .\setup\setup.exe /q /ACTION=Install /INSTANCENAME=SQLEXPRESS /FEATURES=SQLEngine /UPDATEENABLED=0 /SQLSVCACCOUNT='NT AUTHORITY\\System' /SQLSYSADMINACCOUNTS='BUILTIN\\ADMINISTRATORS' /TCPENABLED=1 /NPENABLED=0 /IACCEPTSQLSERVERLICENSETERMS ; `
    Remove-Item -Recurse -Force sqlexpress.exe, setup

RUN stop-service MSSQL`$SQLEXPRESS ; `
    set-itemproperty -path 'HKLM:\\software\\microsoft\\microsoft sql server\\mssql14.SQLEXPRESS\\mssqlserver\\supersocketnetlib\\tcp\\ipall' -name tcpdynamicports -value '' ; `
    set-itemproperty -path 'HKLM:\\software\\microsoft\\microsoft sql server\\mssql14.SQLEXPRESS\\mssqlserver\\supersocketnetlib\\tcp\\ipall' -name tcpport -value 1433 ; `
    set-itemproperty -path 'HKLM:\\software\\microsoft\\microsoft sql server\\mssql14.SQLEXPRESS\\mssqlserver' -name LoginMode -value 2;

EXPOSE 1433

CMD .\start -sa_password $env:sa_password -ACCEPT_EULA $env:ACCEPT_EULA -Verbose

RUN Write-Verbose "Starting SQL Server" ; `
    start-service MSSQL`$SQLEXPRESS ; 

RUN Write-Verbose "Changing SA login credentials" ; `    
    &sqlcmd -Q "ALTER LOGIN sa with password=" +"'" + $env:sa_password + "'" + ";ALTER LOGIN sa ENABLE;" ;

RUN Invoke-WebRequest -Uri https://dotnetbinaries.blob.core.windows.net/servicemonitor/2.0.1.1/ServiceMonitor.exe -OutFile C:\ServiceMonitor.exe

ENTRYPOINT ["C:\\ServiceMonitor.exe", "MSSQL$SQLEXPRESS"]%  
