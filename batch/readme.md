## list available environment variables
SET
#Useful dynamic variables
%CD% %DATE% %TIME% %RANDOM% %ERRORLEVEL% %CMDEXTVERSION% %CMDCMDLINE% %HIGHESTNUMANODENUMBER%

#The environmental variable %ERRORLEVEL% contains the return code of the last executed program or script. 
IF %ERRORLEVEL% NEQ 0 (
  REM do something here to address the error
)
# To execute a follow-on command after sucess, we use the && operator:
SomeCommand.exe && ECHO SomeCommand.exe succeeded!

# To execute a follow-on command after failure, we use the || operator:
SomeCommand.exe || ECHO SomeCommand.exe failed with return code %ERRORLEVEL%

# A common technique is to use > to create/overwrite a log file, then use >> subsequently to append to the log file.
SomeCommand.exe   > temp.txt
OtherCommand.exe >> temp.txt

#Looping Through Files
FOR %I IN (%USERPROFILE%\*) DO @ECHO %I

#Looping Through Directories
FOR /D %I IN (%USERPROFILE%\*) DO @ECHO %I

#Recursively loop through files in all subfolders of the %TEMP% folder
FOR /R "%TEMP%" %I IN (*) DO @ECHO %I

#Recursively loop through all subfolders in the %TEMP% folder
FOR /R "%TEMP%" /D %I IN (*) DO @ECHO %I

##~ MAGIC
#The following syntax does correctly expand to the path of the current batch script.
 %~dp0                                                             //the path of current batch file. It ends with ‘\’
set testtools=%~dp0tools                            //
set testmode=%1                                          // the first parameter
set testtarget=%~f2                                      // the second parameter (full path to the file)
set testtargetdir=%~dp2                             // the second parameter (directory only)
#The magic variables %n contains the arguments used to invoke the file: %0 is the path to the bat-file itself, %1 is the first argument after, %2 is the second and so on. Since the arguments are often file paths, there is some additional syntax to extract parts of the path. ~d is drive, ~p is the path (without drive), ~n is the file name. They can be combined so ~dp is drive+path.  %~dp0 is therefore pretty useful in a bat: it is the folder in which the executing bat file resides.
#You can also get other kinds of meta info about the file: ~t is the timestamp, ~z is the size.
IF STATEMENT
IF EXIST filename …
IF %value% LSS 10 …
IF /I NOT “%string1%”==”string2” …
IF NOT ERRORLEVEL 1 …
IF %1 LSS 10 (
IF %2 GTR 0 (
ECHO %%1 is less than 10 AND %%2 is greater than 0
)
)
#Operator Meaning
EQU equal to
NEQ not equal to
LSS less than
LEQ less than or equal to
GTR greater than
GEQ greater than or equal to
#FOR LOOP
/D Indicates that the set contains directories.
/R Causes the command to be executed recursively through the sub-directories of an indicated parent directory
/L Loops through a command using starting, stepping, and ending parameters indicated in the set.
/F Parses files or command output in a variety of ways
for %%X in (set) do (command)
for %%X in (file1 file2 file3) do command
For %%X in (eenie meenie miney moe) do (echo %%X)
for %%X in (*.jpg) do command
for %%X in (*.jpg *.gif *.png *.bmp) do command
for /l %%X in (start, step, end) do command
for /l %%X in (1,1,99) do (echo %%X >> E:\numbers.txt)
#Working with directories
for /d %%X in (directorySet) do command
for /d %%X in (C:\*) do echo %%X
#Recursing through sub-directories
for /r C:\pictures %%X in (*.jpg) do (echo %%X >> E:\listjpg.txt)
for /f [options] %%X in (source) do command 

#MISC
set /p name= What is your name?  //prompt user to input

#to start multiple command windows

for /l %%x in (1, 1, 5) do (
    start cmd /c "cd / && dir /s && pause"
   )
 
 
 #to run some commands in each window, or just open them to the given path and with the given title
Code:
@echo off
start %SystemRoot%\system32\calc.exe
start "" "C:\Program Files\Pidgin\pidgin.exe"
start "" "C:\Program Files\Mozilla Firefox\firefox.exe"
Start "admin tool" cmd /k cd "C:\Development\VirtualTradingSystem\clean_trunk\tf-tradeweb"
Start "temp_pass.py" cmd /k cd "C:\Development\VirtualTradingSystem\clean_trunk\scripts"

#delete all files and sub folders
@echo off
#the path of current batch file. It ends with ‘\’
set basedir=%CD%
echo %basedir%
cd %CD%\.tmp
FOR /D %%p IN ("%CD%\*.*") DO rmdir "%%p" /s /q
del %CD%\* /F /Q
cd %basedir%
   
#Ionic app build steps
@echo off
making.vbs
call ionic build android --release
cd platforms\android\build\outputs\apk
C:\Users\JRAPARLA\Desktop\cordovacode\newapp\NexsCard\signing.vbs
del /F /Q nexscard.apk
call jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore nexscard.keystore android-release-unsigned.apk "nexscard" -storepass ppv-3333 -keypass ppv-3333
C:\Users\JRAPARLA\Desktop\cordovacode\newapp\NexsCard\packaging.vbs
call "C:\Program Files (x86)\Android\android-sdk\build-tools\23.0.1\zipalign" -v 4 android-release-unsigned.apk nexscard.apk
C:\Users\JRAPARLA\Desktop\cordovacode\newapp\NexsCard\complete.vbs
start .
cd %nexs%
