# Windows Batch Scripting Reference Guide ( ..2025, updated.. )

## Table of Contents
- [Environment Variables](#environment-variables)
- [Core Concepts](#core-concepts)
- [Control Flow](#control-flow)
- [Loops](#loops)
- [Functions & Subroutines](#functions--subroutines)
- [String Manipulation](#string-manipulation)
- [File Operations](#file-operations)
- [Best Practices](#best-practices)

---

## Environment Variables

### Viewing Environment Variables
```bash
SET
```

### Useful Dynamic Variables
```bat
%CD%                    :: Current directory
%DATE%                  :: Current date
%TIME%                  :: Current time
%RANDOM%                :: Random number (0-32767)
%ERRORLEVEL%            :: Last command exit code
%CMDEXTVERSION%         :: Command processor version
%CMDCMDLINE%            :: Command line that invoked cmd.exe
%HIGHESTNUMANODENUMBER% :: Highest NUMA node number
```

### Special Path Variables
```bat
%~dp0                   :: Drive and path of current batch file (ends with \)
%~f0                    :: Full path to current batch file
%~n0                    :: Filename without extension
%~x0                    :: File extension only
```

### Working with Parameters
```bat
%0                      :: Script name
%1-%9                   :: First through ninth parameters
%*                      :: All parameters
%~f1                    :: Full path of first parameter
%~dp1                   :: Drive and path of first parameter
%~n1                    :: Filename only of first parameter
```

---

## Core Concepts

### Basic Script Structure
```bat
@echo off
setlocal enabledelayedexpansion

:: Your code here

endlocal
exit /b 0
```

### Variable Assignment
```bat
:: String assignment
set myVar=hello

:: Arithmetic assignment
set /a result=10+5

:: Prompt user for input
set /p userName=What is your name? 

:: Multi-line string (with line breaks preserved)
set "multiLine=First line^
Second line^
Third line"
```

### Using Delayed Expansion
```bat
:: Without delayed expansion (wrong)
set count=0
set /a count=%count%+1
echo %count%               :: Always shows 0

:: With delayed expansion (correct)
setlocal enabledelayedexpansion
set count=0
set /a count=!count!+1
echo !count!               :: Shows 1
endlocal
```

---

## Control Flow

### Error Handling
```bat
:: Check last command success
SomeCommand.exe
if %ERRORLEVEL% neq 0 (
    echo Command failed with code %ERRORLEVEL%
    exit /b 1
)

:: Execute on success
SomeCommand.exe && echo Success!

:: Execute on failure
SomeCommand.exe || echo Failed with code %ERRORLEVEL%

:: Chain commands
command1 && command2 && command3
```

### If Statements
```bat
:: String comparison
if "%var%" == "value" echo Match found

:: Case-insensitive comparison
if /i "%var%" == "VALUE" echo Match found (case-insensitive)

:: Numeric comparison
if %num% lss 10 echo Less than 10
if %num% leq 10 echo Less than or equal to 10
if %num% gtr 10 echo Greater than 10
if %num% geq 10 echo Greater than or equal to 10
if %num% equ 10 echo Equal to 10
if %num% neq 10 echo Not equal to 10

:: File/directory existence
if exist "C:\file.txt" echo File exists
if not exist "C:\file.txt" echo File does not exist

:: Logical AND (sequential if statements)
if "%1" == "" if "%2" == "" (
    echo Both parameters missing
    exit /b 1
)

:: Logical OR (using flag variable)
set condition=false
if "%1" neq "" set condition=true
if "%2" neq "" set condition=true
if "!condition!" == "true" echo At least one parameter provided
```

### Ternary-style Operations
```bat
:: Single-line if-else
if %num% gtr 5 (echo Greater) else (echo Not greater)

:: Using goto for complex logic
if "%1" == "option1" (goto :option1) else (goto :option2)

:option1
echo Handling option 1
goto :end

:option2
echo Handling option 2
goto :end

:end
```

---

## Loops

### For Loop - Basic
```bat
:: Loop through items
for %%i in (item1 item2 item3) do echo %%i

:: Loop through files
for %%f in (*.txt) do echo %%f

:: Loop through multiple file types
for %%f in (*.txt *.log *.csv) do echo %%f
```

### For Loop - Numeric Range
```bat
:: Count from 1 to 10
for /l %%i in (1,1,10) do echo %%i

:: Count from 10 to 1 (backwards)
for /l %%i in (10,-1,1) do echo %%i

:: Count by 5s from 0 to 100
for /l %%i in (0,5,100) do echo %%i
```

### For Loop - Directories
```bat
:: Loop through directories only
for /d %%d in (C:\*) do echo %%d

:: Recursively loop through subdirectories
for /r "C:\MyFolder" /d %%d in (*) do echo %%d
```

### For Loop - Recursive File Search
```bat
:: Find all .jpg files recursively
for /r "C:\Pictures" %%f in (*.jpg) do echo %%f

:: Process files recursively
for /r "%TEMP%" %%f in (*) do (
    echo Processing: %%f
)
```

### For Loop - Parsing Files/Output
```bat
:: Read lines from file
for /f "tokens=*" %%l in (file.txt) do echo %%l

:: Skip first line (header)
for /f "skip=1 tokens=*" %%l in (file.txt) do echo %%l

:: Parse command output
for /f "tokens=*" %%o in ('dir /b /a-d') do echo %%o

:: Parse CSV (tokens 1 and 3, delimited by comma)
for /f "tokens=1,3 delims=," %%a in (data.csv) do (
    echo Column 1: %%a
    echo Column 3: %%b
)

:: Use multiple delimiters (comma and space)
for /f "tokens=1,2 delims=, " %%a in (data.txt) do echo %%a %%b
```

---

## Functions & Subroutines

### Basic Subroutine
```bat
@echo off
setlocal enabledelayedexpansion

call :greet World
exit /b 0

:greet
echo Hello, %1!
exit /b 0
```

### Subroutine with Return Value
```bat
@echo off
setlocal enabledelayedexpansion

call :add 5 3 result
echo 5 + 3 = !result!

exit /b 0

:add
setlocal enabledelayedexpansion
set /a sum=%1+%2
endlocal & set %3=%sum%
exit /b 0
```

### Advanced - Multiple Return Values
```bat
@echo off
setlocal enabledelayedexpansion

call :calculate 10 3
echo Sum: !sum!
echo Product: !product!

exit /b 0

:calculate
setlocal enabledelayedexpansion
set /a tempSum=%1+%2
set /a tempProduct=%1*%2
endlocal & set sum=%tempSum% & set product=%tempProduct%
exit /b 0
```

### Error Handling in Subroutines
```bat
call :divide 10 2 result
if !errorlevel! neq 0 (
    echo Division failed
    exit /b 1
)
echo Result: !result!
exit /b 0

:divide
setlocal enabledelayedexpansion
if "%2" == "0" (
    echo ERROR: Division by zero
    exit /b 1
)
set /a quotient=%1/%2
endlocal & set %3=%quotient%
exit /b 0
```

---

## String Manipulation

### Substrings
```bat
set str=Hello World

:: Extract substring (start, length)
echo %str:~0,5%          :: Output: Hello
echo %str:~6%            :: Output: World
echo %str:~-5%           :: Output: World (last 5 chars)
echo %str:~0,-6%         :: Output: Hello (all but last 6)
```

### Find and Replace
```bat
set str=Hello World

:: Replace substring
echo %str:World=Universe%    :: Output: Hello Universe
echo %str: =_%               :: Output: Hello_World

:: Remove substring
echo %str:World=%            :: Output: Hello 
```

### String Length
```bat
set str=Hello
set len=0
:lenLoop
if not "!str:~%len%!" == "" set /a len+=1 & goto :lenLoop
echo Length: %len%
```

---

## File Operations

### Redirecting Output
```bat
:: Overwrite file
command > output.txt

:: Append to file
command >> output.txt

:: Redirect stderr
command 2> errors.txt

:: Redirect both stdout and stderr
command > output.txt 2>&1

:: Suppress output
command > nul 2>&1
```

### File and Directory Tests
```bat
if exist "file.txt" echo File exists
if exist "C:\Folder\" echo Directory exists (note trailing backslash)
if not exist "file.txt" echo File does not exist
```

### Delete Files and Folders
```bat
:: Delete files (force, quiet)
del /f /q "file.txt"

:: Delete all files in directory
del /f /q "C:\Temp\*.*"

:: Remove directory and all contents
rmdir /s /q "C:\Temp\OldFolder"

:: Delete files and subdirectories in current location
for /d %%d in (*) do rmdir /s /q "%%d"
del /f /q *
```

---

## Best Practices

### 1. Always Use Delayed Expansion
```bat
setlocal enabledelayedexpansion
:: Use !var! instead of %var% for variables that change
endlocal
```

### 2. Avoid Spaces in Assignments
```bat
:: Wrong
set var = value

:: Correct
set var=value
```

### 3. Quote Paths and Strings
```bat
:: Prevents issues with spaces
if exist "C:\Program Files\App\app.exe" echo Found

set "path=C:\Program Files\My App"
```

### 4. Use Single-Line If Statements
```bat
:: Preferred (more predictable)
if %x% == 1 echo Match
if %x% == 1 exit /b 1

:: Avoid blocks when possible
if %x% == 1 (
    echo Match
    exit /b 1  :: May not behave as expected
)
```

### 5. Check Parameters Safely
```bat
:: Use quotes to handle missing parameters
if "%1" == "" (
    echo Missing parameter
    exit /b 1
)
```

### 6. Proper Exit Codes
```bat
:: Success
exit /b 0

:: Failure
exit /b 1

:: Specific error code
exit /b 2
```

### 7. Log Operations
```bat
echo [%date% %time%] Starting operation >> operation.log
command >> operation.log 2>&1
if %errorlevel% neq 0 (
    echo [%date% %time%] ERROR: Operation failed >> operation.log
    exit /b 1
)
echo [%date% %time%] Operation completed >> operation.log
```

### 8. Use Descriptive Variable Names
```bat
:: Bad
set x=value

:: Good
set configFilePath=C:\Config\app.config
```

---

## Complete Example Script
```bat
@echo off
setlocal enabledelayedexpansion

:: Script configuration
set "scriptDir=%~dp0"
set "logFile=%scriptDir%script.log"

:: Log function
call :log "Script started"

:: Check parameters
if "%1" == "" (
    call :log "ERROR: Missing required parameter"
    echo Usage: %~nx0 ^<parameter^>
    exit /b 1
)

:: Main logic
call :processFile "%1"
if !errorlevel! neq 0 (
    call :log "ERROR: Processing failed"
    exit /b 1
)

call :log "Script completed successfully"
endlocal
exit /b 0

:: === Subroutines ===

:log
echo [%date% %time%] %~1 >> "%logFile%"
echo [%date% %time%] %~1
exit /b 0

:processFile
setlocal enabledelayedexpansion
set "file=%~1"

if not exist "!file!" (
    call :log "ERROR: File not found: !file!"
    exit /b 1
)

:: Process file here
call :log "Processing: !file!"

endlocal
exit /b 0
```

