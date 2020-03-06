+++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++

Examples
First you will need to import your packages

import os
import subprocess
import shutil
from pprint import pprint
Here are some examples of common file and directory operations.

# Get your current working directly
# This returns a string
my_cwd = os.getcwd()
print(my_cwd)
# List the contents of a directory
# This returns a list
dir_list = os.listdir()
for item in dir_list:
    print(item)
# Get the Absolute Path name of a file (file + current working dir)
os.path.abspath('some-file')
#Get the basename - returns file
os.path.basename('/path/to/file')
# Split a directory path - platform independent
os.path.split(os.getcwd())
# Out[17]: ('/Users', 'jillian')
# Check if a path exists
os.path.exists('/path/on/filesystem')
# Check if a path is a symlink
os.path.islink()
Move files and directories around

# Copy a directory
# cp -rf
shutil.copytree('src', 'dest')
# Copy a file
# cp -rf
shutil.copyfile('file1', 'file2')
# Move a directory
# mv
shutil.move('src', 'dest')
Not everything is going to be available through python libraries, such as installing system libraries, so run a few system commands!

# Run an arbitrary system command
command = "echo 'hello'"
result = subprocess.run(command.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#Print the stdout and stderr
print(result.stdout)
print(result.stderr)
Write to files!

# Write to a file (and create it if it doesn't exist)
# echo "hello" > hello.txt
f= open("hello.txt","w+")
f.write("hello!")
f.close()
# Append to a file
# echo "hello" >> hello.txt
f = open("hello.txt", "a+")
f.write("hello again!")
f.close()
Write some tests!
Tests mostly work by using a function called assert, which is essentially saying make sure this is true and if not die loudly.

def test_system_command():
    """Test the exit code of a system command"""
    command = "echo 'hello'"
    result = subprocess.run(command.split(' '), stdout=subprocess.PIPE)
    assert result.returncode == 0
    
Put this function in a file called test_my_code.py and run as pytest test_my_code.py.
+++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++
