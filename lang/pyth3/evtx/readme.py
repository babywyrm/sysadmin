
##
#

https://www.alishaaneja.com/evtx/

#
##


Recently I came across a problem in which I had to convert .evtx files (Windows Event Log files) to a human readable format like XML, CSV, JSON etc.

There’s this popular and only working parser that I know about python-evtx. It parses .evtx files to XML format.

These are the steps which I followed:

Clone the python-evtx directory in your system.

1
git clone https://github.com/williballenthin/python-evtx.git
Go into the cloned directory.

1
cd python-evtx
Install the libraries

1
python3 setup.py install
Go to the scripts directory inside python-evtx.

1
cd scripts
Run the following command if you just have one file which you want to convert.

1
python3 evtx_dump.py /mnt/data/alisha/logs/dc/security.evtx
In my case, I had folders inside folders which had .evtx files to convert, so I did:

1
2
3
4
5
for file in $(find /mnt/data/alisha/logs/ -iname "*.evtx")
do
	python3 evtx_dump.py $file > /mnt/data/alisha/parsed-evtx/`basename "$file"`.xml
	echo "$file: $?" >> conversion.log
done
It will first check every file inside the logs folder for .evtx extension and run evtx_dump.py on every file thereafter storing the .xml in a new folder, i.e., parsed-evtx. If it is not able to parse a file into XML due to some error, the filename will get saved in conversion.log.

I hope this will help someone!

25 Nov 2017
