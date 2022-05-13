rga: ripgrep, but also search in PDFs, E-Books, Office documents, zip, tar.gz, etc.
JUN 16, 2019 • LAST UPDATE OCT 21, 2019
rga is a line-oriented search tool that allows you to look for a regex in a multitude of file types. rga wraps the awesome ripgrep and enables it to search in pdf, docx, sqlite, jpg, zip, tar.*, movie subtitles (mkv, mp4), etc.

##################
##
##

https://phiresky.github.io/blog/2019/rga--ripgrep-for-zip-targz-docx-odt-epub-jpg/

################
##
##

Examples
PDFs
Say you have a large folder of papers or lecture slides, and you can’t remember which one of them mentioned GRUs. With rga, you can just run this:

~$ rga "GRU" slides/
slides/2016/winter1516_lecture14.pdf
Page 34:   GRU                            LSTM
Page 35:   GRU                            CONV
Page 38:     - Try out GRU-RCN! (imo best model)

slides/2018/cs231n_2018_ds08.pdf
Page  3: ●   CNNs, GANs, RNNs, LSTMs, GRU
Page 35: ● 1) temporal pooling 2) RNN (e.g. LSTM, GRU)

slides/2019/cs231n_2019_lecture10.pdf
Page 103:   GRU [Learning phrase representations using rnn
Page 105:    - Common to use LSTM or GRU

and it will recursively find a string in pdfs, including if some of them are zipped up.

You can do mostly the same thing with pdfgrep -r, but you will miss content in other file types and it will be much slower:

Searching in 65 pdfs with 93 slides each

0
5
10
15
20
pdfgrep
rga (first run)
rga(subsequentruns)
run time (seconds, lower is better)

On the first run rga is mostly faster because of multithreading, but on subsequent runs (with the same files but any regex query) rga will cache the text extraction, so it becomes almost as fast as searching in plain text files. All runs were done with a warm FS cache.

Other files
rga will recursively descend into archives and match text in every file type it knows.

Here is an example directory with different file types:

demo
├── greeting.mkv
├── hello.odt
├── hello.sqlite3
└── somearchive.zip
    ├── dir
    │   ├── greeting.docx
    │   └── inner.tar.gz
    │       └── greeting.pdf
    └── greeting.epub
(see the actual directory here)

~$ rga "hello" demo/

demo/greeting.mkv
metadata: chapters.chapter.0.tags.title="Chapter 1: Hello"
00:08.398 --> 00:11.758: Hello from a movie!

demo/hello.odt
Hello from an OpenDocument file!

demo/hello.sqlite3
tbl: greeting='hello', from='sqlite database!'

demo/somearchive.zip
dir/greeting.docx: Hello from a MS Office document!
dir/inner.tar.gz: greeting.pdf: Page 1: Hello from a PDF!
greeting.epub: Hello from an E-Book!
It can even search jpg / png images and scanned pdfs using OCR, though this is disabled by default since it is not useful that often and pretty slow.

~$ # find screenshot of crates.io
~$ rga crates ~/screenshots --rga-adapters=+pdfpages,tesseract
screenshots/2019-06-14-19-01-10.png
crates.io I Browse All Crates  Docs v
Documentation Repository Dependent crates

~$ # there it is!
Setup
Linux, Windows and OSX binaries are available in GitHub releases. See the readme for more information.

For Arch Linux, I have packaged rga in the AUR: yay -S ripgrep-all

Technical details
The code and a few more details are here: https://github.com/phiresky/ripgrep-all

rga simply runs ripgrep (rg) with some options set, especially --pre=rga-preproc and --pre-glob.

rga-preproc [fname] will match an "adapter" to the given file based on either it’s filename or it’s mime type (if --rga-accurate is given). You can see all adapters currently included in src/adapters.

Some rga adapters run external binaries to do the actual work (such as pandoc or ffmpeg), usually by writing to stdin and reading from stdout. Others use a Rust library or bindings to achieve the same effect (like sqlite or zip).

To read archives, the zip and tar libraries are used, which work fully in a streaming fashion - this means that the RAM usage is low and no data is ever actually extracted to disk!

Most adapters read the files from a Read, so they work completely on streamed data (that can come from anywhere including within nested archives).

During the extraction, rga-preproc will compress the data with ZSTD to a memory cache while simultaneously writing it uncompressed to stdout. After completion, if the memory cache is smaller than 2MByte, it is written to a rkv cache. The cache is keyed by (adapter, filename, mtime), so if a file changes it’s content is extracted again.

Future Work
I wanted to add a photograph adapter (based on object classification / detection) for fun, so you can grep for "mountain" and it will show pictures of mountains, like in Google Photos. It worked with YOLO, but something more useful and state-of-the art like this proved very hard to integrate.
7z adapter (couldn’t find a nice to use Rust library with streaming)
Allow per-adapter configuration options (probably via env (RGA_ADAPTERXYZ_CONF=json))
Maybe use a different disk kv-store as a cache instead of rkv, because I had some weird problems with that. SQLite is great. All other Rust alternatives I could find don’t allow writing from multiple processes.
Tests!
There’s some more (mostly technical) todos in the code I don’t know how to fix. Help wanted.
Other open issues
Similar tools
pdfgrep
this gist has my proof of concept version of a caching extractor to use ripgrep as a replacement for pdfgrep.
this gist is a more extensive preprocessing script by @ColonolBuendia
lesspipe is a tool to make less work with many different file types. Different usecase, but similar in what it does.
