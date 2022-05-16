## Ripgrep is a very fast way to search your text based files.  The pre flag is a significantly slower way to search a bunch of your other files as well.  

The scripts below have been superseded by [rgpipe](https://github.com/ColonelBuendia/rgpipe).  

### TL;DR

**Good:** `rg --pre somescripthere yoursearchtermhere`

**Better:** `rg ---pre-glob '*.{comma,seperated,extensions,to,preprocess}' --pre somescripthere yoursearchtermhere`

**Located Below:** Shoddily constructed sample scripts likely to fail you when it matters most

### TL;

Many of the most common types of documents shared today are binary(1), or computer readable, and do not lend themselves to being searched by tools like ripgrep without some sort of intermediate steps.  The [--pre]  flag is a way to tell ripgrep to work with another program to perform those steps and then take that readable output back to ripgrep to be searched then.  This is dramatically slower than the regular thing it does(2). It is also dramatically faster and more efficient than almost anything else I have used for this purpose before, materially improving my daily workflow for the better.  The flexibility created by having a script instead of a built in function lets you tailor your benefits as well as the speed penalty as suits you, which is nice as well.  

The scripts below are tailored to my work flow, i.e. countless old office documents that I have never seen before. If you are regularly searching the same materials/documents, this is nice but probably **NOT** what you want.  You want to index those things really smartly and carefully with great care once, and then you can search lightning fast thereafter - Recoll in particular is dope for this purpose.  Namazu, also dope.  

The three things you need are:
1) The --pre flag itslef.  An alias for it is pretty cool as well, on you though.  
2) A script that tells ripgrep where to send stuff for processing and how to get it back.  Feel free to use the below.
3) Pre-globbing rules. Technically optional, but the difference in speed is (╯°□°）╯︵ ┻━┻


##### Sample command searching for rainbows,
Here re on WSL with one of the below scripts named rgpre (no extension) located in a folder named tools on my C: drive

**Command:** ```rg --pre /mnt/c/tools/rgpre rainbows```

**Outcome:** All files ripgrep would serch get sent through the script, then those outputs are searched.

This is very sad because ripgrep doesnt do all the things it does to make search fast. The solution is to use pre globbing rules. In english this means that since we only have anything clever to try on x number of filetypes, we should only send those filetypes(4) via the slow lane as opposed to everything.  

#### Better sample command searching for rainbows
**Command:**```rg --pre-glob '*.{pdf,xlsx,xls,docx,doc,pptx,ppt,html,epub}' --pre /mnt/c/tools/rgpre rainbows```

**Outcome:** PDF, xlsx, xls, docx, doc, pptx, ppt, html, epub get the script, other filetypes continue to enjoy their 8th ammendment rights.  


This is dramatically faster if there are other filetypes present, though still long to type. By moving the script into our path (for example /usr/local/bin for linux, or c:/windows/system32 for windows) we can save on the typing a bit to
`rg --pre-glob '*.{pdf,xlsx,xls,docx,doc,pptx,ppt,html,epub}' --pre rgpre rainbows`

and by creating an alas in your alias creating document of choice we can do even better:
`alias rgg="rg --pre-glob '*.{pdf,xlsx,xls,docx,doc,pptx,ppt,html,epub}' --pre rgpre"`

giving us a bastardized ripgrep search of a bunch of different files via 
`rgg rainbows`


---
#### Sample Use case
There is a conference call and we will be talking about some issue on which there are 25 ppt decks, a bunch of reports, drafts, excel models etc.  

`rgg "" > allthethings.txt`

Then I have a 10 megabyte or whatnot text file I can ctrl F at lighing speed and sound wildly more prepared than I am.



---
#### notes 
(1) There are details here, I have no idea what those details are.    ¯\_(ツ)_/¯

(2) For the way I have been using this, it is something like 100x slower, literally.  I can use regular ripgrep to go through all or most of the Project gutenberg e-texts, 30k files ~10gb, in 5 to ten seconds. Searching though 7k files of mixed type which together are sub 500mb can be a minute or two easily depending on the eccentricites of said files.

(3) These are worth no more than what you are paying for them.  If you are fired because they suck and you relied on them, sorry not sorry.  Any improvements are welcome.

(4) You're sending anything with that extension of course, not the filetype.  For the same reason you are using this instead of an index based search, they are disproportionally likely to be wrong.  

---
