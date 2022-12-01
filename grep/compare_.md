

I need to search each value of fileA with fileB and return all the 26 values from FileB if matches. The search value (from FileA) may present in any of the 26 values in FileB. This value is not fixed in any of the columns in B file.

FILEA:

abc
def
ghi
FILEB:

drm|fdm|pln|ess|abc|zeh|....|yer (26 values)
fdm|drm|def|ess|yer|zeh|....|pln
Here, abc from fileA is 5th col. of FileB—so my result should be all the 26 values from FileB.
Similarly, def from fileA is 3rd col. of FileB -so my result should be all the 26 values from FileB.

This way, need to do for the entire record set.

If unmatched, ignore the record.

shelltext-processingscripting
Share
Improve this question
Follow
edited Sep 17, 2014 at 21:03
jasonwryan's user avatar
jasonwryan
69.5k3232 gold badges190190 silver badges224224 bronze badges
asked Sep 17, 2014 at 16:49
vamshi's user avatar
vamshi
6111 silver badge22 bronze badges
paste fileA fileB | YOURAWKcomparision – 
PersianGulf
 Sep 17, 2014 at 16:51 
Add a comment
2 Answers
Sorted by:

Highest score (default)

13


You can just use grep:

grep -Fwf fileA fileB
From man grep:

   -F, --fixed-strings
          Interpret PATTERN as a  list  of  fixed  strings,  separated  by
          newlines,  any  of  which is to be matched.  (-F is specified by
          POSIX.)
   -f FILE, --file=FILE
          Obtain  patterns  from  FILE,  one  per  line.   The  empty file
          contains zero patterns, and therefore matches nothing.   (-f  is
          specified by POSIX.)
   -w, --word-regexp
          Select  only  those  lines  containing  matches  that form whole
          words.  The test is that the matching substring must  either  be
          at  the  beginning  of  the  line,  or  preceded  by  a non-word
          constituent character.  Similarly, it must be either at the  end
          of  the  line  or  followed by a non-word constituent character.
          Word-constituent  characters  are  letters,  digits,   and   the
          underscore.
Share
Improve this answer
Follow
answered Sep 17, 2014 at 16:57
terdon's user avatar
terdon♦
224k6161 gold badges419419 silver badges630630 bronze badges
Add a comment

Report this ad

3


Does the order of fileA matter? Can you have multiple lines in fileB with that pattern? This will for example parse fileA and search for each pattern in fileB:

while read i; do grep "$i" fileB; done < fileA
But you need to define the problem better to get a solution with more performance. For example it is sufficient to get the whole line, you don't need to view it as 26 values.

Share
Improve this answer
Follow
edited Sep 18, 2014 at 9:20
terdon's user avatar
terdon♦
224k6161 gold badges419419 silver badges630630 bronze badges
