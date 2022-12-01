#!/usr/bin/perl

use strict;
use warnings;
use autodie;

my $f1 = shift || "/opt/test.txt";
my $f2 = shift || "/opt/test1.txt";
my %results;
open my $file1, '<', $f1;
while (my $line = <$file1>) { $results{$line} = 1 }
open my $file2, '<', $f2;
while (my $line = <$file2>) { $results{$line}++ }
foreach my $line (sort { $results{$b} <=> $results{$a} } keys %results) {
    print "$results{$line}: ", $line if $results{$line} > 1;
}


########
########


Two file processing
This chapter focuses on solving problems which depend upon contents of two or more files. These are usually based on comparing records and fields. Sometimes, record number plays a role too. You'll also see some examples where entire file content is used.

Comparing records
Consider the following input files which will be compared line wise to get common lines and unique lines.


$ cat color_list1.txt
teal
light blue
green
yellow

$ cat color_list2.txt
light blue
black
dark green
yellow
If you do not wish to use modules, you can make use of hash to compare records between two files.


$ # common lines
$ # same as: grep -Fxf color_list1.txt color_list2.txt
$ # for two file input, $#ARGV will be 0 only for the first file
$ # note that 'exists' isn't strictly necessary here
$ perl -ne 'if(!$#ARGV){$h{$_}=1; next}
            print if exists $h{$_}' color_list1.txt color_list2.txt
light blue
yellow

$ # lines from color_list2.txt not present in color_list1.txt
$ # same as: grep -vFxf color_list1.txt color_list2.txt
$ perl -ne 'if(!$#ARGV){$h{$_}=1; next}
            print if !exists $h{$_}' color_list1.txt color_list2.txt
black
dark green

$ # reversing the order of input files gives
$ # lines from color_list1.txt not present in color_list2.txt
$ perl -ne 'if(!$#ARGV){$h{$_}=1; next}
            print if !exists $h{$_}' color_list2.txt color_list1.txt
teal
green
Here's some alternate ways to construct a solution for above examples.


$ # using if-else instead of next
$ perl -ne 'if(!$#ARGV){ $h{$_}=1 }
            else{ print if exists $h{$_} }' color_list1.txt color_list2.txt
light blue
yellow

$ # read all lines from first file passed as STDIN in BEGIN block
$ perl -ne 'BEGIN{ $h{$_}=1 while <STDIN> }
            print if exists $h{$_}' <color_list1.txt color_list2.txt
light blue
yellow
Using modules for set operations
You can use uniq function from List::Util module to preserve only one copy of duplicates from one or more input files. See Dealing with duplicates chapter for field based duplicate processing.


$ # input order of lines is preserved
$ # this is same as performing union between two sets
$ perl -MList::Util=uniq -e 'print uniq <>' color_list1.txt color_list2.txt
teal
light blue
green
yellow
black
dark green
The metacpan: List::Compare module supports set operations like union, intersection, symmetric difference etc. See also metacpan: Array::Utils.


$ # union, input order of lines is NOT preserved
$ # note that only -e option is used and one of the files is passed as stdin
$ perl -MList::Compare -e '@a1=<STDIN>; @a2=<>;
         print List::Compare->new(\@a1, \@a2)->get_union
        ' <color_list1.txt color_list2.txt
black
dark green
green
light blue
teal
yellow

$ # intersection (common lines)
$ perl -MList::Compare -e '@a1=<STDIN>; @a2=<>;
         print List::Compare->new(\@a1, \@a2)->get_intersection
        ' <color_list1.txt color_list2.txt
light blue
yellow

$ # lines from color_list1.txt not present in color_list2.txt
$ perl -MList::Compare -e '@a1=<STDIN>; @a2=<>;
         print List::Compare->new(\@a1, \@a2)->get_unique      
        ' <color_list1.txt color_list2.txt
green
teal
Comparing fields
In the previous sections, you saw how to compare whole contents of records between two files. This section will focus on comparing only specific field(s). The below sample file will be one of the two file inputs for examples in this section. Consider whitespace as the field separator, so -a option is enough to get the fields.


$ cat marks.txt
Dept    Name    Marks
ECE     Raj     53
ECE     Joel    72
EEE     Moi     68
CSE     Surya   81
EEE     Tia     59
ECE     Om      92
CSE     Amy     67
To start with, here's a single field comparison. The problem statement is to fetch all the records from marks.txt if the first field matches any of the departments listed in dept.txt file.


$ cat dept.txt
CSE
ECE

$ perl -ane 'if(!$#ARGV){ $h{$F[0]}=1 }
             else{ print if exists $h{$F[0]} }' dept.txt marks.txt
ECE     Raj     53
ECE     Joel    72
CSE     Surya   81
ECE     Om      92
CSE     Amy     67
For multiple field comparison, you can use comma separated values to construct the hash keys. The special variable $; (whose default is \034) will be used to join these values. The \034 character is usually not present in text files. If you cannot guarantee absence of this character, you can use some other character or use hash of hashes. See also stackoverflow: using array as hash key.


$ cat dept_name.txt
EEE Moi
CSE Amy
ECE Raj

$ # don't use array slice as hash keys
$ perl -anE '$h{@F[0..1]}=1; say join ",", keys %h' dept_name.txt | cat -v
Moi
Moi,Amy
Moi,Raj,Amy
$ # default $; value is \034, same as SUBSEP in awk
$ perl -anE '$h{$F[0],$F[1]}=1; say join ",", keys %h' dept_name.txt | cat -v
EEE^\Moi
CSE^\Amy,EEE^\Moi
ECE^\Raj,CSE^\Amy,EEE^\Moi

$ perl -ane 'if(!$#ARGV){ $h{$F[0],$F[1]}=1 }
             else{ print if exists $h{$F[0],$F[1]} }' dept_name.txt marks.txt
ECE     Raj     53
EEE     Moi     68
CSE     Amy     67
Here's an alternate method with hash of hashes. See also perldoc: REFERENCES.


$ perl -ane 'if(!$#ARGV){ $h{$F[0]}{$F[1]}=1 }
             else{ print if exists $h{$F[0]}{$F[1]} }' dept_name.txt marks.txt
ECE     Raj     53
EEE     Moi     68
CSE     Amy     67
In this example, one of the fields is used for numerical comparison.


$ cat dept_mark.txt
ECE 70
EEE 65
CSE 80

$ # match Dept and minimum marks specified in dept_mark.txt
$ perl -ane 'if(!$#ARGV){ $h{$F[0]}=$F[1] }
             else{ print if exists $h{$F[0]} && $F[2]>=$h{$F[0]} }
            ' dept_mark.txt marks.txt
ECE     Joel    72
EEE     Moi     68
CSE     Surya   81
ECE     Om      92
Here's an example of adding a new field.


$ cat role.txt
Raj class_rep
Amy sports_rep
Tia placement_rep

$ # $.=0 is needed to allow header line checking for second file
$ perl -lane 'if(!$#ARGV){ $r{$F[0]}=$F[1]; $.=0 }
              else{ print join "\t", @F, $.==1 ? "Role" : $r{$F[1]} }
             ' role.txt marks.txt
Dept    Name    Marks   Role
ECE     Raj     53      class_rep
ECE     Joel    72
EEE     Moi     68
CSE     Surya   81
EEE     Tia     59      placement_rep
ECE     Om      92
CSE     Amy     67      sports_rep
Based on line number
Here's an example that shows how you can replace mth line from a file with nth line from another file.


$ # replace 3rd line of table.txt with
$ # 2nd line of greeting.txt
$ perl -pe 'BEGIN{ $m=3; $n=2; $s = <STDIN> for 1..$n }
            $_ = $s if $. == $m' <greeting.txt table.txt
brown bread mat hair 42
blue cake mug shirt -7
Have a nice day
Here's an example where two files are processed simultaneously.


$ # print line from greeting.txt if the last column of corresponding line
$ # from table.txt is a positive number
$ perl -ne 'print if (split " ", <STDIN>)[-1] > 0' <table.txt greeting.txt
Hi there
Good bye
Multiline fixed string substitution
You can use file slurping for fixed string multiline search and replace requirements. The below example is substituting complete lines. The solution will work for partial lines as well, provided there is no newline character at the end of search.txt and repl.txt files.


$ head -n2 table.txt > search.txt
$ cat repl.txt
2$1$&3
wise ice go goa

$ perl -0777 -ne '$#ARGV==1 ? $s=$_ : $#ARGV==0 ? $r=$_ :
                  print s/\Q$s/$r/gr' search.txt repl.txt table.txt
2$1$&3
wise ice go goa
yellow banana window shoes 3.14
warning Don't save contents of search.txt and repl.txt in shell variables for passing them to the perl script. Trailing newlines and ASCII NUL characters will cause issues. See stackoverflow: pitfalls of reading file into shell variable for details.

Add file content conditionally
Case 1: replace each matching line with entire contents of STDIN.


$ # same as: sed -e '/[ot]/{r dept.txt' -e 'd}' greeting.txt
$ perl -pe 'BEGIN{$r = join "", <STDIN>} $_=$r if /[ot]/' <dept.txt greeting.txt
CSE
ECE
Have a nice day
CSE
ECE
Case 2: insert entire contents of STDIN before each matching line.


$ # same as: sed '/nice/e cat dept.txt' greeting.txt
$ perl -pe 'BEGIN{$r = join "", <STDIN>}
            print $r if /nice/' <dept.txt greeting.txt
Hi there
CSE
ECE
Have a nice day
Good bye
Case 3: append entire contents of STDIN after each matching line.


$ # same as: sed '/nice/r dept.txt' greeting.txt
$ perl -pe 'BEGIN{$r = join "", <STDIN>}
            $_ .= $r if /nice/' <dept.txt greeting.txt
Hi there
Have a nice day
CSE
ECE
Good bye
Summary
This chapter discussed use cases where you need to process the contents of two or more files based on entire record/file or field(s). The value of $#ARGV is handy for such cases (formula is n-2 to match first file passed among n input files). The next chapter discusses more such examples, based solely on occurrences of duplicate values.

Exercises
a) Use contents of match_words.txt file to display matching lines from jumbled.txt and sample.txt. The matching criteria is that the second word of lines from these files should match the third word of lines from match_words.txt.


$ cat match_words.txt
%whole(Hello)--{doubt}==ado==
just,\joint*,concession<=nice

$ # 'concession' is one of the third words from 'match_words.txt'
$ # and second word from 'jumbled.txt'
##### add your solution here
wavering:concession/woof\retailer
No doubt you like it too
b) Interleave contents of secrets.txt with the contents of a file passed as stdin in the format as shown below.


##### add your solution here, use 'table.txt' for stdin data
stag area row tick
brown bread mat hair 42
---
deaf chi rate tall glad
blue cake mug shirt -7
---
Bi tac toe - 42
yellow banana window shoes 3.14
c) The file search_terms.txt contains one search string per line (these have no regexp metacharacters). Construct a solution that reads this file and displays search terms (matched case insensitively) that were found in all of the other input file arguments. Note that these terms should be matched with any part of the line, not just whole words.


$ cat search_terms.txt
hello
row
you
is
at

$ # ip: search_terms.txt jumbled.txt mixed_fs.txt secrets.txt table.txt oops.txt
##### add your solution here
row
at

$ # ip: search_terms.txt ip.txt sample.txt oops.txt
##### add your solution here
hello
you
is
d) Replace third to fifth lines of input file ip.txt with second to fourth lines from file para.txt


##### add your solution here
Hello World
How are you
Start working on that
project you always wanted
to, do not let it end
You are funny
e) Insert one line from jumbled.txt before every two lines of copyright.txt


##### add your solution here
overcoats;furrowing-typeface%pewter##hobby
bla bla 2015 bla
blah 2018 blah
wavering:concession/woof\retailer
bla bla bla
copyright: 2020
f) Use entire contents of match.txt to search error.txt and replace with contents of jumbled.txt. Partial lines should NOT be matched.


$ cat match.txt
print this
but not that
$ cat error.txt
print this
but not that or this
print this
but not that
if print this
but not that
print this
but not that

##### add your solution here
print this
but not that or this
overcoats;furrowing-typeface%pewter##hobby
wavering:concession/woof\retailer
if print this
but not that
overcoats;furrowing-typeface%pewter##hobby
wavering:concession/woof\retailer
