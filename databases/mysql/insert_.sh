


#!/bin/bash
inputfile="test.txt"
cat $inputfile | while read ip mac server; do
    echo "INSERT INTO test (IP,MAC,SERVER) VALUES ('$ip', '$mac', '$server');"
done | mysql -uroot -ptest test;

###########

#!/bin/bash
N=1
ARRAY=( adssa asdsa fdgfd vcbxcxv )
for el in "${ARRAY[@]}"
do echo $el
done | shuf | head -$N | while read -r line
do 
mysql -u root -pPass somebase << EOF
  INSERT INTO sometable (name) VALUES ('$line');
  SELECT * FROM site_user;
EOF
done

###########


The simpler way would be:

#!/bin/bash
n=1
array=( adssa asdsa fdgfd vcbxcxv )
printf "INSERT INTO sometable (name) VALUES ('%s');\n" "${array[@]}" | \
  shuf | head -n $n | mysql -u root -pPass somebase
Share
Follow
answered May 19, 2014 at 16:49
that other guy's user avatar
that other guy
114k1111 gold badges166166 silver badges191191 bronze badges
Add a comment

###########

Enclose your for loop using $(...) notation to get your output into the el variable.

#!/bin/bash
N=1
ARRAY=( adssa asdsa fdgfd vcbxcxv )
el=$(for el in "${ARRAY[@]}"
do echo $el
done | shuf | head -$N)

mysql -u root -p1550005 stat << EOF
INSERT INTO site_user (name) VALUES ('$el');
SELECT * FROM site_user;
EOF




###
###

I'm trying to create a bunch of records in my MySQL database. This is a one time creation so I am not trying to create a stored procedure. Here is my code:

BEGIN
SET i = 2376921001;
WHILE (i <= 237692200) DO
    INSERT INTO `mytable` (code, active, total) values (i, 1, 1);
    SET i = i+1;
END WHILE;
END
Here is the error:

[ERROR in query 1] You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'SET i = 2376921001 WHILE (i <= 237692200) DO INSERT INTO coupon (couponCod' at line 2 Execution stopped!

I have tried a Declare with the same results. Code below:

BEGIN
DECLARE i INT unsigned DEFAULT 2376921001;
WHILE (i <= 237692200) DO
    INSERT INTO `mytable` (code, active, total) values (i, 1, 1);
    SET i = i+1;
END WHILE;
END
The one other thing I have tried is with @i instead of just i. Same error. Can anyone see what I am doing wrong?

mysqlwhile-loop
Share
Improve this question
Follow
edited Oct 19, 2021 at 4:38
Giacomo1968's user avatar
Giacomo1968
25.4k1111 gold badges7070 silver badges100100 bronze badges
asked Nov 17, 2014 at 21:01
jessier3's user avatar
jessier3
78911 gold badge66 silver badges1515 bronze badges
what is the definition of your table ... how is 'code' declared ? – 
BWS
 Nov 17, 2014 at 21:50
code is a varchar. I get the same error when I run this : BEGIN DECLARE @i VARCHAR unsigned DEFAULT 1001; WHILE (i <= 2200) DO INSERT INTO coupon (couponCode, active, totalUses) values (i, 1, 1); SET i = i+1; END WHILE; END – 
jessier3
 Nov 17, 2014 at 22:06 
Add a comment
2 Answers
Sorted by:

Highest score (default)

45


drop procedure if exists doWhile;
DELIMITER //  
CREATE PROCEDURE doWhile()   
BEGIN
DECLARE i INT DEFAULT 2376921001; 
WHILE (i <= 237692200) DO
    INSERT INTO `mytable` (code, active, total) values (i, 1, 1);
    SET i = i+1;
END WHILE;
END;
//  

CALL doWhile(); 
Share
Improve this answer
Follow
answered Apr 19, 2016 at 9:31
Lily.He's user avatar
Lily.He
45144 silver badges33 bronze badges
7
While this code snippet may solve the question, including an explanation really helps to improve the quality of your post. Remember that you are answering the question for readers in the future, and those people might not know the reasons for your code suggestion. – 
Tony Babarino
 Apr 19, 2016 at 9:58
Add a comment

Report this ad

42


You cannot use WHILE like that; see: mysql DECLARE WHILE outside stored procedure how?

You have to put your code in a stored procedure. Example:

CREATE PROCEDURE myproc()
BEGIN
    DECLARE i int DEFAULT 237692001;
    WHILE i <= 237692004 DO
        INSERT INTO mytable (code, active, total) VALUES (i, 1, 1);
        SET i = i + 1;
    END WHILE;
END
Fiddle: http://sqlfiddle.com/#!2/a4f92/1

Alternatively, generate a list of INSERT statements using any programming language you like; for a one-time creation, it should be fine. As an example, here's a Bash one-liner:

for i in {2376921001..2376921099}; do echo "INSERT INTO mytable (code, active, total) VALUES ($i, 1, 1);"; done
By the way, you made a typo in your numbers; 2376921001 has 10 digits, 237692200 only 9.

Share
Improve this answer
Follow
edited May 23, 2017 at 12:09
Community's user avatar
CommunityBot
111 silver badge
answered Nov 17, 2014 at 22:17
Ruud Helderman's user avatar
Ruud Helderman
10.2k11 gold badge2525 silver badges4545 bronze badges
Yeah, the numbers were provided and I didn't go in and check them. Thank you for catching that. What I am getting from your post is that there is no way to do this with SQL. That I have to pull the code out and generate each individual statement with PHP. – 
jessier3
 Nov 17, 2014 at 23:46
@jessier3: You misunderstood; it is perfectly well possible in MySQL. I added sample code and a fiddle to clarify. But feel free to use the alternative approach instead; whatever you find convenient. – 
Ruud Helderman
 Nov 18, 2014 at 20:21
This has been a while ago and I forgot to come back and comment. This worked. Thank you for your help. – 
jessier3
 Dec 1, 2014 at 21:36
4
I've got an #1064 - You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 3 with 5.1 ... regarding the documentation this should work :/ – 
Megachip
 Jul 17, 2017 at 20:34
@Megachip Please check your SQL statement with a hex viewer; there may be some invisible Unicode character in there. – 
Ruud Helderman
 Jul 21, 2017 at 19:35
Show 3 more comments

##
##

escape_quote() {
    echo $1 | sed "s/'/''/g"
}

# Get commands to insert data to MySQL.
#
# Params:
#   $1 -- table to insert data to
#   $2 -- number of fields
#   $3 -- data file (fields delimited by '\1', also note that '\1' after last
#         field is required)
insertcmd() {
    table=$1
    shift
    fieldnum=$1
    shift
    datafile=$1
    shift

    holders="?"
    fillers="@f0"
    for i in $( seq 1 $(( $fieldnum - 1 )) ); do
        holders="$holders"",?"
        fillers="$fillers"",@f${i}"
    done
    insertcmd="PREPARE stmt1 FROM 'INSERT INTO $table VALUE($holders)';"

    pos=0
    # read field by field delimited by '\1'
    while read -d $'\1' -r field; do
        field=$( escape_quote $field )
        if [[ $pos -eq 0 ]]; then
            params="set @f0='$field';"
        else
            params="${params} set @f${pos}='$field';"
        fi

        pos=$(( $pos + 1))
        if [[ $pos -eq $fieldnum ]]; then
            insertcmd="""$insertcmd $params EXECUTE stmt1 USING $fillers;"""
            pos=0         
        fi
    done < "$datafile"

    insertcmd="$insertcmd DEALLOCATE PREPARE stmt1;"

    echo $insertcmd    
    
    ##
