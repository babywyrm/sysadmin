#/usr/bin/python3

############################
##
## _WALES_LOL__
##

from collections import defaultdict

digraphs=['ch','dd','ff','ng','ll','ph','rh','th']
breakchars=['|']


def welshcount(word):
    word = word.lower()
    index = 0
    counts = defaultdict(int)  # keys start at 0 if not already present
    while index < len(word):
        if word[index:index+2] in digraphs:
            counts[word[index:index+2]] += 1
            index += 1
        elif word[index] in breakchars:
            pass  # in case you want to do something here later
        else:  # plain old letter
            counts[word[index]] += 1

        index += 1

    return sum(counts.values())

word1='llong'
#ANSWER NEEDS TO BE 3 (ll o ng)

word2='llon|gyfarch'
#ANSWER NEEDS TO BE 9 (ll o n g y f a r ch)

word3='Llanfairpwllgwyn|gyllgogerychwyrndrobwllllantysiliogogogoch'
#ANSWER NEEDS TO BE 51 (Ll a n f a i r p w ll g w y n g y ll g o g e r y ch w y r n d r o b w ll ll a n t y s i l i o g o g o g o ch)

print(welshcount(word1))
print(welshcount(word2))

##################
##
##
