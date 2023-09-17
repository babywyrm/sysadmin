#-*- coding: utf-8 -*-
##
## https://gist.github.com/mhanoglu/3a6cef19b34f10706a02f31343312923
##

import os, sys,re

def substr(txt, start, offset) :
    return txt[start:start+offset]

def strtr(txt, src, tgt) :
    fr = '',
    i = 0,
    j = 0,
    lenStr = 0,
    lenFrom = 0,
    tmpStrictForIn = False,
    fromTypeStr = '',
    toTypeStr = '',
    istr = '';
    tmpFrom = [];
    tmpTo = [];
    ret = '';
    match = False;

    # Compare src and tgt lengths
    if len(src)  > len(tgt) :
        src = src[:len(tgt)]
    elif len(tgt) > len(src) :
        tgt = tgt[:len(src)]
    else : pass

    # Walk through subject and replace chars when needed
    lenStr = len(txt);
    lenFrom = len(src);
    lenTgt = len(tgt); # Add tgt length
    fromTypeStr = isinstance(src, str);
    toTypeStr = isinstance(tgt, str);

    for i in range(lenStr) :
        match = False;
        if (fromTypeStr) :
            istr = txt[i];
            for j in range(lenFrom) :
                if (istr == src[j]) :
                    match = True;
                    break;
        else :
            for j in range(lenFrom) :
                if (substr(txt, i, len(src[j])) == src[j]) :
                    match = True;
                    # Fast forward
                    i = (i + len(src[j])) - 1;
                    break;

        if (match) :
            if toTypeStr :
                ret += tgt[j]
            else :
                ret += tgt[j]
        else :
            ret += txt[i];

    return ret;


def read_file( path ) :
    f = open(path,'r')
    r = f.read()
    f.close();
    result = {}
    find = re.findall(r'\$\_X=\'(.+?)\';', r)
    if len(find) == 0: return False
    result['data'] = find[0].decode("base64")
    find2 = re.findall(r'\$\_D\(\'(.+?)\'\)', r)
    dec = find2[0].decode("base64")
    dec = dec.replace("\n","\\n")
    find3 = re.findall(r'\(\$_X\,\'(.+?)\'\,\'(.+?)\'\)', dec)
    result['source'] = find3[0][0].replace("\\n","\n")
    result['target'] = find3[0][1].replace("\\n","\n")
    return result


if len(sys.argv) == 2:
    file_path = sys.argv[1]
    #file_name = file_path.split('/')[-1]
    #file_dir = '/'.join( file_path.split('/')[:-1] ) + '/'

    resource = read_file( file_path )
    if resource != False:
        src = strtr(resource['data'], resource['source'], resource['target'])

        decoded_content = src[2:]

        f = open(file_path,'w')
        f.write(decoded_content)
        f.close();

        print "file decoded successfully"
    else:
        print "file not encoded"
    #print decoded_content
else:
    print "no argument"

##
##
