from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse
from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from javax.swing import JOptionPane
import subprocess
import tempfile
import threading
import time
import re

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpRequestResponse):

    def clean_unicode(self, data):
        data = data
        if '\xc2\xa7' in data:
            data = re.sub('\xc2.*\xa7/', "FUZZ/", data)
            data = re.sub('\xc2.*\xa7', "FUZZ", data)
        else:
            return data
        return data

    def str_to_array(self, string):
        return [ord(c) for c in string]

    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Copy as fuzzer...")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        self.helpers = callbacks.getHelpers()
        self.callbacks = callbacks
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()

        menuList.add(JMenuItem("Copy as Ffuf",
                actionPerformed=self.copyAsFfuf))

        menuList.add(JMenuItem("Copy as Feroxbuster",
                actionPerformed=self.copyAsFeroxbuster))

        return menuList

    def copyAsFfuf(self, event):
        httpTraffic = self.context.getSelectedMessages()[0]
        httpRequest = httpTraffic.getRequest()
        httpRequest = self.helpers.bytesToString(httpRequest)

        headers = httpRequest.splitlines()
        scheme = '-u http://'
        for x in headers:
            if x.lower().startswith("host"):
                header = x.split(" ")
                host = header[1]
                break
        for x in headers:
            if x.lower().startswith("get") or x.lower().startswith("post"):
                header = x.split(" ")
                path = self.clean_unicode(header[1].encode('utf-8'))
                method = header[0]
                break
        for x in headers:
            if x.lower().startswith("cookie"):
                cookie = x
                break
            else:
                cookie = None
        for x in headers:
            if x.lower().startswith("upgrade-insecure-requests"):
                scheme = '-k -u https://'
                break

        if method == 'POST':
            data = self.clean_unicode(headers[-1].encode('utf-8'))
            if cookie != None:
                ffuf_cmd = "ffuf {scheme}{host}{path} -X {method} -d '{data}' -H '{cookie}' -w ~/wordlists/raft-medium-words.txt".format(scheme=scheme,host=host,path=path,method=method,data=data,cookie=cookie)
            else:
                ffuf_cmd = "ffuf {scheme}{host}{path} -X {method} -d '{data}' -w ~/wordlists/raft-medium-words.txt".format(scheme=scheme,host=host,path=path,method=method,data=data)

        if method == 'GET':
            if cookie != None:
                ffuf_cmd = "ffuf {scheme}{host}{path} -X {method} -H '{cookie}' -w ~/wordlists/raft-medium-words.txt".format(scheme=scheme,host=host,path=path,method=method,cookie=cookie)
            else:
                ffuf_cmd = "ffuf {scheme}{host}{path} -X {method} -w ~/wordlists/raft-medium-words.txt".format(scheme=scheme,host=host,path=path,method=method)

        self.copyToClipboard(ffuf_cmd)

        t = threading.Thread(target=self.copyToClipboard, args=(ffuf_cmd,True))
        t.start()

    def copyAsFeroxbuster(self, event):
        httpTraffic = self.context.getSelectedMessages()[0]
        httpRequest = httpTraffic.getRequest()
        httpRequest = self.helpers.bytesToString(httpRequest)

        headers = httpRequest.splitlines()
        for x in headers:
            if x.lower().startswith("host"):
                header = x.split(" ")
                host = header[1]
                break
        for x in headers:
            if x.lower().startswith("get") or x.lower().startswith("post"):
                header = x.split(" ")
                path = header[1]
                break
        for x in headers:
            if x.lower().startswith("cookie"):
                cookie = x
                break
            else:
                cookie = None

        if cookie != None:
            ferox_cmd = "feroxbuster {scheme}{host}{path} -H '{cookie}' -w ~/wordlists/raft-medium-words.txt".format(scheme=scheme,host=host,path=path,cookie=cookie)
        else:
            ferox_cmd = "feroxbuster {scheme}{host}{path} -w ~/wordlists/raft-medium-words.txt".format(scheme=scheme,host=host,path=path,cookie=cookie)

        self.copyToClipboard(ferox_cmd)

        t = threading.Thread(target=self.copyToClipboard, args=(ferox_cmd,True))
        t.start()
        

    def copyToClipboard(self, data, sleep=False):
        if sleep is True:
            time.sleep(1.5)

        data = self.helpers.bytesToString(data)
        systemClipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        systemSelection = Toolkit.getDefaultToolkit().getSystemSelection()
        transferText = StringSelection(data)
        systemClipboard.setContents(transferText, None)
        systemSelection.setContents(transferText, None)
