#######################
#######################

def checkinstallation():
    with hide('output','warnings','running'):
        try:
            startlog()
            ...................
            ...................
            log('task done')
        except Exception, e:
            #print "%s host is down :: %s"%(env.host,str(e))
            log('bad host %s::%s'%(env.host,str(e)))


def startlog():
    import datetime
    i = datetime.datetime.now()
    logfile = open("output.txt", "a+")
    logfile.close()


def log(msg):
    logfile=open("output.txt","a+")
    logfile.write(msg + "\n")
    logfile.close()
    
#######################    
#######################
