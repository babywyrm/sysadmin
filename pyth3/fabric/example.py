
###################
##  https://github.com/fabric/fabric/issues/1351
################### 

from fabric.api import *
from fabric.colors import green,red,blue,cyan,yellow
import os , sys
import socket
import datetime
import logging
import logging.handlers
#get logger for logging 
def initLoggerWithRotate():
    logname=''.join(env.host_string.split('.'))+'.log'
    logFileName="logs/%s"%logname
    logger = logging.getLogger("fabric")
    formater = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s","%Y-%m-%d %H:%M:%S")
    file_handler = logging.handlers.RotatingFileHandler(logFileName, maxBytes=104857600, backupCount=5)
    file_handler.setFormatter(formater)
    stream_handler = logging.StreamHandler(sys.stderr)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.setLevel(logging.INFO)
    return logger
#mkdir
def runmkdir(dir):
    run(''' mkdir -p %s '''%dir)
#stp 1 check host
def checkhost(logger):
     host = env.host_string 
     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     flag_c = 0
     try:
         s.connect((host, 22))
         flag_c = 1
         logger.info( green( ' --> host %s can be reachable ' %host ) )
     except socket.error as e: 
         logger.warning( yellow( ' --> Error on connect %s' %e ) )
     s.close()
     return flag_c
#stp 2 check alive instance on target host 
def checkmysqlinstance(logger):
    try:
        wc = run(''' ps -ef |grep mysqld|grep  -v safe | grep -v grep | wc -l  ''') 
        if int(wc) > 0  : 
            logger.warning(yellow( ' --> %sinstance exist on the target host  '%wc )) 
            portraw = run('''  ps -ef |grep mysqld|grep -v safe |grep -v grep  |awk ' {for(i=1;i<=NF;i++){if($i ~/--port/ ){print $i}}}' |awk -F '=' '{print $2}'
            ''')
            ports = [x.strip() for x in portraw.split() ]
            logger.warning( yellow( ' --> existing instance port : [ %s ] '%( ','.join( ports ))))
            if port in ports:
                logger.error( red( ' --> Install port %s exist , install failed '%port))
                logger.error( red( ' <<<exit>>>>>  task on host %s stop & exit() '%thost))
                sys.exit()
    except Exception, e:
        logger.warning(yellow( ' --> checkmysqlinstance() exception : %s '%e )) 
        raise e 
#stp 3 initdir for installation
def createUser(logger,user='mysql',group='dba'):
    try:
        if int(run('grep "^mysql" /etc/passwd|wc -l')) == 0 :
            run('groupadd dba ')
            run('useradd -c "mysql software owner" -g dba -G dba mysql')
            run('mkdir -p /home/mysql ; chown -R mysql.dba /home/mysql ')
            logger.info(cyan( ' --> create user [ mysql ] in group [ dba ]  success ' )) 
        else : 
            logger.info(yellow ( ' --> user [ mysql ] in group [ dba ] exist & skip  ' )) 
    except Exception, e:
        logger.warning(yellow( ' --> createUser() exception : %s '%e )) 
        raise e
#stp 4 initail directory for mysql        
def initdir(logger,port=3306):  
    try :
        logger.info( green( ' --> begin to create dirs for installation '))
        datadir='/data/'
        logdir ='/log/'
        mandir = 'mysql%s'%port
        subddir ='/data/mysql%s/{data,log,run,tmp}'%(port)
        subldir ='/log/mysql%s/{binlog,iblog}'%(port) 
        #data
        ck1 = run(' df -vh  | grep  /data | wc -l ')
        if ck1  == 0 : 
            logger.error(green(' --> no /data/ partition exist' ) )
            #sys.exit()
        if int( run(' ls /  | grep  /data | wc -l ')) == 0 or int( run(' ls /data/ | grep -w %s | wc -l '%mandir) ) == 0 : 
            runmkdir(subddir) 
            logger.info(green(' --> /data/*** create Ok ' ) )
        else : 
            logger.info(green(' --> /data/mysql%s exsit '%port ))
            logger.info(green(' --> pls,handle it and restart this task '))
            sys.exit()
        #log 
        ck2 = run(' df -vh | grep /log/  | wc -l  ')
        if int( run(' df -vh | grep /log/  | wc -l  ') ) == 0  and int( run(' ls / | grep -w log  | wc -l  ') ) == 0: 
            logger.warning( yellow(' --> no /log/ partition exist') ) 
            logger.warning( yellow(' --> create link for /log/ --> /data/log/') ) 
            runmkdir('/data/log')
            run('ln -s /data/log  /log ')
            runmkdir(subldir) 
            logger.info(green(' --> /log/*** create Ok ' ) )
        else : 
            if  int(run(' ls /log/ | grep -w %s | wc -l '%mandir)) == 0: 
                runmkdir(subldir) 
                logger.info(green(' --> /log/*** create Ok ' ) )
            else : 
                logger.info(yellow(' --> /log/mysql%s exsit '%port ))
                logger.error(red(' --> pls,handle it and restart this task ' ))
                sys.exit() 
        #change 
        runmkdir('/data/tmp')
        logger.info(green(' --> change dirs owner&privs start'))
        run('chown -R mysql:dba /data/*')
        run('chown -R mysql:dba /log') 
        logger.info(green(' --> change dirs owner&privs done'))
    except Exception, e:
        logger.warning(yellow( ' --> initdir() exception : %s '%e )) 
        raise e 
#stp 5 put mysql install package
def copymysql(logger,version='5.7'): 
    try:
        dits = {
        'ubuntu':'mysql-server_5.6.21-1ubuntu12.04_amd64.deb-bundle.tar',
        'centos':'mysql-server.tar.gz'
        }
        issue = run ('cat /etc/issue') 
        ss = issue.lower()
        logger.info( green( ' %s '%ss))
        if int ( run( ' ls /usr/local/ | grep mysql | wc -l ') ) > 0 : 
            logger.info( yellow( ' --> mysql software installed , skip   ' )) 
            return
        plats = dits.keys()
        for x in plats: 
            if ss.find(x) != -1: 
                logger.info( green( ' --> the target host platform is %s'% x ) )
                put( local_path="configs/%s"%dits[x],remote_path="/tmp/%s"%dits[x] )
                logger.info( green( ' --> tar the ball to prop dir '))
                run( 'tar zxvf /tmp/%s -C /usr/local/ '%dits[x] )
                run( 'ln -s /usr/local/%s  /usr/local/mysql  '%dits[x][:-7] )
                break 
    except Exception, e:
        logger.warning(yellow( ' --> copymysql() exception : %s '%e )) 
        raise e 
#gen my.cnf file 
def getnewServerId(logger,port):  
    host = env.host_string
    print 'getnewServerId : ',host
    pics = host.split('.')
    a=int(pics[0])
    b=int(pics[1])
    c=int(pics[2])
    d=int(pics[3])
    suf = int(port) % 256
    server_id =  b * 256 * 256 * 256 + c * 256 * 256 + d * 256 + suf
    logger.info( cyan( ' --> gen server_id done , %s %s is %s '%( host , port , server_id) ) )
    return server_id
def genmycnf(logger,port=3306,itype='h'):
    host = env.host_string
    bps={
    "a":"48|32|3100|3000",
    "b":"62|40|4600|4500",
    'c':'94|64|7600|7500',
    'd':'94|32|3100|3000',
    'e':'125|75|10100|10000',
    'f':'188|120|15100|15000',
    'g':'188|60|7600|7500',
    'h':'1|256M|800|750'
    } 
    try:
        myfile=''.join(host.split('.'))+'.cnf'
        cpmycnf="""cp configs/my.cnf  tmp/%s """%myfile 
        local( 'rm -f  tmp/%s'%myfile  )
        local("cp configs/my.cnf tmp/%s "%myfile )  
        sid=getnewServerId(logger,port)
        keys=bps.keys()
        bpxs=bps[itype]
        mem,bpsize,maxc,maxuc=bpxs.split('|')
        if bpsize[-1] != "M":
            bpsize = bpsize +'g'
        chrgcmd="""  sed -i -e "s/3306/%s/g" -e "s/server_id=10000/server_id=%s/g" -e "s/=32g/=%s/g" -e "s/max_connections=3100/max_connections=%s/g" -e "s/max_user_connections=3000/max_user_connections=%s/g" tmp/%s """
        local( chrgcmd%(port,sid,bpsize,maxc,maxuc,myfile) ) 
        logger.info( green( ' --> gen my.cnf success  ') )
        logger.info( green( ' --> copy my.cnf to dist host ') )
        put( local_path="tmp/%s"%myfile, remote_path="/data/mysql%s/my.cnf"%(port) )
    except Exception, e:
        logger.warning(yellow( ' --> genmycnf() exception : %s '%traceback.format_exc()  ) ) 
        raise e 

############################
###
###
