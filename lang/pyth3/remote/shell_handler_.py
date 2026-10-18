
## class ShellHandler:
##############################
##############################

def __init__(self, host, user, psw):
    logger.debug("Initialising instance of ShellHandler host:{0}".format(host))
    try:
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(host, username=user, password=psw, port=22)
        self.channel = self.ssh.invoke_shell()
    except:
        logger.error("Error Creating ssh connection to {0}".format(host))
        logger.error("Exiting ShellHandler")
        return
    self.psw=psw
    self.stdin = self.channel.makefile('wb')
    self.stdout = self.channel.makefile('r')
    self.host=host
    time.sleep(2)

    while not self.channel.recv_ready():
        time.sleep(2)
    self.initialprompt=""
    while self.channel.recv_ready():

        rl, wl, xl = select.select([ self.stdout.channel ], [ ], [ ], 0.0)
        if len(rl) > 0:
            tmp = self.stdout.channel.recv(24)
            self.initialprompt=self.initialprompt+str(tmp.decode())



def __del__(self):
    self.ssh.close()
    logger.info("closed connection to {0}".format(self.host))

def execute(self, cmd):
    cmd = cmd.strip('\n')
    self.stdin.write(cmd + '\n')
    #self.stdin.write(self.psw +'\n')
    self.stdin.flush()
    time.sleep(1)
    while not self.stdout.channel.recv_ready():
        time.sleep(2)
        logger.debug("Waiting for recv_ready")

    output=""
    while self.channel.recv_ready():
        rl, wl, xl = select.select([ self.stdout.channel ], [ ], [ ], 0.0)
        if len(rl) > 0:
            tmp = self.stdout.channel.recv(24)
            output=output+str(tmp.decode())
    return output

####################################
##
##
