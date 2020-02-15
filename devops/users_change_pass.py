#!/usr/bin/python3

######
#######
################################################

import subprocess
from time import sleep

###
PASSWD_CMD = '/usr/bin/passwd'
###
##
##

def set_password(user, password):
    cmd = [PASSWD_CMD, user]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    p.stdin.write(u'%(p)s\n%(p)s\n' % {'p': password})
    p.stdin.flush()
    # Give `passwd` cmd 1 second to finish and kill it otherwise.
    for x in range(0, 10):
        if p.poll() is not None:
            break
        sleep(0.1)
    else:
        p.terminate()
        sleep(1)
        p.kill()
        raise RuntimeError('Setting password failed. '
                           '`passwd` process did not terminate.')
    if p.returncode != 0:
        raise RuntimeError('`passwd` failed: %d' % p.returncode)
        
############################################
