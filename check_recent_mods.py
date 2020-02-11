#!/usr/bin/python3

##
#################

## modified_most_recently_ 
## TARGET DIR, SECONDS

##################################
import os
import time


def modified_within(top, seconds):
    ''' top: search from this directory, down
    seconds: going back this number of seconds
    '''
    now = time.time()
    for path, dirs, files in os.walk(top):
        for name in files:
            fullpath = os.path.join(path, name)
            if os.path.exists(fullpath):
                mtime = os.path.getmtime(fullpath)
                if mtime > (now - seconds):
                    print(fullpath)

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print('Usage: {} dir seconds'.format(sys.argv[0]))
        raise SystemExit(1)

    modified_within(sys.argv[1], float(sys.argv[2]))
~                                                                                                                                  
########################################################
########################################################
