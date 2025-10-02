#!/usr/bin/env python3
"""
A generic daemon base class for UNIX-like systems, (..skeleton..)

Usage:
    Subclass Daemon and override the run() method.

Example:
    class MyDaemon(Daemon):
        def run(self):
            while True:
                do_some_work()
"""

import sys
import os
import time
import atexit
import logging
from signal import SIGTERM


class Daemon:
    """
    Generic daemon class.
    """

    def __init__(
        self,
        pidfile: str,
        stdin: str = "/dev/null",
        stdout: str = "/dev/null",
        stderr: str = "/dev/null",
    ):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

        # Setup logger
        logging.basicConfig(
            filename="/tmp/daemon.log",
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )

    def daemonize(self):
        """
        UNIX double-fork trick to daemonize the process.
        """

        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as e:
            logging.error("fork #1 failed: %d (%s)", e.errno, e.strerror)
            sys.exit(1)

        # decouple from environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            logging.error("fork #2 failed: %d (%s)", e.errno, e.strerror)
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()

        with open(self.stdin, "rb", 0) as si, \
             open(self.stdout, "ab+", 0) as so, \
             open(self.stderr, "ab+", 0) as se:
            os.dup2(si.fileno(), sys.stdin.fileno())
            os.dup2(so.fileno(), sys.stdout.fileno())
            os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        with open(self.pidfile, "w+") as f:
            f.write("%s\n" % pid)

        logging.info("Daemon started with pid %s", pid)

    def delpid(self):
        if os.path.exists(self.pidfile):
            os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        pid = None
        try:
            with open(self.pidfile, "r") as pf:
                pid = int(pf.read().strip())
        except (IOError, ValueError):
            pid = None

        if pid:
            message = f"pidfile {self.pidfile} already exists. Daemon already running?\n"
            sys.stderr.write(message)
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self):
        """
        Stop the daemon
        """
        try:
            with open(self.pidfile, "r") as pf:
                pid = int(pf.read().strip())
        except (IOError, ValueError):
            pid = None

        if not pid:
            sys.stderr.write(
                f"pidfile {self.pidfile} does not exist. Daemon not running?\n"
            )
            return  # not an error in a restart

        # Kill the process
        try:
            while True:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            if "No such process" in str(err):
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
                logging.info("Daemon process stopped")
            else:
                logging.error(str(err))
                sys.exit(1)

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        time.sleep(0.5)  # small delay for cleanup
        self.start()

    def status(self):
        """
        Check if daemon is running
        """
        try:
            with open(self.pidfile) as pf:
                pid = int(pf.read().strip())
            os.kill(pid, 0)  # test if process exists
        except Exception:
            return False
        return True

    def run(self):
        """
        Override this method in subclass.
        """
        raise NotImplementedError("You must override 'run()' in subclass")


# Example subclass
if __name__ == "__main__":

    class MyDaemon(Daemon):
        def run(self):
            while True:
                logging.info("Daemon alive - doing work...")
                time.sleep(5)

    daemon = MyDaemon("/tmp/mydaemon.pid")

    if len(sys.argv) == 2:
        cmd = sys.argv[1].lower()
        if cmd == "start":
            daemon.start()
        elif cmd == "stop":
            daemon.stop()
        elif cmd == "restart":
            daemon.restart()
        elif cmd == "status":
            running = daemon.status()
            print("Running" if running else "Not running")
            sys.exit(0 if running else 1)
        else:
            print("Unknown command")
            sys.exit(2)
    else:
        print(f"Usage: {sys.argv[0]} start|stop|restart|status")
        sys.exit(2)
##
##
