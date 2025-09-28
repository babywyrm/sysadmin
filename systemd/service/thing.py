#!/usr/bin/env python3
import logging
import signal
import sys
import time
from threading import Event

# Optional: systemd notifications
try:
    from systemd import daemon
    SYSTEMD_NOTIFY = True
except ImportError:
    SYSTEMD_NOTIFY = False

stop_event = Event()

def handle_signal(signum, frame):
    logging.info("Received signal %s, shutting down...", signum)
    stop_event.set()

def run_bot():
    """
    Replace this with your CTF bot’s core logic.
    For example: probing cluster services, hitting endpoints, parsing responses.
    """
    logging.info("Bot tick...")
    time.sleep(5)  # simulate work

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    logging.info("Bot service starting...")

    # Tell systemd we’re ready
    if SYSTEMD_NOTIFY:
        daemon.notify("READY=1")

    # Register signal handlers
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, handle_signal)

    while not stop_event.is_set():
        try:
            run_bot()
        except Exception as e:
            logging.exception("Bot error: %s", e)
            time.sleep(2)

    logging.info("Bot service stopped cleanly.")

if __name__ == "__main__":
    main()
