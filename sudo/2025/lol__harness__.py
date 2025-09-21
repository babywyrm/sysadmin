import argparse
import os
import subprocess
import shutil
import tempfile
import sys
import logging

# Harness constants
CHROOT = "./ctf_chroot"
LIB_DIR = os.path.join(CHROOT, "lib")
ETC_DIR = os.path.join(CHROOT, "etc")
PAYLOAD_C = "payload.c"
LIB_NAME = "libnss_dummy.so.2"
PAYLOAD_SO = os.path.join(LIB_DIR, LIB_NAME)
NSSWITCH = os.path.join(ETC_DIR, "nsswitch.conf")


def setup_logging(verbose=False):
    """Set up logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="[%(levelname)s] %(message)s", level=level
    )


def setup_chroot():
    """Prepare fake chroot directory structure."""
    logging.info("Setting up chroot directories...")
    os.makedirs(LIB_DIR, exist_ok=True)
    os.makedirs(ETC_DIR, exist_ok=True)
    logging.debug(f"Created {LIB_DIR} and {ETC_DIR}")


def write_nsswitch(service_name="dummy"):
    """Write a fake nsswitch.conf for testing."""
    logging.info("Writing fake nsswitch.conf...")
    with open(NSSWITCH, "w") as f:
        f.write(f"passwd: {service_name}\n")
        f.write("group: files\n")
        f.write("shadow: files\n")
    logging.debug(f"Written nsswitch.conf to {NSSWITCH}")


def write_payload(payload_code=None):
    """Write out a placeholder payload in C."""
    if payload_code is None:
        # Safe placeholder
        payload_code = r'''
#include <stdio.h>
void __attribute__((constructor)) init() {
    printf("** Placeholder payload executed in C harness **\n");
}
'''
    logging.info("Writing payload source...")
    with open(PAYLOAD_C, "w") as f:
        f.write(payload_code)
    logging.debug(f"Wrote payload C source to {PAYLOAD_C}")


def compile_payload():
    """Simulate compilation of a shared object."""
    logging.info("Compiling payload into shared object (simulated)...")
    try:
        subprocess.run(
            ["gcc", "-fPIC", "-shared", "-o", PAYLOAD_SO, PAYLOAD_C],
            check=True,
        )
        logging.debug(f"Compiled shared object to {PAYLOAD_SO}")
    except FileNotFoundError:
        logging.warning("GCC not found — skipping real compilation.")


def cleanup():
    """Clean up temporary payload source and files."""
    logging.info("Cleaning up payload and chroot...")
    if os.path.exists(PAYLOAD_C):
        os.remove(PAYLOAD_C)
    if os.path.exists(CHROOT):
        shutil.rmtree(CHROOT, ignore_errors=True)
    logging.debug("Cleanup complete.")


def run_demo(cmd="id"):
    """Demo run step (safe placeholder)."""
    logging.info("Running demo command (no exploit)...")
    subprocess.run(["echo", f"Would run '{cmd}' in chroot {CHROOT}"])


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generic CTF Harness (safe template). "
        "Replace payload source in lab only.",
        epilog="✅ Safe to share: contains NO exploit by default.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug output",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.verbose)

    try:
        setup_chroot()
        write_nsswitch(service_name="dummy")
        write_payload()  # placeholder payload
        compile_payload()
        run_demo()
    finally:
        cleanup()


if __name__ == "__main__":
    main()
