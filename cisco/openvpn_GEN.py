#!/usr/bin/env python3
"""
OpenVPN Certificate Generator

Generates OpenVPN client configuration files (.ovpn) with embedded certificates.. (updated)..
Can also create a new Certificate Authority if needed.

Requirements:
    pip install pyopenssl

Platform Support:
    - Linux: Full support
    - macOS: Full support
    - Windows: Should work but untested

Usage Examples:

    1. Create a new Certificate Authority:
       ./script.py create-ca \\
         --common-name "My VPN CA" \\
         --output-cert ca.crt \\
         --output-key ca.key

    2. Generate client configuration:
       ./script.py generate-client \\
         --ca-cert ca.crt \\
         --ca-key ca.key \\
         --common-config common.txt \\
         --client-name john_doe \\
         --output john_doe.ovpn

    3. Create everything from scratch:
       # First create the CA
       ./script.py create-ca --common-name "VPN-CA" \\
         --output-cert ca.crt --output-key ca.key
       
       # Create common config file
       cat > common.txt << 'EOF'
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
auth SHA256
verb 3
EOF
       
       # Generate client config
       ./script.py generate-client --ca-cert ca.crt --ca-key ca.key \\
         --common-config common.txt --client-name client1 \\
         --output client1.ovpn

Certificate Management:

    The script maintains a serial number file (serials.txt) to track issued
    certificates. Each client gets a unique serial number automatically.
    
    To manually specify a serial:
       ./script.py generate-client ... --serial 0x0C
    
    Serial numbers can be decimal (12) or hex (0x0C).

Security Notes:

    - Keep ca.key secure and backed up
    - Use strong passphrases in production (future enhancement)
    - Default validity is 10 years
    - Certificates use SHA256 signatures with 2048-bit RSA keys
"""

import argparse
import sys
from pathlib import Path
from typing import Union, Optional
from datetime import datetime

try:
    from OpenSSL import crypto
except ImportError:
    print(
        "[!] Error: pyopenssl not found. Install with: pip install pyopenssl",
        file=sys.stderr,
    )
    sys.exit(1)


class CertificateError(Exception):
    """Custom exception for certificate-related errors."""
    pass


class SerialNumberManager:
    """Manages certificate serial numbers to ensure uniqueness."""

    def __init__(self, serial_file: Path = Path("serials.txt")):
        self.serial_file = serial_file

    def get_next_serial(self) -> int:
        """Get the next available serial number."""
        if not self.serial_file.exists():
            self.serial_file.write_text("1\n")
            return 1

        try:
            current = int(self.serial_file.read_text().strip())
            next_serial = current + 1
            self.serial_file.write_text(f"{next_serial}\n")
            return next_serial
        except ValueError:
            raise CertificateError(
                f"Invalid serial file format: {self.serial_file}"
            )

    def record_serial(self, serial: int) -> None:
        """Record a manually specified serial number."""
        if not self.serial_file.exists():
            self.serial_file.write_text(f"{serial + 1}\n")
            return

        try:
            current = int(self.serial_file.read_text().strip())
            if serial >= current:
                self.serial_file.write_text(f"{serial + 1}\n")
        except ValueError:
            self.serial_file.write_text(f"{serial + 1}\n")


class CertificateGenerator:
    """Handles certificate and key generation using OpenSSL."""

    DEFAULT_HASH_ALGORITHM = "sha256WithRSAEncryption"
    DEFAULT_KEY_SIZE = 2048
    DEFAULT_VALIDITY_YEARS = 10

    @staticmethod
    def generate_keypair(
        algorithm: int = crypto.TYPE_RSA, bits: int = DEFAULT_KEY_SIZE
    ) -> crypto.PKey:
        """
        Generate a new public/private key pair.

        Args:
            algorithm: Key algorithm (default: RSA)
            bits: Key size in bits (default: 2048)

        Returns:
            Generated private key
        """
        pkey = crypto.PKey()
        pkey.generate_key(algorithm, bits)
        return pkey

    @staticmethod
    def create_csr(
        pkey: crypto.PKey,
        common_name: str,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        organizational_unit: Optional[str] = None,
        email: Optional[str] = None,
        hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
    ) -> crypto.X509Req:
        """
        Create a Certificate Signing Request (CSR).

        Args:
            pkey: Private key for the CSR
            common_name: Common Name (CN) - typically client/server name
            country: Country code (C) - 2 letter code
            state: State or Province (ST)
            locality: City/Locality (L)
            organization: Organization name (O)
            organizational_unit: Department/Unit (OU)
            email: Email address
            hash_algorithm: Signature algorithm

        Returns:
            Certificate Signing Request
        """
        req = crypto.X509Req()
        subject = req.get_subject()

        if country:
            subject.C = country
        if state:
            subject.ST = state
        if locality:
            subject.L = locality
        if organization:
            subject.O = organization
        if organizational_unit:
            subject.OU = organizational_unit
        if common_name:
            subject.CN = common_name
        if email:
            subject.emailAddress = email

        req.set_pubkey(pkey)
        req.sign(pkey, hash_algorithm)
        return req

    @classmethod
    def create_ca(
        cls,
        common_name: str,
        country: str = "",
        state: str = "",
        locality: str = "",
        organization: str = "",
        organizational_unit: str = "",
        email: str = "",
        validity_years: int = DEFAULT_VALIDITY_YEARS,
    ) -> tuple[crypto.X509, crypto.PKey]:
        """
        Create a self-signed Certificate Authority.

        This CA can be used to sign client and server certificates.
        The CA certificate and private key should be kept secure.

        Args:
            common_name: Name for the CA (e.g., "My VPN CA")
            country: Country code
            state: State or Province
            locality: City
            organization: Organization name
            organizational_unit: Department
            email: Contact email
            validity_years: How many years the CA is valid

        Returns:
            Tuple of (CA certificate, CA private key)
        """
        ca_key = cls.generate_keypair()
        ca_req = cls.create_csr(
            ca_key,
            common_name,
            country,
            state,
            locality,
            organization,
            organizational_unit,
            email,
        )

        ca_cert = crypto.X509()
        ca_cert.set_serial_number(0)
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * validity_years)
        ca_cert.set_issuer(ca_req.get_subject())
        ca_cert.set_subject(ca_req.get_subject())
        ca_cert.set_pubkey(ca_req.get_pubkey())
        ca_cert.set_version(2)

        # CA extensions
        ca_cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            crypto.X509Extension(
                b"subjectKeyIdentifier", True, b"hash", subject=ca_cert
            ),
        ])

        ca_cert.add_extensions([
            crypto.X509Extension(
                b"authorityKeyIdentifier",
                False,
                b"issuer:always, keyid:always",
                issuer=ca_cert,
                subject=ca_cert,
            )
        ])

        ca_cert.sign(ca_key, cls.DEFAULT_HASH_ALGORITHM)
        return ca_cert, ca_key

    @classmethod
    def create_client_certificate(
        cls,
        csr: crypto.X509Req,
        ca_key: crypto.PKey,
        ca_cert: crypto.X509,
        serial: int,
        validity_years: int = DEFAULT_VALIDITY_YEARS,
    ) -> crypto.X509:
        """
        Create and sign a client certificate.

        Args:
            csr: Certificate Signing Request
            ca_key: CA private key for signing
            ca_cert: CA certificate
            serial: Unique serial number for this certificate
            validity_years: How many years the certificate is valid

        Returns:
            Signed client certificate
        """
        cert = crypto.X509()
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * validity_years)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        cert.set_version(2)

        # Client certificate extensions
        extensions = [
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
            crypto.X509Extension(
                b"subjectKeyIdentifier", False, b"hash", subject=cert
            ),
            crypto.X509Extension(
                b"authorityKeyIdentifier",
                False,
                b"keyid:always,issuer:always",
                subject=ca_cert,
                issuer=ca_cert,
            ),
        ]

        cert.add_extensions(extensions)
        cert.sign(ca_key, cls.DEFAULT_HASH_ALGORITHM)
        return cert


class FileHandler:
    """Handles reading and writing certificate/key files."""

    @staticmethod
    def dump_to_bytes(
        material: Union[crypto.X509, crypto.PKey, crypto.X509Req],
        file_type: int = crypto.FILETYPE_PEM,
    ) -> bytes:
        """
        Dump certificate material to bytes.

        Args:
            material: Certificate, key, or CSR to dump
            file_type: Output format (PEM or DER)

        Returns:
            Binary representation
        """
        if isinstance(material, crypto.X509):
            return crypto.dump_certificate(file_type, material)
        elif isinstance(material, crypto.PKey):
            return crypto.dump_privatekey(file_type, material)
        elif isinstance(material, crypto.X509Req):
            return crypto.dump_certificate_request(file_type, material)
        else:
            raise CertificateError(
                f"Unknown material type: {type(material)}"
            )

    @staticmethod
    def dump_to_string(
        material: Union[crypto.X509, crypto.PKey, crypto.X509Req]
    ) -> str:
        """
        Dump certificate material to string (PEM format).

        Args:
            material: Certificate, key, or CSR to dump

        Returns:
            PEM-formatted string
        """
        return FileHandler.dump_to_bytes(material).decode("utf-8")

    @staticmethod
    def save_to_file(
        material: Union[crypto.X509, crypto.PKey],
        filepath: Path,
        file_type: int = crypto.FILETYPE_PEM,
    ) -> None:
        """
        Save certificate or key to file.

        Args:
            material: Certificate or key to save
            filepath: Destination file path
            file_type: Output format (PEM or DER)
        """
        data = FileHandler.dump_to_bytes(material, file_type)
        filepath.write_bytes(data)

        # Set restrictive permissions on key files
        if isinstance(material, crypto.PKey):
            filepath.chmod(0o600)

    @staticmethod
    def load_from_file(
        filepath: Path, obj_type: type, file_type: int = crypto.FILETYPE_PEM
    ):
        """
        Load certificate material from file.

        Args:
            filepath: Path to file
            obj_type: Type to load (crypto.X509, crypto.PKey, etc.)
            file_type: File format (PEM or DER)

        Returns:
            Loaded certificate material
        """
        if obj_type is crypto.X509:
            load_func = crypto.load_certificate
        elif obj_type is crypto.X509Req:
            load_func = crypto.load_certificate_request
        elif obj_type is crypto.PKey:
            load_func = crypto.load_privatekey
        else:
            raise CertificateError(f"Unsupported material type: {obj_type}")

        try:
            with open(filepath, "rb") as f:
                data = f.read()
            return load_func(file_type, data)
        except FileNotFoundError:
            raise CertificateError(f"File not found: {filepath}")
        except Exception as e:
            raise CertificateError(f"Error loading {filepath}: {e}")

    @staticmethod
    def load_certificate(filepath: Path) -> crypto.X509:
        """Load certificate from file."""
        return FileHandler.load_from_file(filepath, crypto.X509)

    @staticmethod
    def load_private_key(filepath: Path) -> crypto.PKey:
        """Load private key from file."""
        return FileHandler.load_from_file(filepath, crypto.PKey)


class OpenVPNConfigGenerator:
    """Generates OpenVPN configuration files with embedded certificates."""

    def __init__(
        self,
        ca_cert_path: Path,
        ca_key_path: Path,
        common_config_path: Path,
        serial_manager: Optional[SerialNumberManager] = None,
    ):
        """
        Initialize the generator.

        Args:
            ca_cert_path: Path to CA certificate
            ca_key_path: Path to CA private key
            common_config_path: Path to common OpenVPN options file
            serial_manager: Optional serial number manager
        """
        self.ca_cert_path = Path(ca_cert_path)
        self.ca_key_path = Path(ca_key_path)
        self.common_config_path = Path(common_config_path)
        self.serial_manager = serial_manager or SerialNumberManager()

        # Validate files exist
        for path in [
            self.ca_cert_path,
            self.ca_key_path,
            self.common_config_path,
        ]:
            if not path.exists():
                raise CertificateError(f"Required file not found: {path}")

    def generate_client_config(
        self,
        client_name: str,
        output_path: Path,
        serial: Optional[int] = None,
        validity_years: int = CertificateGenerator.DEFAULT_VALIDITY_YEARS,
    ) -> None:
        """
        Generate a complete .ovpn file for a client.

        Args:
            client_name: Common name for the client certificate
            output_path: Where to write the .ovpn file
            serial: Optional serial number (auto-generated if None)
            validity_years: Certificate validity period
        """
        # Load CA materials
        ca_cert = FileHandler.load_certificate(self.ca_cert_path)
        ca_key = FileHandler.load_private_key(self.ca_key_path)

        # Get or assign serial number
        if serial is None:
            serial = self.serial_manager.get_next_serial()
        else:
            self.serial_manager.record_serial(serial)

        # Generate client certificate
        client_key = CertificateGenerator.generate_keypair()
        client_csr = CertificateGenerator.create_csr(client_key, client_name)
        client_cert = CertificateGenerator.create_client_certificate(
            client_csr, ca_key, ca_cert, serial, validity_years
        )

        # Load common configuration
        common_config = self.common_config_path.read_text()

        # Build .ovpn content
        ovpn_content = self._build_ovpn_content(
            common_config, ca_cert, client_cert, client_key
        )

        # Write output file
        output_path = Path(output_path)
        output_path.write_text(ovpn_content)
        output_path.chmod(0o600)  # Restrict permissions

        print(f"[+] Generated {output_path}")
        print(f"    Serial: {serial} (0x{serial:X})")
        print(f"    CN: {client_name}")
        print(f"    Valid for: {validity_years} years")

    @staticmethod
    def _build_ovpn_content(
        common_config: str,
        ca_cert: crypto.X509,
        client_cert: crypto.X509,
        client_key: crypto.PKey,
    ) -> str:
        """
        Build the complete .ovpn file content.

        The .ovpn file contains:
        - Common configuration options
        - Embedded CA certificate
        - Embedded client certificate
        - Embedded client private key

        Args:
            common_config: Common OpenVPN settings
            ca_cert: CA certificate
            client_cert: Client certificate
            client_key: Client private key

        Returns:
            Complete .ovpn file content
        """
        ca_pem = FileHandler.dump_to_string(ca_cert)
        cert_pem = FileHandler.dump_to_string(client_cert)
        key_pem = FileHandler.dump_to_string(client_key)

        # Ensure common config ends with newline
        if not common_config.endswith("\n"):
            common_config += "\n"

        return (
            f"{common_config}"
            f"<ca>\n{ca_pem}</ca>\n"
            f"<cert>\n{cert_pem}</cert>\n"
            f"<key>\n{key_pem}</key>\n"
        )


def cmd_create_ca(args):
    """Handle 'create-ca' command."""
    print(f"[+] Creating Certificate Authority...")
    print(f"    CN: {args.common_name}")

    ca_cert, ca_key = CertificateGenerator.create_ca(
        common_name=args.common_name,
        country=args.country or "",
        state=args.state or "",
        locality=args.locality or "",
        organization=args.organization or "",
        organizational_unit=args.organizational_unit or "",
        email=args.email or "",
        validity_years=args.validity_years,
    )

    # Save CA certificate and key
    FileHandler.save_to_file(ca_cert, args.output_cert)
    FileHandler.save_to_file(ca_key, args.output_key)

    print(f"[+] CA Certificate: {args.output_cert}")
    print(f"[+] CA Private Key: {args.output_key} (keep secure!)")
    print(f"[+] Valid for: {args.validity_years} years")
    print(
        f"\n[!] IMPORTANT: Back up {args.output_key} and keep it secure!"
    )

    return 0


def cmd_generate_client(args):
    """Handle 'generate-client' command."""
    print(f"[+] Generating client configuration...")
    print(f"    Client: {args.client_name}")

    try:
        generator = OpenVPNConfigGenerator(
            args.ca_cert,
            args.ca_key,
            args.common_config,
            SerialNumberManager(args.serial_file),
        )

        generator.generate_client_config(
            args.client_name,
            args.output,
            args.serial,
            args.validity_years,
        )

        print(f"[+] Success! Client config: {args.output}")
        return 0

    except CertificateError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="OpenVPN Certificate and Configuration Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Command to execute", required=True
    )

    # create-ca command
    ca_parser = subparsers.add_parser(
        "create-ca", help="Create a new Certificate Authority"
    )
    ca_parser.add_argument(
        "--common-name",
        required=True,
        help="Common Name for the CA (e.g., 'My VPN CA')",
    )
    ca_parser.add_argument("--country", help="Country code (e.g., 'US')")
    ca_parser.add_argument("--state", help="State or Province")
    ca_parser.add_argument("--locality", help="City or Locality")
    ca_parser.add_argument("--organization", help="Organization name")
    ca_parser.add_argument(
        "--organizational-unit", help="Organizational Unit/Department"
    )
    ca_parser.add_argument("--email", help="Email address")
    ca_parser.add_argument(
        "--validity-years",
        type=int,
        default=CertificateGenerator.DEFAULT_VALIDITY_YEARS,
        help=f"Validity period in years (default: {CertificateGenerator.DEFAULT_VALIDITY_YEARS})",
    )
    ca_parser.add_argument(
        "--output-cert",
        type=Path,
        default=Path("ca.crt"),
        help="Output path for CA certificate (default: ca.crt)",
    )
    ca_parser.add_argument(
        "--output-key",
        type=Path,
        default=Path("ca.key"),
        help="Output path for CA private key (default: ca.key)",
    )

    # generate-client command
    client_parser = subparsers.add_parser(
        "generate-client", help="Generate client configuration"
    )
    client_parser.add_argument(
        "--ca-cert",
        type=Path,
        required=True,
        help="Path to CA certificate file",
    )
    client_parser.add_argument(
        "--ca-key",
        type=Path,
        required=True,
        help="Path to CA private key file",
    )
    client_parser.add_argument(
        "--common-config",
        type=Path,
        required=True,
        help="Path to common OpenVPN configuration file",
    )
    client_parser.add_argument(
        "--client-name",
        required=True,
        help="Common name for the client certificate",
    )
    client_parser.add_argument(
        "--serial",
        type=lambda x: int(x, 0),
        help="Serial number (auto if not specified, supports hex with 0x)",
    )
    client_parser.add_argument(
        "--serial-file",
        type=Path,
        default=Path("serials.txt"),
        help="Serial number tracking file (default: serials.txt)",
    )
    client_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output path for the .ovpn file",
    )
    client_parser.add_argument(
        "--validity-years",
        type=int,
        default=CertificateGenerator.DEFAULT_VALIDITY_YEARS,
        help=f"Certificate validity in years (default: {CertificateGenerator.DEFAULT_VALIDITY_YEARS})",
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    try:
        args = parse_args()

        if args.command == "create-ca":
            return cmd_create_ca(args)
        elif args.command == "generate-client":
            return cmd_generate_client(args)
        else:
            print(f"[!] Unknown command: {args.command}", file=sys.stderr)
            return 1

    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

##
##
# Create CA
./script.py create-ca \
  --common-name "My VPN CA" \
  --organization "My Company" \
  --country US \
  --output-cert ca.crt \
  --output-key ca.key

# Create common config
cat > common.txt << 'EOF'
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
verb 3
EOF

# Generate client
./script.py generate-client \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --common-config common.txt \
  --client-name john_doe \
  --output john_doe.ovpn
##
##
for client in alice bob charlie; do
  ./script.py generate-client \
    --ca-cert ca.crt \
    --ca-key ca.key \
    --common-config common.txt \
    --client-name "$client" \
    --output "${client}.ovpn"
done
##
##

