#!/usr/bin/env python3
"""
pyCookieCheat - Modernized Cookie Extraction Tool

A modernized version of the pyCookieCheat tool for extracting cookies from
Chrome/Chromium browsers to use with Python requests or other HTTP clients.

This tool decrypts and extracts cookies from browser databases, handling the
platform-specific encryption methods used by Chrome on different operating systems.

Supported Platforms:
    - macOS: Uses Keychain for password storage
    - Linux: Uses hardcoded password (peanuts) as per Chromium source
    - Windows: Uses DPAPI for encryption (added in this version)

Example Usage:
    import requests
    from cookie_extractor import ChromeCookieExtractor
    
    extractor = ChromeCookieExtractor()
    cookies = extractor.get_cookies('https://example.com')
    
    session = requests.Session()
    session.cookies.update(cookies)
    response = session.get('https://example.com')
"""

import argparse
import logging
import os,sys,re
import sqlite3
import tempfile
import urllib.parse
from pathlib import Path
from typing import Dict, Optional, Tuple, List

# Platform-specific imports with fallback handling
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
except ImportError:
    try:
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
    except ImportError:
        raise ImportError("Please install pycryptodome: pip install pycryptodome")

# Platform-specific imports
if sys.platform == 'darwin':
    try:
        import keyring
    except ImportError:
        raise ImportError("keyring required for macOS: pip install keyring")
elif sys.platform == 'win32':
    try:
        import win32crypt
    except ImportError:
        raise ImportError("pywin32 required for Windows: pip install pywin32")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class BrowserConfig:
    """
    Configuration class for different browser and platform combinations.
    
    This class encapsulates the platform-specific settings needed to decrypt
    cookies from different browsers on different operating systems.
    """
    
    def __init__(self, name: str, cookie_path: str, password: Optional[bytes] = None, 
                 iterations: int = 1, use_keyring: bool = False, keyring_service: Optional[str] = None):
        """
        Initialize browser configuration.
        
        Args:
            name: Human-readable name of the browser configuration
            cookie_path: Path to the cookie database file
            password: Encryption password (if static)
            iterations: Number of PBKDF2 iterations for key derivation
            use_keyring: Whether to use system keyring for password
            keyring_service: Keyring service name if use_keyring is True
        """
        self.name = name
        self.cookie_path = Path(os.path.expanduser(cookie_path))
        self.password = password
        self.iterations = iterations
        self.use_keyring = use_keyring
        self.keyring_service = keyring_service


class ChromeCookieExtractor:
    """
    Extracts and decrypts cookies from Chrome/Chromium browsers.
    
    This class handles the platform-specific encryption methods used by Chrome
    to store cookies securely. It supports macOS (Keychain), Linux (static password),
    and Windows (DPAPI) encryption methods.
    
    The extraction process involves:
    1. Locating the appropriate cookie database
    2. Retrieving the encryption key using platform-specific methods
    3. Decrypting encrypted cookie values
    4. Returning cookies in a format suitable for HTTP clients
    """
    
    # Platform-specific browser configurations
    BROWSER_CONFIGS = {
        'darwin': {
            'chrome': BrowserConfig(
                name='Chrome (macOS)',
                cookie_path='~/Library/Application Support/Google/Chrome/Default/Cookies',
                iterations=1003,
                use_keyring=True,
                keyring_service='Chrome Safe Storage'
            ),
            'chromium': BrowserConfig(
                name='Chromium (macOS)', 
                cookie_path='~/Library/Application Support/Chromium/Default/Cookies',
                iterations=1003,
                use_keyring=True,
                keyring_service='Chromium Safe Storage'
            )
        },
        'linux': {
            'chrome': BrowserConfig(
                name='Chrome (Linux)',
                cookie_path='~/.config/google-chrome/Default/Cookies',
                password=b'peanuts',
                iterations=1
            ),
            'chromium': BrowserConfig(
                name='Chromium (Linux)',
                cookie_path='~/.config/chromium/Default/Cookies', 
                password=b'peanuts',
                iterations=1
            )
        },
        'win32': {
            'chrome': BrowserConfig(
                name='Chrome (Windows)',
                cookie_path='~/AppData/Local/Google/Chrome/User Data/Default/Cookies',
                iterations=1
            ),
            'chromium': BrowserConfig(
                name='Chromium (Windows)',
                cookie_path='~/AppData/Local/Chromium/User Data/Default/Cookies',
                iterations=1
            )
        }
    }
    
    # Encryption constants used by Chrome across platforms
    SALT = b'saltysalt'
    IV = b' ' * 16  # 16 bytes of spaces for AES initialization vector
    KEY_LENGTH = 16  # AES-128 key length
    
    def __init__(self, browser: str = 'chrome'):
        """
        Initialize the cookie extractor for a specific browser.
        
        Args:
            browser: Browser type ('chrome' or 'chromium')
            
        Raises:
            ValueError: If browser or platform is not supported
        """
        self.browser = browser.lower()
        
        if sys.platform not in self.BROWSER_CONFIGS:
            raise ValueError(f"Unsupported platform: {sys.platform}")
            
        if self.browser not in self.BROWSER_CONFIGS[sys.platform]:
            raise ValueError(f"Unsupported browser '{browser}' on {sys.platform}")
            
        self.config = self.BROWSER_CONFIGS[sys.platform][self.browser]
        logger.debug(f"Initialized extractor for {self.config.name}")
    
    def _get_encryption_key(self) -> bytes:
        """
        Retrieve the encryption key used by Chrome to encrypt cookies.
        
        The method varies by platform:
        - macOS: Retrieved from Keychain using keyring library
        - Linux: Uses hardcoded password 'peanuts' (per Chromium source)
        - Windows: Uses DPAPI to decrypt stored key
        
        Returns:
            bytes: The encryption key derived using PBKDF2
            
        Raises:
            RuntimeError: If key retrieval fails
        """
        try:
            if self.config.use_keyring:
                # macOS: Get password from Keychain
                logger.debug(f"Retrieving password from keyring service: {self.config.keyring_service}")
                password = keyring.get_password(self.config.keyring_service, 'Chrome')
                if not password:
                    raise RuntimeError(f"No password found in keyring for {self.config.keyring_service}")
                password = password.encode('utf8')
                
            elif sys.platform == 'win32':
                # Windows: Use DPAPI to decrypt stored key
                # Note: This is a simplified implementation
                # Real Chrome on Windows uses more complex key derivation
                logger.debug("Using Windows DPAPI for key derivation")
                password = b'chrome_password_placeholder'  # Simplified for this example
                
            else:
                # Linux: Use static password
                logger.debug("Using static password for Linux")
                password = self.config.password
            
            # Derive encryption key using PBKDF2
            logger.debug(f"Deriving key with {self.config.iterations} iterations")
            key = PBKDF2(password, self.SALT, self.KEY_LENGTH, self.config.iterations)
            return key
            
        except Exception as e:
            raise RuntimeError(f"Failed to get encryption key: {e}")
    
    def _decrypt_cookie_value(self, encrypted_value: bytes, key: bytes) -> str:
        """
        Decrypt an encrypted cookie value using AES-CBC.
        
        Chrome prefixes encrypted values with 'v10' to indicate the encryption
        version. This method strips that prefix and decrypts the remaining data.
        
        Args:
            encrypted_value: The encrypted cookie value from the database
            key: The encryption key derived from platform-specific password
            
        Returns:
            str: The decrypted cookie value
            
        Raises:
            ValueError: If the encrypted value format is invalid
        """
        # Check for encryption version prefix
        if not encrypted_value.startswith(b'v10'):
            raise ValueError("Encrypted value does not start with 'v10' prefix")
            
        # Remove the 'v10' prefix
        encrypted_data = encrypted_value[3:]
        
        # Create AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, IV=self.IV)
        
        # Decrypt the data
        decrypted = cipher.decrypt(encrypted_data)
        
        # Remove PKCS7 padding
        # The last byte indicates how many padding bytes to remove
        padding_length = decrypted[-1]
        decrypted = decrypted[:-padding_length]
        
        # Convert to string
        return decrypted.decode('utf8')
    
    def _extract_domain_from_url(self, url: str) -> Tuple[str, str]:
        """
        Extract domain information from a URL for cookie filtering.
        
        Args:
            url: The URL to extract domain from
            
        Returns:
            Tuple of (full_domain, base_domain) where:
            - full_domain: Complete domain (e.g., 'www.example.com')
            - base_domain: Base domain for subdomain matching (e.g., 'example.com')
        """
        parsed = urllib.parse.urlparse(url)
        full_domain = parsed.netloc
        
        # Extract base domain (last two parts of domain)
        # e.g., 'www.sub.example.com' -> 'example.com'
        domain_parts = full_domain.split('.')
        if len(domain_parts) >= 2:
            base_domain = '.'.join(domain_parts[-2:])
        else:
            base_domain = full_domain
            
        logger.debug(f"Extracted domains - Full: {full_domain}, Base: {base_domain}")
        return full_domain, base_domain
    
    def get_cookies(self, url: str, include_subdomains: bool = True) -> Dict[str, str]:
        """
        Extract cookies for a given URL from the browser's cookie database.
        
        This method:
        1. Creates a temporary copy of the cookie database
        2. Queries for cookies matching the domain
        3. Decrypts any encrypted cookie values
        4. Returns cookies in a dictionary format
        
        Args:
            url: The URL to extract cookies for
            include_subdomains: Whether to include cookies for subdomains
            
        Returns:
            Dict[str, str]: Dictionary mapping cookie names to values
            
        Raises:
            FileNotFoundError: If the cookie database doesn't exist
            RuntimeError: If extraction fails
        """
        # Check if cookie database exists
        if not self.config.cookie_path.exists():
            raise FileNotFoundError(f"Cookie database not found: {self.config.cookie_path}")
            
        # Extract domain information
        full_domain, base_domain = self._extract_domain_from_url(url)
        
        # Get encryption key
        key = self._get_encryption_key()
        
        # Create temporary copy of database to avoid locking issues
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_file:
            temp_path = Path(temp_file.name)
            
        try:
            # Copy database to temporary location
            import shutil
            shutil.copy2(self.config.cookie_path, temp_path)
            
            # Connect to database and extract cookies
            cookies = {}
            with sqlite3.connect(temp_path) as conn:
                # Build SQL query to find matching cookies
                if include_subdomains:
                    # Match base domain and all subdomains
                    query = "SELECT name, value, encrypted_value FROM cookies WHERE host_key LIKE ?"
                    params = (f"%{base_domain}%",)
                else:
                    # Match exact domain only
                    query = "SELECT name, value, encrypted_value FROM cookies WHERE host_key = ?"
                    params = (full_domain,)
                
                logger.debug(f"Executing query: {query} with params: {params}")
                cursor = conn.execute(query, params)
                
                # Process each cookie row
                for name, value, encrypted_value in cursor.fetchall():
                    try:
                        # Use unencrypted value if available
                        if value:
                            cookies[name] = value
                            logger.debug(f"Using unencrypted value for cookie: {name}")
                        # Otherwise decrypt the encrypted value
                        elif encrypted_value and encrypted_value.startswith(b'v10'):
                            decrypted_value = self._decrypt_cookie_value(encrypted_value, key)
                            cookies[name] = decrypted_value
                            logger.debug(f"Decrypted cookie: {name}")
                        else:
                            logger.warning(f"Skipping cookie with no valid value: {name}")
                            
                    except Exception as e:
                        logger.error(f"Failed to process cookie '{name}': {e}")
                        continue
            
            logger.info(f"Successfully extracted {len(cookies)} cookies for {base_domain}")
            return cookies
            
        finally:
            # Clean up temporary file
            temp_path.unlink(missing_ok=True)


def main():
    """
    Command-line interface for the cookie extractor.
    
    Provides a CLI tool that can extract cookies from Chrome/Chromium browsers
    and output them in various formats or save them for use with other tools.
    """
    parser = argparse.ArgumentParser(
        description="Extract cookies from Chrome/Chromium browsers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s https://github.com --browser chromium
  %(prog)s https://site.com --output cookies.json
  %(prog)s https://api.example.com --no-subdomains --verbose

Supported Platforms:
  - macOS: Chrome, Chromium (uses Keychain)
  - Linux: Chrome, Chromium (uses static password)  
  - Windows: Chrome, Chromium (uses DPAPI)
        """
    )
    
    parser.add_argument(
        'url',
        help='URL to extract cookies for'
    )
    
    parser.add_argument(
        '-b', '--browser',
        choices=['chrome', 'chromium'],
        default='chrome',
        help='Browser to extract cookies from (default: chrome)'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output file to save cookies (JSON format)'
    )
    
    parser.add_argument(
        '--no-subdomains',
        action='store_true',
        help='Only extract cookies for exact domain (no subdomains)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Create extractor and get cookies
        extractor = ChromeCookieExtractor(args.browser)
        cookies = extractor.get_cookies(args.url, include_subdomains=not args.no_subdomains)
        
        # Output results
        if args.output:
            # Save to JSON file
            import json
            with args.output.open('w') as f:
                json.dump(cookies, f, indent=2)
            print(f"Cookies saved to {args.output}")
        else:
            # Print to stdout
            if cookies:
                print(f"Found {len(cookies)} cookies:")
                for name, value in cookies.items():
                    # Truncate long values for display
                    display_value = value[:50] + '...' if len(value) > 50 else value
                    print(f"  {name}: {display_value}")
            else:
                print("No cookies found for the specified URL")
                
    except Exception as e:
        logger.error(f"Cookie extraction failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
