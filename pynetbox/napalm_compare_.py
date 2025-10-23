import os
import sys
import yaml
import difflib
import logging
import argparse
from typing import Dict, Any, List, Generator
from itertools import zip_longest

import napalm
import pynetbox
from netaddr import IPNetwork
from pynetbox.core.query import RequestError

# --- Optional Colorama Import ---
try:
    from colorama import Fore, init
    init(autoreset=True)
except ImportError:
    # Fallback if colorama is not installed
    class ColorFallback:
        def __getattr__(self, name: str) -> str:
            return ""
    Fore = ColorFallback()

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)


class DeviceAuditor:
    """
    Audits a network device's configuration by comparing its live state
    (via NAPALM) with its documented state in NetBox.
    """

    def __init__(
        self,
        device_name: str,
        nb_url: str,
        nb_token: str,
        napalm_user: str,
        napalm_pass: str,
    ):
        if not all([nb_url, nb_token]):
            raise ValueError("NETBOX_URL and NETBOX_TOKEN must be set.")
        if not all([napalm_user, napalm_pass]):
            raise ValueError("NAPALM_USERNAME and NAPALM_PASSWORD must be set.")

        self.device_name = device_name
        self.nb = pynetbox.api(url=nb_url, token=nb_token)
        self.napalm_creds = {"username": napalm_user, "password": napalm_pass}

    def _get_netbox_data(self) -> Dict[str, Any]:
        """Fetches and structures interface data from NetBox."""
        logging.info("Fetching data for device '%s' from NetBox...", self.device_name)
        nb_device = self.nb.dcim.devices.get(name=self.device_name)
        if not nb_device:
            raise FileNotFoundError(f"Device '{self.device_name}' not found in NetBox.")

        nb_ips = self.nb.ipam.ip_addresses.filter(device=self.device_name)
        netbox_interfaces = {}

        for ip_addr in nb_ips:
            if not ip_addr.interface:
                logging.warning("Skipping IP %s, not assigned to an interface.", ip_addr)
                continue

            iface_name = ip_addr.interface.name
            ip_network = IPNetwork(str(ip_addr.address))
            family = f"ipv{ip_network.version}"

            # Initialize interface dict if not present
            if iface_name not in netbox_interfaces:
                netbox_interfaces[iface_name] = {
                    "description": ip_addr.interface.description or "",
                    "ipv4": {},
                    "ipv6": {},
                }

            # Add IP address details
            netbox_interfaces[iface_name][family][str(ip_network.ip)] = {
                "prefix_length": ip_network.prefixlen
            }

        logging.info("Successfully structured data from NetBox.")
        return netbox_interfaces, nb_device

    def _get_device_data(self, nb_device: pynetbox.core.response.Record) -> Dict:
        """Fetches live interface data from the network device using NAPALM."""
        if not nb_device.primary_ip4:
            raise ValueError(f"Device '{self.device_name}' has no primary IPv4 in NetBox.")
        if not nb_device.platform:
            raise ValueError(f"Device '{self.device_name}' has no platform set in NetBox.")

        hostname = str(IPNetwork(nb_device.primary_ip4.address).ip)
        platform = nb_device.platform.slug

        logging.info("Connecting to %s (%s) via NAPALM...", hostname, platform)
        driver = napalm.get_network_driver(platform)
        try:
            with driver(hostname=hostname, **self.napalm_creds) as device:
                logging.info("Fetching interface IPs from device...")
                live_data = device.get_interfaces_ip()
                logging.info("Successfully fetched live data.")
                return live_data
        except Exception as e:
            raise ConnectionError(f"Failed to connect or fetch data from device: {e}")

    @staticmethod
    def _color_diff(diff: List[str]) -> Generator[str, None, None]:
        """Applies color to a diff text output."""
        for line in diff:
            if line.startswith("+"):
                yield Fore.GREEN + line
            elif line.startswith("-"):
                yield Fore.RED + line
            elif line.startswith("?"):
                yield Fore.YELLOW + line
            else:
                yield line

    def _compare_and_print(self, netbox_data: Dict, live_data: Dict):
        """Compares the two data sources and prints a side-by-side diff."""
        # Convert dicts to sorted YAML strings for a consistent, readable diff
        netbox_yaml = yaml.dump(netbox_data, sort_keys=True)
        live_yaml = yaml.dump(live_data, sort_keys=True)

        diff_netbox_vs_live = list(
            self._color_diff(difflib.ndiff(netbox_yaml.splitlines(), live_yaml.splitlines()))
        )
        diff_live_vs_netbox = list(
            self._color_diff(difflib.ndiff(live_yaml.splitlines(), netbox_yaml.splitlines()))
        )

        print("\n" + "=" * 80)
        print(f"Audit for: {self.device_name}")
        print(f"{Fore.RED}- Deletions (in NetBox, not on device){Fore.RESET}")
        print(f"{Fore.GREEN}+ Additions (on device, not in NetBox){Fore.RESET}")
        print("=" * 80)

        header_format = "{:<70}{}"
        line_format = "{:<70}{}"
        print(header_format.format("NETBOX (Intended State)", "DEVICE (Live State)"))
        print(header_format.format("-" * 70, "-" * 70))

        # Use zip_longest to handle diffs of different lengths
        for nb_line, live_line in zip_longest(
            diff_netbox_vs_live, diff_live_vs_netbox, fillvalue=""
        ):
            print(line_format.format(nb_line, live_line))

    def run(self):
        """Executes the full audit process."""
        try:
            netbox_data, nb_device = self._get_netbox_data()
            live_data = self._get_device_data(nb_device)
            self._compare_and_print(netbox_data, live_data)
        except (
            FileNotFoundError,
            ValueError,
            ConnectionError,
            RequestError,
        ) as e:
            logging.error("Audit failed: %s", e)
            sys.exit(1)


def main():
    """Main function to parse arguments and run the audit."""
    parser = argparse.ArgumentParser(
        description="Compare NetBox device data with live state via NAPALM."
    )
    parser.add_argument(
        "device_name",
        help="The name of the device in NetBox to audit.",
    )
    args = parser.parse_args()

    auditor = DeviceAuditor(
        device_name=args.device_name,
        nb_url=os.getenv("NETBOX_URL"),
        nb_token=os.getenv("NETBOX_TOKEN"),
        napalm_user=os.getenv("NAPALM_USERNAME"),
        napalm_pass=os.getenv("NAPALM_PASSWORD"),
    )
    auditor.run()


if __name__ == "__main__":
    main()
