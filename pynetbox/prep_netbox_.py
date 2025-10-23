import os
import sys
import logging
from typing import Any, Dict, List

import pynetbox
import yaml
from pynetbox.core.api import Api
from pynetbox.core.endpoint import Endpoint
from pynetbox.core.response import Record

# --- Configuration ---
DATA_FILE = "netbox_initial.yaml"

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)


class NetBoxProvisioner:
    """A class to provision NetBox objects from a YAML file."""

    def __init__(self, url: str, token: str):
        if not all([url, token]):
            raise ValueError(
                "NETBOX_URL and NETBOX_TOKEN environment variables must be set."
            )
        self.nb: Api = pynetbox.api(url=url, token=token)
        self.cache: Dict[str, Dict[str, Record]] = {
            "sites": {},
            "manufacturers": {},
            "device_types": {},
            "device_roles": {},
            "platforms": {},
            "vrfs": {},
            "vlan_groups": {},
            "vlans": {},
            "prefixes": {},
            "ip_addresses": {},
        }
        logging.info("Successfully connected to NetBox at %s", url)

        # Dynamically load interface mode choices from NetBox
        try:
            choices = self.nb.dcim.choices()
            self.interface_modes = {
                choice["label"]: choice["value"]
                for choice in choices["interface"]["mode"]
            }
            logging.info("Successfully loaded interface mode choices from NetBox.")
        except Exception as e:
            logging.error("Failed to load interface mode choices: %s", e)
            sys.exit(1)

    def _get_or_create(
        self, endpoint: Endpoint, lookup_key: str, data: Dict[str, Any]
    ) -> Record:
        """Generic get-or-create function with caching."""
        lookup_value = data[lookup_key]
        endpoint_name = endpoint.name.replace("-", "_")

        # 1. Check cache first
        if lookup_value in self.cache.get(endpoint_name, {}):
            logging.debug(
                "Found %s '%s' in cache.", endpoint_name, lookup_value
            )
            return self.cache[endpoint_name][lookup_value]

        # 2. Query NetBox if not in cache
        obj = endpoint.get(**{lookup_key: lookup_value})

        # 3. Create if it doesn't exist
        if not obj:
            logging.info(
                "Creating %s '%s'.",
                endpoint_name,
                data.get("name") or data.get("model") or lookup_value,
            )
            try:
                obj = endpoint.create(data)
            except pynetbox.RequestError as e:
                logging.error(
                    "Failed to create %s with data %s: %s",
                    endpoint_name,
                    data,
                    e,
                )
                raise

        # 4. Store in cache and return
        if obj:
            self.cache[endpoint_name][lookup_value] = obj
        return obj

    def run(self, data: Dict[str, Any]):
        """Main method to run the provisioning process."""
        self._process_foundational(data)
        self._process_ipam(data)
        self._process_devices(data)
        logging.info("NetBox provisioning complete.")

    def _process_foundational(self, data: Dict[str, Any]):
        """Process sites, manufacturers, roles, platforms, and types."""
        for item in data.get("sites", []):
            self._get_or_create(self.nb.dcim.sites, "slug", item)

        for item in data.get("manufacturers", []):
            self._get_or_create(self.nb.dcim.manufacturers, "slug", item)

        for item in data.get("device_roles", []):
            self._get_or_create(self.nb.dcim.device_roles, "slug", item)

        for item in data.get("platforms", []):
            item["manufacturer"] = self._get_or_create(
                self.nb.dcim.manufacturers, "slug", {"slug": item.pop("manufacturer_slug")}
            ).id
            self._get_or_create(self.nb.dcim.platforms, "slug", item)

        for item in data.get("device_types", []):
            item["manufacturer"] = self._get_or_create(
                self.nb.dcim.manufacturers, "slug", {"slug": item.pop("manufacturer_slug")}
            ).id
            self._get_or_create(self.nb.dcim.device_types, "slug", item)

    def _process_ipam(self, data: Dict[str, Any]):
        """Process VRFs, VLANs, and Prefixes."""
        for item in data.get("vrfs", []):
            self._get_or_create(self.nb.ipam.vrfs, "rd", item)

        for group in data.get("vlan_groups", []):
            group_data = {
                "name": group["name"],
                "slug": group["slug"],
                "site": self._get_or_create(
                    self.nb.dcim.sites, "slug", {"slug": group["site_slug"]}
                ).id,
            }
            nb_group = self._get_or_create(
                self.nb.ipam.vlan_groups, "slug", group_data
            )

            for vlan in group.get("vlans", []):
                vlan_data = {
                    "name": vlan["name"],
                    "vid": vlan["vid"],
                    "description": vlan.get("description", ""),
                    "site": nb_group.site.id,
                    "group": nb_group.id,
                }
                nb_vlan = self._get_or_create(
                    self.nb.ipam.vlans, "vid", vlan_data
                )
                self.cache["vlans"][vlan["name"]] = nb_vlan # Cache by name for interface lookup

                if "prefix" in vlan:
                    nb_vrf = self._get_or_create(
                        self.nb.ipam.vrfs, "rd", {"rd": vlan["vrf"]}
                    )
                    prefix_data = {
                        "prefix": vlan["prefix"],
                        "description": vlan.get("description", ""),
                        "site": nb_group.site.id,
                        "vrf": nb_vrf.id,
                        "vlan": nb_vlan.id,
                    }
                    self._get_or_create(
                        self.nb.ipam.prefixes, "prefix", prefix_data
                    )
    
    def _process_devices(self, data: Dict[str, Any]):
        """Process devices, interfaces, and IP addresses."""
        for device in data.get("devices", []):
            device_data = {
                "name": device["name"],
                "site": self._get_or_create(
                    self.nb.dcim.sites, "slug", {"slug": device["site_slug"]}
                ).id,
                "manufacturer": self._get_or_create(
                    self.nb.dcim.manufacturers, "slug", {"slug": device["manufacturer_slug"]}
                ).id,
                "device_role": self._get_or_create(
                    self.nb.dcim.device_roles, "slug", {"slug": device["device_role_slug"]}
                ).id,
                "device_type": self._get_or_create(
                    self.nb.dcim.device_types, "slug", {"slug": device["device_type_slug"]}
                ).id,
            }
            nb_device = self._get_or_create(self.nb.dcim.devices, "name", device_data)

            for interface in device.get("interfaces", []):
                self._process_interface(nb_device, interface)

    def _process_interface(self, nb_device: Record, interface_data: Dict[str, Any]):
        """Process a single interface and its associated IPs."""
        logging.info("Configuring interface %s on %s", interface_data["name"], nb_device.name)
        nb_interface = self.nb.dcim.interfaces.get(
            device_id=nb_device.id, name=interface_data["name"]
        )
        update_data = {}

        # Handle simple key-value pairs
        for key in ["description", "mgmt_only", "enabled"]:
            if key in interface_data:
                update_data[key] = interface_data[key]
        
        # Handle interface mode and VLANs
        if "mode" in interface_data:
            update_data["mode"] = self.interface_modes.get(interface_data["mode"])
            if interface_data["mode"] == "Access" and "untagged_vlan" in interface_data:
                vlan_name = interface_data["untagged_vlan"]
                nb_vlan = self.cache["vlans"].get(vlan_name)
                if nb_vlan:
                    update_data["untagged_vlan"] = nb_vlan.id
            elif interface_data["mode"] == "Tagged":
                tagged_vlans = []
                for vlan_name in interface_data.get("tagged_vlans", []):
                    nb_vlan = self.cache["vlans"].get(vlan_name)
                    if nb_vlan:
                        tagged_vlans.append(nb_vlan.id)
                update_data["tagged_vlans"] = tagged_vlans

        if not nb_interface:
            creation_data = {"device": nb_device.id, "name": interface_data["name"], **update_data}
            nb_interface = self.nb.dcim.interfaces.create(creation_data)
        elif update_data:
            nb_interface.update(update_data)
            nb_interface.save()

        # Handle IP addresses
        for ip in interface_data.get("ip_addresses", []):
            nb_vrf = self._get_or_create(self.nb.ipam.vrfs, "rd", {"rd": ip["vrf"]})
            ip_data = {"address": ip["address"], "vrf": nb_vrf.id, "interface": nb_interface.id}
            nb_ip = self._get_or_create(self.nb.ipam.ip_addresses, "address", ip_data)
            
            if ip.get("primary"):
                logging.info("Setting primary IP for %s to %s", nb_device.name, nb_ip.address)
                nb_device.primary_ip4 = nb_ip.id
                nb_device.save()


def main():
    """Main function to orchestrate the provisioning."""
    try:
        with open(DATA_FILE, "r") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        logging.error("Data file not found: %s", DATA_FILE)
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.error("Error parsing YAML file %s: %s", DATA_FILE, e)
        sys.exit(1)

    try:
        provisioner = NetBoxProvisioner(
            url=os.getenv("NETBOX_URL"), token=os.getenv("NETBOX_TOKEN")
        )
        provisioner.run(data)
    except (ValueError, pynetbox.RequestError) as e:
        logging.error("An error occurred: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
