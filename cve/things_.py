
import requests

def get_patched_version_from_nvd(cve_id):
    base_url = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
    url = f"{base_url}{cve_id}"

    try:
        response = requests.get(url)
        response.raise_for_status()

        cve_data = response.json()

        if "result" in cve_data and "CVE_Items" in cve_data["result"]:
            cve_items = cve_data["result"]["CVE_Items"]
            if cve_items:
                cve_item = cve_items[0]
                if "affects" in cve_item and "vendor" in cve_item["affects"]:
                    vendors = cve_item["affects"]["vendor"]
                    for vendor_data in vendors:
                        vendor_name = vendor_data.get("vendor_name", "")
                        if "product" in vendor_data:
                            for product_data in vendor_data["product"]:
                                product_name = product_data.get("product_name", "")
                                if "version" in product_data:
                                    versions = product_data["version"]
                                    for version_data in versions:
                                        if "version_value" in version_data and "version_affected" in version_data:
                                            version_value = version_data["version_value"]
                                            version_affected = version_data["version_affected"]
                                            if version_affected == "TRUE":
                                                return f"NVD: Vendor: {vendor_name}, Product: {product_name}, Fixed Version: {version_value}"

        return "Patched version information not found for this CVE in NVD."

    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

def get_patched_version_from_redhat(cve_id):
    base_url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}"

    try:
        response = requests.get(base_url)
        response.raise_for_status()
        cve_data = response.json()

        if "rpmList" in cve_data:
            return f"Red Hat: {cve_data['rpmList']}"

        return "Patched version information not found for this CVE in Red Hat."

    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

def get_patched_version_from_ubuntu(cve_id):
    base_url = f"https://people.canonical.com/~ubuntu-security/cve/{cve_id}.json"

    try:
        response = requests.get(base_url)
        response.raise_for_status()
        cve_data = response.json()

        if "usn" in cve_data:
            usn_info = cve_data["usn"]
            return f"Ubuntu: {usn_info}"

        return "Patched version information not found for this CVE in Ubuntu."

    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

if __name__ == "__main__":
    cve_id = input("Enter CVE ID (e.g., CVE-2022-12345): ")
    patched_version_nvd = get_patched_version_from_nvd(cve_id)
    patched_version_redhat = get_patched_version_from_redhat(cve_id)
    patched_version_ubuntu = get_patched_version_from_ubuntu(cve_id)

    print("Patched Version Information:")
    print(patched_version_nvd)
    print(patched_version_redhat)
    print(patched_version_ubuntu)


##
##
