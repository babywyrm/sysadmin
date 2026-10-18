from tenable.io import TenableIO
import csv

# Define your Tenable.io access parameters
TIO_ACCESS_KEY = "YOUR_TIO_ACCESS_KEY"
TIO_SECRET_KEY = "YOUR_TIO_SECRET_KEY"

# Initialize the Tenable.io client
tio = TenableIO(TIO_ACCESS_KEY, TIO_SECRET_KEY)

# Retrieve vulnerabilities from Tenable.io (Tenable Cloud)
try:
    vulnerabilities = tio.vulns.list()
    
    # Create a dictionary to group vulnerabilities by host
    vulnerabilities_by_host = {}
    
    for vuln in vulnerabilities:
        host = vuln.get('host', 'N/A')
        if host not in vulnerabilities_by_host:
            vulnerabilities_by_host[host] = []
        vulnerabilities_by_host[host].append(vuln)

    with open("vulnerabilities.csv", "w", newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        
        # Write the header row
        csv_writer.writerow(["Host", "Plugin ID", "CVEs", "CVSS Score", "Title", "Severity"])
        
        for host, host_vulns in sorted(vulnerabilities_by_host.items()):
            for vuln in host_vulns:
                plugin_id = vuln['plugin_id']
                cves = ", ".join(vuln.get('cve', []))
                cvss_score = vuln.get('cvss_base_score', 'N/A')
                title = vuln.get('plugin_name', 'N/A')
                severity = vuln.get('risk_factor', 'N/A')

                # Write the data for each vulnerability
                csv_writer.writerow([host, plugin_id, cves, cvss_score, title, severity])

        print("Vulnerabilities sorted by host and exported to vulnerabilities.csv")
except Exception as e:
    print(f"Error retrieving vulnerabilities from Tenable.io: {e}")
