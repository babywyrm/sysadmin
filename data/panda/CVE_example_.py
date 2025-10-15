import pandas as pd
from datetime import datetime, timedelta
import numpy as np

# Define the functions for CVE data manipulation

def inner_join(df1, df2, on_columns):
    """
    Function to perform inner join on two dataframes based on the given columns
    """
    return pd.merge(df1, df2, on=on_columns, how='inner')

def sort_df(df, sort_column, ascending=True):
    """
    Function to sort a dataframe based on a given column in ascending or descending order
    """
    return df.sort_values(by=sort_column, ascending=ascending)

def filter_df(df, filter_column, filter_value):
    """
    Function to filter a dataframe based on a given column and value
    """
    return df[df[filter_column] == filter_value]

def filter_df_range(df, filter_column, min_value, max_value):
    """
    Function to filter a dataframe based on a range of values
    """
    return df[(df[filter_column] >= min_value) & (df[filter_column] <= max_value)]

def calculate_risk_score(df):
    """
    Calculate composite risk score based on CVSS, exploitability, and impact
    """
    df['risk_score'] = (df['cvss_score'] * 0.4 + 
                       df['exploitability_score'] * 0.3 + 
                       df['impact_score'] * 0.3)
    return df

# Create sample CVE dataframes

cves = pd.DataFrame({
    'cve_id': ['CVE-2023-0001', 'CVE-2023-0002', 'CVE-2023-0003', 'CVE-2023-0004', 
               'CVE-2023-0005', 'CVE-2023-0006'],
    'severity': ['Critical', 'High', 'Medium', 'Critical', 'Low', 'High'],
    'cvss_score': [9.8, 8.1, 5.4, 9.0, 3.1, 7.5],
    'exploitability_score': [3.9, 2.8, 1.8, 3.9, 1.2, 2.4],
    'impact_score': [6.0, 5.9, 3.6, 5.2, 1.4, 5.9],
    'attack_vector': ['Network', 'Network', 'Local', 'Network', 'Physical', 'Network'],
    'attack_complexity': ['Low', 'Low', 'High', 'Low', 'High', 'Low'],
    'published_date': [
        datetime(2023, 1, 15),
        datetime(2023, 2, 3),
        datetime(2023, 2, 20),
        datetime(2023, 3, 8),
        datetime(2023, 3, 15),
        datetime(2023, 4, 2)
    ],
    'category': ['RCE', 'SQLi', 'Privilege Escalation', 'RCE', 'Info Disclosure', 'XSS']
})

# Asset inventory dataframe
assets = pd.DataFrame({
    'cve_id': ['CVE-2023-0001', 'CVE-2023-0002', 'CVE-2023-0003', 'CVE-2023-0004'],
    'affected_systems': [150, 45, 23, 89],
    'business_unit': ['Production', 'Development', 'Staging', 'Production'],
    'remediation_status': ['Open', 'In Progress', 'Patched', 'Open'],
    'days_to_remediate': [45, 30, 7, 60]
})

# Threat intelligence dataframe
threat_intel = pd.DataFrame({
    'cve_id': ['CVE-2023-0001', 'CVE-2023-0004', 'CVE-2023-0006'],
    'active_exploitation': [True, True, False],
    'exploit_available': [True, True, True],
    'threat_actor': ['APT29', 'Lazarus Group', 'Script Kiddies']
})

print("=== Original CVE Data ===")
print(cves.head())
print("\n")

# Calculate risk scores
cves = calculate_risk_score(cves)

# Filter for high-risk CVEs (CVSS >= 7.0)
high_risk_cves = filter_df_range(cves, 'cvss_score', 7.0, 10.0)

print("=== High Risk CVEs (CVSS >= 7.0) ===")
print(high_risk_cves[['cve_id', 'severity', 'cvss_score', 'risk_score']])
print("\n")

# Join with asset data to understand impact
cve_asset_analysis = inner_join(high_risk_cves, assets, on_columns='cve_id')

print("=== High Risk CVEs with Asset Impact ===")
print(cve_asset_analysis[['cve_id', 'severity', 'cvss_score', 'affected_systems', 
                         'business_unit', 'remediation_status']])
print("\n")

# Join with threat intelligence for context
critical_threats = inner_join(cve_asset_analysis, threat_intel, on_columns='cve_id')

print("=== Critical Threats with Active Exploitation ===")
print(critical_threats[['cve_id', 'cvss_score', 'affected_systems', 
                       'active_exploitation', 'threat_actor']])
print("\n")

# Sort by risk priority (combination of CVSS score and affected systems)
cve_asset_analysis['priority_score'] = (cve_asset_analysis['cvss_score'] * 
                                       np.log(cve_asset_analysis['affected_systems'] + 1))

prioritized_cves = sort_df(cve_asset_analysis, 'priority_score', ascending=False)

print("=== Prioritized CVE Remediation Queue ===")
print(prioritized_cves[['cve_id', 'severity', 'cvss_score', 'affected_systems', 
                       'priority_score', 'remediation_status']].round(2))
print("\n")

# Filter for production systems only
production_cves = filter_df(prioritized_cves, 'business_unit', 'Production')

print("=== Production System CVEs ===")
print(production_cves[['cve_id', 'severity', 'affected_systems', 'remediation_status']])
print("\n")

# Summary statistics
print("=== CVE Summary Statistics ===")
print(f"Total CVEs: {len(cves)}")
print(f"Critical/High Severity: {len(high_risk_cves)}")
print(f"CVEs affecting assets: {len(cve_asset_analysis)}")
print(f"CVEs with active exploitation: {len(critical_threats)}")
print(f"Average CVSS score: {cves['cvss_score'].mean():.2f}")
print(f"Total affected systems: {cve_asset_analysis['affected_systems'].sum()}")

# Generate remediation timeline
print("\n=== Remediation Timeline Analysis ===")
remediation_summary = cve_asset_analysis.groupby('remediation_status').agg({
    'cve_id': 'count',
    'affected_systems': 'sum',
    'days_to_remediate': 'mean'
}).round(2)
print(remediation_summary)
##
##
