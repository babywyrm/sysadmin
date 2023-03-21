#!/usr/bin/python3

####################
##
##

import json
import os
import mysql.connector
from mysql.connector import Error
import boto3

# List of AWS account profiles
ACCOUNT_PROFILES=["profile1", "profile2", "profile3", "profile4"]

# List of regions to check for ALBs
REGIONS=["us-east-1", "us-west-2", "eu-west-1"]

# Initialize the MySQL connection
try:
    connection = mysql.connector.connect(
        host='localhost',
        database='testdb',
        user='testuser',
        password='testpassword'
    )

    cursor = connection.cursor()
    print("Connected to MySQL database")

except Error as e:
    print("Error connecting to MySQL database: ", e)

# Array to store public IPs
public_ips = []

# Loop through all AWS account profiles and regions to get the public IPs of ALBs and Global Accelerators
for profile in ACCOUNT_PROFILES:
    for region in REGIONS:
        # Get public IPs of ALBs in the region
        elbv2 = boto3.client('elbv2', region_name=region, profile_name=profile)
        lb_ips = []
        lbs = elbv2.describe_load_balancers()
        for lb in lbs['LoadBalancers']:
            lb_ips += elbv2.resolve_dns_name(LoadBalancerArn=lb['LoadBalancerArn'])['IPAddresses']

        # Get public IPs of Global Accelerators in the region
        ec2 = boto3.client('ec2', region_name=region, profile_name=profile)
        ga_ips = []
        gas = ec2.describe_accelerators()
        for ga in gas['Accelerators']:
            ga_ips += ec2.describe_accelerator_attributes(AcceleratorIds=[ga['AcceleratorId']])['AcceleratorAttributes'][0]['IpSets'][0]['IpAddresses']

        # Combine the list of ALB and Global Accelerator public IPs and add them to the public_ips array
        all_ips = list(set(lb_ips + ga_ips))
        for ip in all_ips:
            if ip:
                public_ips.append(ip)

# Print the public IPs in JSON format
json_data = json.dumps({"public_ips": public_ips})

# Insert the JSON data into MySQL database
try:
    cursor.execute(f"INSERT INTO testtable (data) VALUES ('{json_data}')")
    connection.commit()
    print("JSON data inserted into MySQL database")

except Error as e:
    print("Error inserting JSON data into MySQL database: ", e)

finally:
    cursor.close()
    connection.close()
    print("MySQL connection closed")

    
####################
####################
##
##
