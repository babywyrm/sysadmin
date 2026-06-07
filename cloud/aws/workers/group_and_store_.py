import subprocess
import json
import sqlite3

##
##

# Define the AWS profiles to use
profiles = ['profile1', 'profile2', 'profile3']

# Define the command to list Kubernetes clusters
cluster_command = 'aws eks list-clusters --profile {}'

# Define the command to list Kubernetes worker nodes for a cluster
node_command = 'aws eks list-nodegroups --cluster-name {} --profile {}'

# Define the SQL query to insert data into the database
insert_query = 'INSERT INTO workers (cluster, nodegroup, instance_type) VALUES (?, ?, ?)'

# Connect to the SQL database
conn = sqlite3.connect('workers.db')

# Create the workers table if it doesn't already exist
conn.execute('CREATE TABLE IF NOT EXISTS workers (cluster TEXT, nodegroup TEXT, instance_type TEXT)')

# Loop through each AWS profile
for profile in profiles:
    # Get the list of Kubernetes clusters for this profile
    cluster_output = subprocess.check_output(cluster_command.format(profile), shell=True)
    clusters = json.loads(cluster_output)

    # Loop through each cluster
    for cluster in clusters['clusters']:
        # Get the list of Kubernetes worker nodes for this cluster
        node_output = subprocess.check_output(node_command.format(cluster, profile), shell=True)
        nodes = json.loads(node_output)

        # Loop through each worker node
        for node in nodes['nodegroups']:
            # Extract the relevant information
            cluster_name = cluster
            nodegroup_name = node['nodegroupName']
            instance_type = node['instanceTypes'][0]

            # Insert the data into the SQL database
            conn.execute(insert_query, (cluster_name, nodegroup_name, instance_type))

# Commit the changes to the SQL database
conn.commit()

# Close the SQL database connection
conn.close()

##
##

###############
###############

This code uses the subprocess module to run AWS CLI commands to list Kubernetes clusters and worker nodes. It then loops through the results and extracts the relevant information. It then uses the sqlite3 module to connect to a SQL database, create a table to store the data, and insert the data into the table. Finally, it commits the changes to the database and closes the database connection.

Note that you will need to replace profile1, profile2, and profile3 with the actual AWS profile names you want to use, and you may need to modify the insert_query string to match your SQL database schema.
