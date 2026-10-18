import pytenable
import pandas as pd

##
##

# Tenable.io API Access
access_key = 'YOUR_ACCESS_KEY'
secret_key = 'YOUR_SECRET_KEY'
tenable = pytenable.Tenable(access_key, secret_key)

# Get all tenable agents
agents = tenable.agents.list()

# Get agent groups
agent_groups = tenable.agent_groups.list()

# Create a dictionary to map agent IDs to their names
agent_names = {agent['id']: agent['name'] for agent in agents}

# Create a dictionary to map agent IDs to their associated groups
agent_group_mapping = {}
for group in agent_groups:
    for agent_id in group['agent_ids']:
        agent_group_mapping[agent_id] = agent_group_mapping.get(agent_id, []) + [group['name']]

# Create a list of dictionaries with agent information
agent_info_list = []
for agent in agents:
    agent_info_list.append({
        'Agent Name': agent['name'],
        'Agent ID': agent['id'],
        'Groups': ', '.join(agent_group_mapping.get(agent['id'], []))
    })

# Create a DataFrame for a nice table
agent_info_df = pd.DataFrame(agent_info_list)

# Print the table
print(agent_info_df)

##
##
