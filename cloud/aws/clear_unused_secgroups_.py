#!/usr/bin/env python
#############
#############
###
### _please_refactor_for_the_future______
###
import boto3

###                                             ###
#  Need aws credentails already been configured   #
###                                             ###

### Code based on https://gist.github.com/miketheman/2630437

client = boto3.client('ec2')

### Pre-defined groups lists
in_use_groups = []
to_delete_groups = []

### Get All security groups
all_groups = [group['GroupName'] for group in client.describe_security_groups()['SecurityGroups']]

### Get All instances
all_instances = client.describe_instances()

### Get All security groups that has been used by some instances
for instances in all_instances['Reservations']:
  for inst in instances['Instances']:
    for group in inst['SecurityGroups']:
      groupName = group['GroupName']
      if groupName not in in_use_groups:
        in_use_groups.append(groupName)

### Get security group candidates that has not been used and will be deleted
delete_candidates = [item for item in all_groups if item not in in_use_groups]

### Can Add some more filtering conditions like this:
#delete_candidates = [item for item in all_groups if item not in in_use_groups and item.startswith('launch-wizard-') and int(group.split('-')[-1]) > 5]

### Start delete security groups that haven't been used
print("We will now delete security groups.")
for group in to_delete_groups:
    client.delete_security_group(GroupName = group)
print("We have deleted %d groups." % (len(to_delete_groups)))


####################################
##
##
