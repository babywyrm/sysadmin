#!/usr/bin/python3

##
##
##
########################################3

import sys
import boto3

##
##
####  _input_instance_id_to_kill_it__
##
##

ec2 = boto3.resource('ec2')
for instance_id in sys.argv[1:]:
	instance = ec2.Instance(instance_id)
	response = instance.terminate()
	print(response)


###########
##
##
##
