#!/usr/bin/python3

##
##
################################################

import os
import boto3


############### CentOS 7 (x86_64) - with Updates HVM
###############  03/04/2020

ec2 = boto3.resource('ec2')
instance = ec2.create_instances(
         ImageId='ami-02eac2c0129f6376b',
         MinCount=1,
         MaxCount=1,
         InstanceType='t2.micro')

print(instance[0].id)

################################################
##
##


