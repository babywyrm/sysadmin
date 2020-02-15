####################################
####################################

import boto3 as boto3

s = boto3.Session(region_name="us-west-1")
ec2 = s.resource('ec2')

instance = ec2.create_instances(
    BlockDeviceMappings=[
        {
            'DeviceName': 'disk_1',
            'VirtualName': 'disk_1',
            'Ebs': {
                'Encrypted': True,
                'DeleteOnTermination': False,
                'VolumeSize': 1024,
                'VolumeType': 'standard'
            }
        },
    ],
    InstanceType='h1.4xlarge',
    Monitoring={
        'Enabled': True
    },
    Placement={
        'AvailabilityZone': 'us-east-1'
    },
    MaxCount=2,
    MinCount=1
)

###########################################
