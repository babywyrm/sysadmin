################################
############################

import boto3 as boto3

s = boto3.Session(region_name="us-west-1")
s3Client = s.resource('s3')

response = s3Client.create_bucket(
    ACL='private',
    Bucket='python-example-bucket',
    CreateBucketConfiguration={
        'LocationConstraint': 'us-east-1'
    }
)

################################
