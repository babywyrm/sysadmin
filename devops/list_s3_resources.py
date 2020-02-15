##############################################

import boto3

# get bucket
s3 = boto3.resource('s3')
bucket = s3.Bucket('python-example-bucket')

# put object
bucket.put_object(
    ACL='private',
    Body=b'bytes-to-write'
)

# delete bucket
response = bucket.delete_objects(
    Delete={
        'Objects': [
            {
                'Key': 'key-to-existing',
                'VersionId': '0'
            },
        ],
        'Quiet': False
    }
)

# download file
s3 = boto3.resource('s3')
s3.Bucket('python-example-bucket') \
    .download_file('hello.txt', '/tmp/hello.txt')
    
##############################################
