import ssl
import json
import socket

##
##

hostname = 'example.com'
port = 443

# Get the list of supported cipher suites for the given hostname and port
context = ssl.create_default_context()
with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
    sock.connect((hostname, port))
    cipher_suites = sock.cipher()

# Convert the cipher suites to a JSON object
cipher_suites_dict = {
    'name': cipher_suites.name,
    'protocol': cipher_suites.version,
    'cipher': cipher_suites.name,
    'bits': cipher_suites.bits,
}
cipher_suites_json = json.dumps(cipher_suites_dict, indent=4)

print(cipher_suites_json)

##
##

{
    "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "protocol": "TLSv1.2",
    "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
    "bits": 256
}

#####################
#####################


import boto3

# Set the AWS region and ALB ARN
region = 'us-west-2'
alb_arn = 'arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/my-load-balancer/1234567890abcdef'

# Create a boto3 client for Elastic Load Balancing and Global Accelerator
elbv2 = boto3.client('elbv2', region_name=region)
globalaccelerator = boto3.client('globalaccelerator', region_name=region)

# Get the current cipher suites for the ALB
response = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])
current_ciphers = response['LoadBalancers'][0]['LoadBalancerAttributes']['CipherOptions']['ALPN_POLICY']['Values']

# Remove any cipher suites that include CBC
new_ciphers = [c for c in current_ciphers if 'CBC' not in c]

# Update the ALB with the new cipher suites
elbv2.modify_load_balancer_attributes(
    LoadBalancerArn=alb_arn,
    Attributes=[
        {
            'Key': 'CipherOptions.ALPN_POLICY',
            'Value': ','.join(new_ciphers)
        },
    ]
)

# Get the current listener configurations for the Global Accelerator
response = globalaccelerator.describe_listener(
    ListenerArn='arn:aws:globalaccelerator:us-west-2:123456789012:listener/abcdef1234567890'
)
current_config = response['Listener']['AcceleratorArn']

# Update the listener with the new cipher suites
globalaccelerator.update_listener(
    ListenerArn='arn:aws:globalaccelerator:us-west-2:123456789012:listener/abcdef1234567890',
    PortRanges=[
        {
            'FromPort': 80,
            'ToPort': 80,
        },
        {
            'FromPort': 443,
            'ToPort': 443,
        },
    ],
    Protocol='TCP',
    ClientAffinity='NONE',
    CipherSets=new_ciphers,
    AcceleratorArn=current_config
)


###
###

