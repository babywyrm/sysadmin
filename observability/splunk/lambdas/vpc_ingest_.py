##
## https://github.com/aws-samples/vpc-flow-log-filtering-and-ingestion-in-splunk-using-aws-lambda/blob/main/lambda_splunk_function.py
##

import os
import boto3
import json
import gzip
import urllib3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
splunk_hec_url = os.environ['splunk_hec_url']
splunk_hec_token = os.environ['splunk_hec_token']
s3_bucket_name = os.environ['backup_s3']

def write_to_backup_s3(data, key):
    data_bytes=bytes(json.dumps(data).encode())
    compressed_data = gzip.compress(data_bytes)
    try:
        response = s3.put_object(
            Bucket = s3_bucket_name,
            Key = key,
            Body = compressed_data
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            logger.info('Object written to S3 successfully')
 
    except Exception as e:
        logger.info(f"Error writing object to S3: {e}")
    return


def send_to_splunk_hec(data_list):
    data = str(data_list)[1:-1]
    
    headers = {
        "Authorization": "Splunk " + splunk_hec_token
    }
    
    http = urllib3.PoolManager(timeout=20)
    
    try:
        response = http.request(
            "POST",
            splunk_hec_url, 
            headers=headers, 
            body=json.dumps(data)
            )
        logger.info(f"Splunk HEC Response: {response.status} - {response.data}")
        return response.status
        
    except Exception as e:
        logger.info(f"HTTP POST error: {e}")
        return None

def filter_data(obj):
    logs_to_send = []
    content = gzip.decompress(obj['Body'].read()).decode('utf-8')
    flow_log_records = content.strip().split('\n')
    for record in flow_log_records:
        fields = record.strip().split()
        action = fields[12]
        logger.info(f"Action: {action}")
        if action == "REJECT":
            logs_to_send.append(record)
            logger.info(f"logs_to_send = {logs_to_send}")
    return logs_to_send

def get_object(bucket, key):
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)  
        return obj 
    
    except Exception as e:
        logger.info(f"Error retrieving S3 object: {e}")
        return None

def lambda_handler(event, context):
    for record in event['Records']:
        body = record['body']
        logger.info(f"received sqs message: {body}")
        #Parse the json message
        message = json.loads(body)
        try:
            #extract s3 key and bucket name from the message
            bucket = message['Records'][0]['s3']['bucket']['name']
            s3_key = message['Records'][0]['s3']['object']['key']
            #log the bucket and s3_key parameters
            logger.info(f"bucket: {bucket}")
            logger.info(f"s3 key: {s3_key}")

        except Exception as e:
            logger.info(f"Error retrieving S3 bucket name and/or object key from message: {e}")

        #if bucket and s3_key are not null, invoke get_object function
        if not (bucket or s3_key):
            continue
        obj = get_object(bucket, s3_key)
        if not obj:
            continue
        filtered_data = filter_data(obj)
        logger.info(f"filtered data = {filtered_data}")
        if filtered_data:
            status = send_to_splunk_hec(filtered_data)
            logger.info(f"status: {status}")
            if status != 200:
                write_to_backup_s3(filtered_data, s3_key)

    return
