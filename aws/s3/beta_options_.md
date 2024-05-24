
##
#
Alternatives to ClamAV
#
##

Sophos Anti-Virus: Sophos provides an API for malware scanning. You can integrate it into your Lambda function similarly to ClamAV.
McAfee VirusScan: McAfee offers a comprehensive suite of tools and APIs for virus scanning that can be integrated into your Lambda functions.
Trend Micro: Trend Micro provides cloud-based antivirus solutions and APIs that can be integrated for malware scanning.
F-Secure: F-Secure offers antivirus APIs that you can use to scan files in your S3 buckets.

##
#
Alternatives to VirusTotal
#
##

Metadefender: OPSWAT's Metadefender provides multi-scanning capabilities with multiple antivirus engines via an API.
Hybrid Analysis: This platform offers a free public API for malware analysis and detection.
Jotti’s Malware Scan: Jotti offers an online malware scan with multiple antivirus engines and can be accessed programmatically.
Cuckoo Sandbox: An open-source automated malware analysis system that can be integrated for more detailed analysis.


##
#
Example with Sophos Anti-Virus and Metadefender
#
##


##
##

Step 1: Terraform Setup for Lambda Functions and IAM Roles
Create a main.tf file to define your Lambda functions, IAM roles, and S3 bucket configurations.


```
main.tf
..........................

provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "lambda_role" {
  name = "lambda_s3_scan_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda_s3_scan_policy"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        Effect = "Allow",
        Resource = [
          "arn:aws:s3:::my-bucket/*",
          "arn:aws:s3:::my-bucket"
        ]
      },
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Effect = "Allow",
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "sophos_scan" {
  filename         = "sophos_scan.zip"
  function_name    = "sophos_scan"
  role             = aws_iam_role.lambda_role.arn
  handler          = "sophos_scan.lambda_handler"
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 1024
}

resource "aws_lambda_function" "metadefender_check" {
  filename         = "metadefender_check.zip"
  function_name    = "metadefender_check"
  role             = aws_iam_role.lambda_role.arn
  handler          = "metadefender_check.lambda_handler"
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 1024
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = "my-bucket"

  lambda_function {
    lambda_function_arn = aws_lambda_function.sophos_scan.arn
    events              = ["s3:ObjectCreated:*"]
  }
}

resource "aws_lambda_permission" "allow_s3_to_call_sophos" {
  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sophos_scan.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::my-bucket"
}

resource "aws_lambda_permission" "allow_sophos_to_call_metadefender" {
  statement_id  = "AllowExecutionFromSophos"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.metadefender_check.function_name
  principal     = "lambda.amazonaws.com"
}
```


Step 2: Implement Sophos Scan Lambda Function
Create a Python script sophos_scan.py that will be used by the Sophos Lambda function.

```
import boto3
import os
import subprocess
import json
import requests

s3 = boto3.client('s3')
SOPHOS_API_KEY = 'your_sophos_api_key'

def lambda_handler(event, context):
    # Get the bucket and object key from the event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    # Download the object to /tmp
    download_path = f"/tmp/{key.split('/')[-1]}"
    s3.download_file(bucket, key, download_path)

    # Scan file with Sophos API
    with open(download_path, 'rb') as file_data:
        response = requests.post(
            "https://api.labs.sophos.com/analysis/file",
            headers={"Authorization": f"Bearer {SOPHOS_API_KEY}"},
            files={"file": file_data}
        )
    sophos_result = response.json()

    # Log the result
    print(f"Sophos result for {key}: {sophos_result}")

    # If the file is clean, call the Metadefender check Lambda
    if sophos_result.get("result") == "clean":
        invoke_response = boto3.client('lambda').invoke(
            FunctionName='metadefender_check',
            InvocationType='Event',
            Payload=json.dumps({'bucket': bucket, 'key': key})
        )
    else:
        print(f"File {key} is infected according to Sophos")

    # Cleanup downloaded file
    os.remove(download_path)

    return {
        'statusCode': 200,
        'body': json.dumps('Scan complete')
    }

```
    
Step 3: Implement Metadefender Check Lambda Function
Create a Python script metadefender_check.py that will be used by the Metadefender Lambda function.

```
import boto3
import requests
import json
import os

s3 = boto3.client('s3')
METADEFENDER_API_KEY = 'your_metadefender_api_key'

def lambda_handler(event, context):
    # Get the bucket and object key from the event
    bucket = event['bucket']
    key = event['key']

    # Download the object to /tmp
    download_path = f"/tmp/{key.split('/')[-1]}"
    s3.download_file(bucket, key, download_path)

    # Check Metadefender
    with open(download_path, 'rb') as file_data:
        response = requests.post(
            "https://api.metadefender.com/v4/file",
            headers={"apikey": METADEFENDER_API_KEY},
            files={"file": file_data}
        )
    metadefender_result = response.json()

    # Log the result
    print(f"Metadefender result for {key}: {metadefender_result}")

    # Cleanup downloaded file
    os.remove(download_path)

    return {
        'statusCode': 200,
        'body': json.dumps('Metadefender check complete')
    }

```
Step 4: Prepare and Deploy the Lambda Functions
Zip the Lambda function scripts:
```
zip sophos_scan.zip sophos_scan.py
zip metadefender_check.zip metadefender_check.py
```
Run the Terraform script to deploy the infrastructure:

```
terraform init
terraform apply
