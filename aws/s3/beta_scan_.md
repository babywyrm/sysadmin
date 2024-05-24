
##
#
Terraform setup for AWS Lambda functions and IAM roles: Define your Lambda functions and IAM roles in Terraform.
#
##

Lambda function for scanning with ClamAV: Implement a Lambda function that downloads S3 objects and scans them with ClamAV.
Lambda function for checking VirusTotal: Implement a Lambda function that checks the VirusTotal database for the scanned files.
Triggering mechanism: Configure S3 to trigger the Lambda functions when new files are uploaded.


Step 1: Terraform Setup for Lambda Functions and IAM Roles
Create a main.tf file and define your Lambda functions, IAM roles, and S3 bucket configurations.

```
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

resource "aws_lambda_function" "clamav_scan" {
  filename         = "clamav_scan.zip"
  function_name    = "clamav_scan"
  role             = aws_iam_role.lambda_role.arn
  handler          = "clamav_scan.lambda_handler"
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 1024
}

resource "aws_lambda_function" "virustotal_check" {
  filename         = "virustotal_check.zip"
  function_name    = "virustotal_check"
  role             = aws_iam_role.lambda_role.arn
  handler          = "virustotal_check.lambda_handler"
  runtime          = "python3.8"
  timeout          = 300
  memory_size      = 1024
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = "my-bucket"

  lambda_function {
    lambda_function_arn = aws_lambda_function.clamav_scan.arn
    events              = ["s3:ObjectCreated:*"]
  }
}

resource "aws_lambda_permission" "allow_s3_to_call_clamav" {
  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.clamav_scan.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::my-bucket"
}

resource "aws_lambda_permission" "allow_clamav_to_call_virustotal" {
  statement_id  = "AllowExecutionFromClamAV"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.virustotal_check.function_name
  principal     = "lambda.amazonaws.com"
}
```

Step 2: Implement ClamAV Scan Lambda Function
Create a Python script clamav_scan.py that will be used by the ClamAV Lambda function.

```
import boto3
import os
import subprocess
import json

s3 = boto3.client('s3')

def lambda_handler(event, context):
    # Get the bucket and object key from the event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    # Download the object to /tmp
    download_path = f"/tmp/{key.split('/')[-1]}"
    s3.download_file(bucket, key, download_path)

    # Run ClamAV to scan the file
    result = subprocess.run(['clamscan', download_path], stdout=subprocess.PIPE)
    scan_result = result.stdout.decode('utf-8')

    # Log the result
    print(f"ClamAV result for {key}: {scan_result}")

    # If the file is clean, call the VirusTotal check Lambda
    if "OK" in scan_result:
        invoke_response = boto3.client('lambda').invoke(
            FunctionName='virustotal_check',
            InvocationType='Event',
            Payload=json.dumps({'bucket': bucket, 'key': key})
        )
    else:
        print(f"File {key} is infected according to ClamAV")

    # Cleanup downloaded file
    os.remove(download_path)

    return {
        'statusCode': 200,
        'body': json.dumps('Scan complete')
    }

```

Step 3: Implement VirusTotal Check Lambda Function
Create a Python script virustotal_check.py that will be used by the VirusTotal Lambda function.

```
import boto3
import requests
import json
import os

s3 = boto3.client('s3')
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'

def lambda_handler(event, context):
    # Get the bucket and object key from the event
    bucket = event['bucket']
    key = event['key']

    # Download the object to /tmp
    download_path = f"/tmp/{key.split('/')[-1]}"
    s3.download_file(bucket, key, download_path)

    # Check VirusTotal
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {'file': (download_path, open(download_path, 'rb'))}
    params = {'apikey': VIRUSTOTAL_API_KEY}
    response = requests.post(url, files=files, params=params)
    vt_result = response.json()

    # Log the result
    print(f"VirusTotal result for {key}: {vt_result}")

    # Cleanup downloaded file
    os.remove(download_path)

    return {
        'statusCode': 200,
        'body': json.dumps('VirusTotal check complete')
    }
```
Step 4: Prepare and Deploy the Lambda Functions
Zip the Lambda function scripts:
```
zip clamav_scan.zip clamav_scan.py
zip virustotal_check.zip virustotal_check.py
```
Run the Terraform script to deploy the infrastructure:

```
terraform init
terraform apply
```
This will set up the necessary IAM roles, Lambda functions, 
and S3 bucket notifications to trigger the Lambda functions when new objects are uploaded to the S3 bucket. 
The ClamAV function will scan the files for malware, and if they are clean, the VirusTotal check function will be invoked to further scan the files.



##
##
