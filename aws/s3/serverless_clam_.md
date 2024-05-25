
##
#
https://aws.amazon.com/blogs/developer/virus-scan-s3-buckets-with-a-serverless-clamav-based-cdk-construct/
#
##

Virus scan S3 buckets with a serverless ClamAV based CDK construct
by Arun Donti | on 26 AUG 2021 | in Amazon Elastic File System (EFS), Amazon EventBridge, Amazon Simple Queue Service (SQS), Amazon Simple Storage Service (S3), Amazon VPC, AWS Lambda, Technical How-to | Permalink |  Comments |  Share
Edit: March 10th 2022 – Updated post to use AWS Cloud Development Kit (CDK) v2.

Protecting systems from malware is an essential part of a systems protection strategy. It is important to both scan binaries and other files before introducing them into your system boundary and appropriately respond to potential threats in accordance to your organizational security strategy.

This post shows you how to leverage an aws-cdk construct that uses ClamAV® to scan new objects in Amazon S3 for viruses. The construct provides easy integration with AWS services to allow for your system to act based on the results of a ClamAV scan.

Overview of Solution
In short the construct creates a Docker based AWS Lambda function that tags and temporarily downloads a newly created file in configured Amazon S3 buckets into an Amazon Elastic File System, scans the file, and appropriately tags the file in S3 and publishes the result to a supported Lambda destination of your choosing. Additionally, the construct, creates an hourly job to download the latest ClamAV definition files to the Virus Definitions S3 Bucket by utilizing an Amazon EventBridge rule and a Lambda function and publishes Amazon CloudWatch Metrics on scan results to the ‘serverless-clamscan’ namespace.

Architecture Diagram of the serverless-clamscan cdk construct

Walkthrough
This walkthrough will show you how to deploy a minimal setup of using the construct and how to view manually view the results. The walkthrough does not go over configuring your own Lambda Destinations. In short you will create a new CDK application with a minimal configuration of the construct, upload the EICAR anti malware test file to the example S3 Bucket, view the results in S3 and CloudWatch Metrics, and finally clean up the deployment.

GitHub repo: https://github.com/awslabs/cdk-serverless-clamscan

Prerequisites
For this walkthrough, you should have the following prerequisites:

An AWS account
Docker installed on your local machine
A local installation of and experience using the AWS Cloud Development Kit
Create and deploy our cdk application
You will be deploying a minimal configuration of the construct in this section. To learn more about how to customize the construct configuration (like the Lambda Destinations), take a look at the API Documentation. If you are unfamiliar with using the CDK, learn how to install and setup the CDK by taking a look at their open source GitHub repository.

Run the following commands to create the CDK application.
mkdir CdkTest
cd CdkTest
cdk init app --language typescript
Bash
Replace the contents of the package.json file with the following.

```
{
  "name": "cdk_test",
  "version": "0.1.0",
  "bin": {
    "cdk_test": "bin/cdk_test.js"
  },
  "scripts": {
    "build": "tsc",
    "watch": "tsc -w",
    "test": "jest",
    "cdk": "cdk"
  },
  "devDependencies": {
    "@types/jest": "^26.0.10",
    "@types/node": "10.17.27",
    "aws-cdk": "^2.11.0",
    "jest": "^26.4.2",
    "ts-jest": "^26.2.0",
    "ts-node": "^9.0.0",
    "typescript": "~3.9.7"
  },
  "dependencies": {
    "aws-cdk-lib": "^2.11.0",
    "cdk-serverless-clamscan": "^2.1.29",
    "constructs": "^10.0.0",
    "source-map-support": "^0.5.16"
  }
}
```

JSON
 Replace the contents of the lib/cdk_test-stack.ts with the following.

```
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { Stack, StackProps, RemovalPolicy, CfnOutput } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { ServerlessClamscan } from 'cdk-serverless-clamscan';

export class CdkTestStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);
    const sc = new ServerlessClamscan(this, 'rClamscan', {});
    const bucket = new Bucket(this, 'rBucket', {
      autoDeleteObjects: true,
      removalPolicy: RemovalPolicy.DESTROY
    });
    sc.addSourceBucket(bucket);
    new CfnOutput(this, 'oBucketName', {
      description: 'The name of the input S3 Bucket',
      value: bucket.bucketName
    })
  }
}
```
TypeScript
Run the following commands to install dependencies and deploy our sample app.
npm install
cdk deploy
Bash
After the application deploys, you should see CdkTestStack.oBucketName output in your terminal. You will be navigating to that S3 bucket in the AWS console in the next step.
Testing the construct and viewing the results
In this section you will upload the EICAR anti malware test file to the S3 Bucket and view the results. The file contains a non-viral 68 character string that a number of anti-virus software (like ClamAV) will react to as it were a virus. You can learn more about the test file at the eicar.org website

Navigate to the to the S3 Console and search for the S3 bucket that you noted at the end of last section.
Click on the name of the bucket, navigate to the Permissions tab, and scroll down to view the bucket policy. You should see a policy similar to the following.
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "NotPrincipal": {
        "AWS": [
          "arn:aws:sts::111122223333:assumed-role/ServerlessClamscanFunction/ServerlessClamscanFunctionAssumedRole",
          "arn:aws:iam::111122223333:role/ServerlessClamscanFunction"
        ]
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::DOC-EXAMPLE-BUCKET/*",
      "Condition": {
        "StringEquals": {
          "s3:ExistingObjectTag/scan-status": [
            "IN PROGRESS",
            "INFECTED",
            "ERROR"
          ]
        }
      }
    }
  ]
}

JSON
This bucket policy prevents users/applications in your system from downloading new objects while a scan is in “IN PROGRESS“, the object was marked as “INFECTED“, or if there was an “ERROR” with the scan.

 Scroll up, navigate to the Objects tab and click upload.
Click on the Add files button, and paste the URL to the Eicar test file (https://secure.eicar.org/eicar.com) in the file name dialog, and click open to select the file.
Click the Upload button in the S3 Console.
Once the file has uploaded, navigate to the file in the S3 Bucket and click on the Properties tab for the file.
Scroll down to the Tags section. You should see a tag called scan-status with a value of “INFECTED“. If you don’t see any tags or the value of the tag is “IN PROGRESS“, refresh the page. It may take a few seconds for the first invocation of the Lambda function to start up and scan the object. Since this is a small object the scan should finish quickly.the scan-status tag of the eicar test file with a value of infected
 Navigate to the CloudWatch console and click on the Metrics sidebar item. You should see the “serverless-clamscan” Namespace in the Customer Namespaces section.
Click on the “serverless-clamscan” namespace, then click on “service“. You should see the following metrics.
the serverless-clamscan metric namespace in the CloudWatch Metrics console
Toggle the checkboxes next to the metrics. You should see an example graph like the following with the charted metrics. In addition to the Lambda destinations, you can use these metrics to include in custom CloudWatch Dashboards or create additional CloudWatch alarms.
Example CloudWatch dashboard showing graphed serverless-clamscan metrics
Resource clean up
Delete the resources by running the cdk destroy command twice. The S3 Bucket that contains the Virus Definitions has a bucket policy that will likely cause a deletion error if you when deleting the stack associated in the construct. However since the bucket itself gets deleted, you can run the destroy command again to resolve the error.
 Navigate to the S3 console and manually delete the S3 Bucket with a name like “cdktest-rclamscanvirusdefsaccessl”. This bucket was created to retain Access Logs for the Virus Definitions S3 Bucket.
Conclusion
In this post you learned how to use an aws-cdk construct that uses ClamAV® to scan new objects in Amazon S3 for viruses. To learn more about configuring the construct to your use case, read the API reference. The construct has been pre-packaged and published on npm (cdk, monocdk) and PyPI (cdk, monocdk) for easy use in TypeScript and Python CDK
