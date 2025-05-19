#!/usr/bin/env python3

"""
CloudTrail Automator: run predefined CloudTrail searches across scenarios, (testing..)

This script runs AWS CLI cloudtrail lookup-events commands for a set of
predefined scenarios. Use -h/--help for usage details.
"""

import argparse
import subprocess
import os,sys,re

##
##
# Predefined CloudTrail scenarios mapping to AWS CLI arguments
SCENARIOS = {
    "console-login-success": {
        "label": "Successful Console Login",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=ConsoleLogin",
            "--query", "Events[?ErrorCode==null].{User:Username,Time:EventTime,SourceIP:Resources[0].ResourceName}"
        ]
    },
    "console-login-failed": {
        "label": "Failed Console Login",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=ConsoleLogin",
            "--query", "Events[?ErrorCode=='FailedAuthentication'].{User:Username,Time:EventTime,Error:ErrorCode}"
        ]
    },
    "ec2-stop": {
        "label": "EC2 Instance Stop",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=StopInstances",
            "--query", "Events[*].{User:Username,Time:EventTime,Instance:Resources[0].ResourceName}"
        ]
    },
    "ec2-start": {
        "label": "EC2 Instance Start",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=StartInstances",
            "--query", "Events[*].{User:Username,Time:EventTime,Instance:Resources[0].ResourceName}"
        ]
    },
    "ec2-run": {
        "label": "EC2 RunInstances",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=RunInstances",
            "--query", "Events[*].{User:Username,Time:EventTime,Image:ResponseElements.instancesSet.items[0].imageId,Instance:ResponseElements.instancesSet.items[0].instanceId}"
        ]
    },
    "iam-create-user": {
        "label": "IAM User Creation",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=CreateUser",
            "--query", "Events[*].{Admin:Username,Time:EventTime,NewUser:ResponseElements.user.userName}"
        ]
    },
    "iam-delete-user": {
        "label": "IAM User Deletion",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=DeleteUser",
            "--query", "Events[*].{Admin:Username,Time:EventTime,DeletedUser:RequestParameters.userName}"
        ]
    },
    "attach-role-policy": {
        "label": "Attach Role Policy",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=AttachRolePolicy",
            "--query", "Events[*].{Admin:Username,Time:EventTime,Role:RequestParameters.roleName,PolicyArn:RequestParameters.policyArn}"
        ]
    },
    "detach-role-policy": {
        "label": "Detach Role Policy",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=DetachRolePolicy",
            "--query", "Events[*].{Admin:Username,Time:EventTime,Role:RequestParameters.roleName,PolicyArn:RequestParameters.policyArn}"
        ]
    },
    "assume-role": {
        "label": "Assume Role",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=AssumeRole",
            "--query", "Events[*].{Caller:Username,Time:EventTime,Role:RequestParameters.roleArn}"
        ]
    },
    "s3-put-bucket-policy": {
        "label": "S3 Bucket Policy Change",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=PutBucketPolicy",
            "--query", "Events[*].{Admin:Username,Time:EventTime,Bucket:RequestParameters.bucketName}"
        ]
    },
    "sg-ingress": {
        "label": "Authorize Security Group Ingress",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress",
            "--query", "Events[*].{Admin:Username,Time:EventTime,Group:RequestParameters.groupId,Cidr:RequestParameters.ipPermissions[0].ipRanges[0].cidrIp}"
        ]
    },
    "unauthorized-api": {
        "label": "Unauthorized API Call",
        "args": [
            "--lookup-attributes", "AttributeKey=ErrorCode,AttributeValue=UnauthorizedOperation",
            "--query", "Events[*].{User:Username,Time:EventTime,Operation:EventName}"
        ]
    },
    "ssm-start-session": {
        "label": "SSM Session Start",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=StartSession",
            "--query", "Events[*].{User:Username,Time:EventTime,Target:RequestParameters.target}"
        ]
    },
    "ssm-send-command": {
        "label": "SSM Command Execution",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=SendCommand",
            "--query", "Events[*].{Admin:Username,Time:EventTime,Document:RequestParameters.documentName,Targets:RequestParameters.targets}"
        ]
    },
    "ami-register": {
        "label": "AMI Registration",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=RegisterImage",
            "--query", "Events[*].{User:Username,Time:EventTime,ImageId:ResponseElements.imageId}"
        ]
    },
    "ami-deregister": {
        "label": "AMI Deregistration",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=DeregisterImage",
            "--query", "Events[*].{User:Username,Time:EventTime,ImageId:RequestParameters.imageId}"
        ]
    },
    "ecr-put-image": {
        "label": "ECR Image Push",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=PutImage",
            "--query", "Events[*].{User:Username,Time:EventTime,Repository:RequestParameters.repositoryName,ImageTag:RequestParameters.imageTag}"
        ]
    },
    "ecr-delete-image": {
        "label": "ECR Image Delete",
        "args": [
            "--lookup-attributes", "AttributeKey=EventName,AttributeValue=BatchDeleteImage",
            "--query", "Events[*].{User:Username,Time:EventTime,Repository:RequestParameters.repositoryName,ImageIds:RequestParameters.imageIds}"
        ]
    }
}

def run_scenario(name, profile, region, start_time=None, end_time=None):
    """
    Run a single CloudTrail lookup-events scenario.
    """
    scenario = SCENARIOS.get(name)
    if not scenario:
        print(f"Unknown scenario: {name}", file=sys.stderr)
        return

    cmd = [
        "aws", "cloudtrail", "lookup-events",
        "--profile", profile,
        "--region", region
    ] + scenario["args"]

    # Add time window filters if provided
    if start_time:
        cmd += ["--start-time", start_time]
    if end_time:
        cmd += ["--end-time", end_time]

    cmd += ["--output", "table"]

    print(f"\\n=== {scenario['label']} ({name}) ===")
    subprocess.run(cmd)

def create_parser():
    """
    Create and return the argument parser with all options.
    """
    parser = argparse.ArgumentParser(
        description="CloudTrail Automator: predefined CloudTrail search scenarios",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--profile", default="default",
        help="AWS CLI profile to use (default: default)"
    )
    parser.add_argument(
        "--region", default="ap-northeast-1",
        help="AWS region to query (default: ap-northeast-1)"
    )
    parser.add_argument(
        "--start-time",
        help="Start time in ISO8601 (e.g. 2025-05-01T00:00:00Z)"
    )
    parser.add_argument(
        "--end-time",
        help="End time in ISO8601 (e.g. 2025-05-19T23:59:59Z)"
    )
    parser.add_argument(
        "--scenarios", nargs="+", choices=list(SCENARIOS.keys()),
        default=list(SCENARIOS.keys()),
        help="Scenario keys to run (default: all)\n"
             + ", ".join(f"{k}" for k in SCENARIOS)
    )
    return parser

def main():
    """
    Main entry point. Parses args and executes scenarios.
    """
    parser = create_parser()
    args = parser.parse_args()

    # If no scenarios specified, show help
    if not args.scenarios:
        parser.print_help()
        sys.exit(1)

    # Execute each requested scenario
    for name in args.scenarios:
        run_scenario(
            name=name,
            profile=args.profile,
            region=args.region,
            start_time=args.start_time,
            end_time=args.end_time
        )

if __name__ == "__main__":
    main()
