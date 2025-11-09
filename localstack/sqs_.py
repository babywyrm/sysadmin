#!/usr/bin/env python3
"""
Send and receive SQS messages against LocalStack (or AWS).

Examples
--------
# Default LocalStack on localhost:4566
python3 sqs_local.py --queue blockchain-local-engine-input.fifo

# Override endpoint and region
python3 sqs_local.py --endpoint http://localstack:4566 --region us-west-2
"""

import argparse
import json
import os
import sys
import time
import uuid
import boto3
from botocore.exceptions import BotoCoreError, ClientError


def make_client(endpoint: str, region: str):
    """Return a boto3 SQS client configured either for LocalStack or AWS."""
    session = boto3.session.Session()
    return session.client(
        "sqs",
        region_name=region,
        endpoint_url=endpoint,
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "foo"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "bar"),
    )


def send_message(sqs, queue_url: str):
    """Send one sample message."""
    body = {
        "time": {"updatedISO": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        "note": "LocalStack SQS functional test",
        "bpi": {
            "USD": {"rate_float": 9083.8632},
            "BTC": {"rate_float": 1.0},
        },
    }
    try:
        resp = sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(body),
            DelaySeconds=3,
            MessageDeduplicationId=str(uuid.uuid4()),
            MessageGroupId="blockchain",
            MessageAttributes={
                "contentType": {
                    "StringValue": "application/json",
                    "DataType": "String",
                }
            },
        )
        print(f"Sent message ID={resp.get('MessageId')}")
    except (ClientError, BotoCoreError) as e:
        print(f"[!] Failed to send message: {e}")


def poll_messages(sqs, queue_url: str):
    """Continuously receive and delete messages."""
    print("Starting long‑poll loop (Ctrl‑C to stop)...")
    try:
        while True:
            resp = sqs.receive_message(
                QueueUrl=queue_url,
                AttributeNames=["All"],
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20,
                VisibilityTimeout=30,
                MessageAttributeNames=["All"],
            )
            messages = resp.get("Messages", [])
            if not messages:
                print(".", end="", flush=True)
                continue

            print(f"\nReceived {len(messages)} message(s)")
            for msg in messages:
                body = json.loads(msg["Body"])
                print(json.dumps(body, indent=2))

                # delete the message
                sqs.delete_message(
                    QueueUrl=queue_url,
                    ReceiptHandle=msg["ReceiptHandle"],
                )
                print(f"Deleted message {msg.get('MessageId', '')}")
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except (ClientError, BotoCoreError) as e:
        print(f"[!] Polling error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Send and poll messages from SQS / LocalStack."
    )
    parser.add_argument(
        "--endpoint",
        "-e",
        default=os.getenv("LOCALSTACK_SQS_ENDPOINT_URL", "http://localhost:4566"),
        help="SQS endpoint URL (default: http://localhost:4566)",
    )
    parser.add_argument("--region", "-r", default="us-east-1")
    parser.add_argument(
        "--queue",
        "-q",
        required=True,
        help="Queue name or full queue URL "
        "(e.g. blockchain-local-engine-input.fifo or full http://... URL)",
    )
    parser.add_argument("--send-only", action="store_true", help="Send once and exit")
    args = parser.parse_args()

    # construct queue URL if only a name was given
    queue_url = (
        args.queue
        if args.queue.startswith("http")
        else f"{args.endpoint}/000000000000/{args.queue}"
    )

    sqs = make_client(args.endpoint, args.region)

    # one send first
    send_message(sqs, queue_url)

    if not args.send_only:
        poll_messages(sqs, queue_url)


if __name__ == "__main__":
    sys.exit(main())
