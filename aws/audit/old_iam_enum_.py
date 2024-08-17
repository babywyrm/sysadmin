
##
## c/o
## https://gist.github.com/darkarnium/1df59865f503355ef30672168063da4e
##

"""IAM Account Enumerator.

This code provides a mechanism to attempt to validate the permissions assigned
to a given set of AWS tokens.
"""
import re
import sys
import logging
import datetime
import boto3
import pprint
import botocore
import click


def report_arn(candidate):
    ''' Attempt to extract and slice up an ARN from the input string. '''
    logger = logging.getLogger()
    arn_search = re.search(r'.*(arn:aws:.*:.*:.*:.*)\s*.*$', candidate)
    if arn_search:
        arn = arn_search.group(1)
        logger.info('-- Account ARN : %s', arn)
        logger.info('-- Account Id  : %s', arn.split(':')[4])
        logger.info('-- Account Path: %s', arn.split(':')[5])


# This is lame and won't work with federated policies and a bunch of other cases.
def build_arn(user_arn, policy_name, path='policy'):
    ''' Chops up the user ARN and attempts and builds a policy ARN. '''
    return '{}:{}/{}'.format(':'.join(user_arn.split(':')[0:5]), path, policy_name)


def brute(access_key, secret_key, session_token):
    ''' Attempt to brute-force common describe calls. '''
    logger = logging.getLogger()
    logger.info('Attempting common-service describe / list bruteforce.')

    # ACM
    acm = boto3.client(
        'acm',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking ACM (Certificate Manager)')

    try:
        acm.list_certificates()
        logger.info('-- list_certificates() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_certificates() failed')

    # CloudFormation
    cfn = boto3.client(
        'cloudformation',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking CFN (CloudFormation)')

    try:
        cfn.describe_stacks()
        logger.info('-- describe_stacks() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_stacks() failed')

    # CloudHSM
    cloudhsm = boto3.client(
        'cloudhsm',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking CloudHSM')

    try:
        cloudhsm.list_hsms()
        logger.info('-- list_hsms() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_hsms() failed')

    # CloudSearch
    cloudsearch = boto3.client(
        'cloudsearch',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking CloudSearch')

    try:
        cloudsearch.list_domain_names()
        logger.info('-- list_domain_names() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_domain_names() failed')

    # CloudTrail
    cloudtrail = boto3.client(
        'cloudtrail',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking CloudTrail')

    try:
        cloudtrail.describe_trails()
        logger.info('-- describe_trails() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_trails() failed')

    # CloudWatch
    cloudwatch = boto3.client(
        'cloudwatch',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking CloudWatch')

    try:
        cloudwatch.describe_alarm_history()
        logger.info('-- describe_alarm_history() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_alarm_history() failed')

    # CodeCommit
    codecommit = boto3.client(
        'codecommit',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking CodeCommit')

    try:
        codecommit.list_repositories()
        logger.info('-- list_repositories() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_repositories() failed')

    # CodeDeploy
    codedeploy = boto3.client(
        'codedeploy',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking CodeDeploy')

    try:
        codedeploy.list_applications()
        logger.info('-- list_applications() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_applications() failed')

    try:
        codedeploy.list_deployments()
        logger.info('-- list_deployments() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_deployments() failed')

    # EC2
    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking EC2 (Elastic Compute)')

    try:
        ec2.describe_instances()
        logger.info('-- describe_instances() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_instances() failed')

    try:
        ec2.describe_images()
        logger.info('-- describe_images() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_images() failed')

    try:
        ec2.describe_addresses()
        logger.info('-- describe_addresses() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_addresses() failed')

    try:
        ec2.describe_hosts()
        logger.info('-- describe_hosts() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_hosts() failed')

    try:
        ec2.describe_nat_gateways()
        logger.info('-- describe_nat_gateways() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_nat_gateways() failed')

    try:
        ec2.describe_key_pairs()
        logger.info('-- describe_key_pairs() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_key_pairs() failed')

    try:
        ec2.describe_snapshots()
        logger.info('-- describe_snapshots() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_snapshots() failed')

    try:
        ec2.describe_volumes()
        logger.info('-- describe_volumes() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_volumes() failed')

    try:
        ec2.describe_tags()
        logger.info('-- describe_tags() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_tags() failed')

    try:
        ec2.describe_tags()
        logger.info('-- describe_tags() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_tags() failed')

    try:
        ec2.describe_vpcs()
        logger.info('-- describe_vpcs() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_vpcs() failed')

    # ECS
    ecs = boto3.client(
        'ecs',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking ECS (DOCKER DOCKER DOCKER DOCKER ...)')

    try:
        ecs.describe_clusters()
        logger.info('-- describe_clusters() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_clusters() failed')

    # Elastic Beanstalk
    beanstalk = boto3.client(
        'elasticbeanstalk',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking ElasticBeanstalk')

    try:
        beanstalk.describe_applications()
        logger.info('-- describe_applications() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_applications() failed')

    try:
        beanstalk.describe_environments()
        logger.info('-- describe_environments() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_environments() failed')

    # ELB
    elb = boto3.client(
        'elb',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking ELB (Elastic Load Balancing)')

    try:
        elb.describe_load_balancers()
        logger.info('-- describe_load_balancers() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_load_balancers() failed')

    # ELBv2
    elbv2 = boto3.client(
        'elbv2',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking ELBv2 (Elastic Load Balancing)')

    try:
        elbv2.describe_load_balancers()
        logger.info('-- describe_load_balancers() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_load_balancers() failed')

    # ElasticTranscoder
    elastictranscoder = boto3.client(
        'elastictranscoder',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking ElasticTranscoder')

    try:
        elastictranscoder.list_pipelines()
        logger.info('-- list_pipelines() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_pipelines() failed')

    # DynomoDB
    dynamodb = boto3.client(
        'dynamodb',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking DynamoDB')

    try:
        dynamodb.list_tables()
        logger.info('-- list_tables() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_tables() failed')

    # IoT
    iot = boto3.client(
        'iot',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking IoT')

    try:
        iot.list_things()
        logger.info('-- list_things() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_things() failed')

    try:
        iot.describe_endpoint()
        logger.info('-- describe_endpoint() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_endpoint() failed')

    # Kinesis
    kinesis = boto3.client(
        'kinesis',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking Kinesis')

    try:
        kinesis.list_streams()
        logger.info('-- list_streams() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_streams() failed')

    # KMS
    kms = boto3.client(
        'kms',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking KMS (Key Management Service)')

    try:
        kms.list_keys()
        logger.info('-- list_keys() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_keys() failed')

    # Lambda
    lmb = boto3.client(
        'lambda',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking Lambda')

    try:
        lmb.list_functions()
        logger.info('-- list_functions() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_functions() failed')

    # OpsWorks
    opsworks = boto3.client(
        'opsworks',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking OpsWorks')

    try:
        opsworks.describe_stacks()
        logger.info('-- describe_stacks() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_stacks() failed')

    # RDS
    rds = boto3.client(
        'rds',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking RDS (Relational Database Service)')

    try:
        rds.describe_db_clusters()
        logger.info('-- describe_db_clusters() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_db_clusters() failed')

    try:
        rds.describe_db_instances()
        logger.info('-- describe_db_instances() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_db_instances() failed')

    # Route53
    route53 = boto3.client(
        'route53',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking Route53 (DNS)')

    try:
        route53.list_hosted_zones()
        logger.info('-- list_hosted_zones() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_hosted_zones() failed')

    # S3
    s3 = boto3.client(
        's3',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking S3 (Simple Storage Service)')

    try:
        s3.list_buckets()
        logger.info('-- list_buckets() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_buckets() failed')

    # SES
    ses = boto3.client(
        'ses',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking SES (Simple Email Service)')

    try:
        ses.list_identities()
        logger.info('-- list_identities() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_identities() failed')

    # sns
    sns = boto3.client(
        'sns',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking SNS (Simple Notification Service)')

    try:
        sns.list_topics()
        logger.info('-- list_topics() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_topics() failed')

    # SQS
    sqs = boto3.client(
        'sqs',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking SQS (Simple Queue Service)')

    try:
        sqs.list_queues()
        logger.info('-- list_queues() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- list_queues() failed')

    # support
    support = boto3.client(
        'support',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    logger.info('Checking Support')

    try:
        support.describe_cases()
        logger.info('-- describe_cases() worked!')
    except botocore.exceptions.ClientError:
        logger.error('-- describe_cases() failed')

@click.command()
@click.option('--access-key', help='An AWS Access Key Id to check')
@click.option('--secret-key', help='An AWS Secret Access Key to check')
@click.option('--session-token', help='An AWS Session Token to check')
def main(access_key, secret_key, session_token):
    """IAM Account Enumerator.

This code provides a mechanism to attempt to validate the permissions assigned
to a given set of AWS tokens.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(process)d - [%(levelname)s] %(message)s',
    )
    logger = logging.getLogger()

    # Suppress boto INFO.
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('nose').setLevel(logging.WARNING)

    # Ensure requires parameters are set.
    if access_key is None:
        logger.fatal('No access-key provided, cannot continue.')
        sys.exit(-1)
    if secret_key is None:
        logger.fatal('No secret-key provided, cannot continue.')
        sys.exit(-1)

    # Connect to the IAM API and start testing.
    logger.info('Starting scrape for access-key-id "%s"', access_key)
    iam = boto3.client(
        'iam',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )

    # Try for the kitchen sink.
    try:
        everything = iam.get_account_authorization_details()
        logger.info('Run for the hills, get_account_authorization_details worked!')
        logger.info('-- %s', everything)
    except botocore.exceptions.ClientError:
        logger.error('Failed to get everything at once (get_account_authorization_details) :(')

    # Attempt to get user to start.
    try:
        user = iam.get_user()
        report_arn(user['User']['Arn'])
    except botocore.exceptions.ClientError as err:
        logger.error('Failed to retrieve any IAM data for this key.')
        report_arn(str(err))
        brute(access_key=access_key, secret_key=secret_key, session_token=session_token)
        sys.exit(0)

    # Attempt to get policies attached to this user.
    try:
        user_policies = iam.list_attached_user_policies(UserName=user['User']['UserName'])
        logger.info(
            'User "%s" has %0d attached policies',
            user['User']['UserName'],
            len(user_policies['AttachedPolicies'])
        )

        # List all policies, if present.
        for policy in user_policies['AttachedPolicies']:
            logger.info('-- Policy "%s" (%s)', policy['PolicyName'], policy['PolicyArn'])
    except botocore.exceptions.ClientError as err:
        logger.error(
            'Unable to query for user policies for "%s" (list_attached_user_policies): %s',
            user['User']['UserName'],
            err
        )

    # Attempt to get inline policies for this user.
    try:
        user_policies = iam.list_user_policies(UserName=user['User']['UserName'])
        logger.info(
            'User "%s" has %0d inline policies',
            user['User']['UserName'],
            len(user_policies['PolicyNames'])
        )

        # List all policies, if present.
        for policy in user_policies['PolicyNames']:
            logger.info('-- Policy "%s"', policy)

    except botocore.exceptions.ClientError as err:
        logger.error(
            'Unable to query for user policies for "%s" (list_user_policies): %s',
            user['User']['UserName'],
            err
        )

    # Attempt to get the groups attached to this user.
    try:
        user_groups = iam.list_groups_for_user(UserName=user['User']['UserName'])
        logger.info(
            'User "%s" has %0d groups associated',
            user['User']['UserName'],
            len(user_groups['Groups'])
        )

        # List all groups, if present.
        for group in user_groups['Groups']:
            try:
                group_policy = iam.list_group_policies(GroupName=group['GroupName'])
                logger.info(
                    '-- Group "%s" has %0d inline policies',
                    group['GroupName'],
                    len(group_policy['PolicyNames'])
                )

                # List all group policy names.
                for policy in group_policy['PolicyNames']:
                    logger.info('---- Policy "%s"', policy)
            except botocore.exceptions.ClientError as err:
                logger.error(
                    '---- Failed to get policies for group "%s" (list_group_policies): %s',
                    group['GroupName'],
                    err
                )
    except botocore.exceptions.ClientError as err:
        logger.error(
            'Unable to query for groups for %s (list_groups_for_user): %s',
            user['User']['UserName'],
            err
        )

    # Try a brute-force approach.
    brute(access_key=access_key, secret_key=secret_key, session_token=session_token)

if __name__ == '__main__':
    main()
