# -*- coding: utf-8 -*-
# #!/usr/bin/env python
"""
Deploy docker image to ecs, upload repo to ecr
Pass the repository url, the tag and the service family
Also checks cluster is there or creates it
Sets up necessary ELB and TG
"""
import os
import sys
import time
import logging
import argparse
from ast import literal_eval

import boto3


class EcsConfigError(Exception):
    """
    Throw ECS config error
    """
    def __init__(self, message, errors=None):
        super(EcsConfigError, self).__init__(message)
        self.errors = errors


class EcsDefaults(object):
    """
    Default values for optional fields
    used in ecs creation and deployment
    """
    ELB_PROTOCOL = 'HTTP'
    ELB_PORT = 80
    INSTANCE_TYPE = 'm5.large'
    TASK_HOST_PORT = 0  # Use to 0 to let ECS decide from 32768-61000 (dynamic port mapping)
    SERVICE_LAUNCH_TYPE = 'EC2'
    SERVICE_SCHEDULING_STRATEGY = 'REPLICA'
    SERVICE_MIN_HEALTHY_PERCENT = 50
    SERVICE_MAX_PERCENT = 200
    SERVICE_TASK_COUNT = 1
    SERVICE_FORCE_DEPLOY = False
    TASK_CONTAINER_PORT = None  # Not required for stuff like cron jobs
    TASK_PROTOCOL = 'tcp'
    TASK_NETWORK_MODE = 'bridge'
    TASK_CPU = 256  # Docker container ratio
    TASK_MEMORY = 512  # Docker container ratio
    TASK_RUN_WITHOUT_SERVICE = False
    ELB_HEALTH_CHECK_PATH = '/'
    ELB_HEALTH_CHECK_STATUS_CODE = '200'
    INSTANCE_KEY_PAIR = 'operations'
    IAM_ROLE = 'ecsServiceInstanceRole'  # Same as instance_profile
    DNS_DOMAIN = ''
    STACK_TEMPLATE_URL = 'TODO:InsertOwn'
    EBS_DEVICE_NAME = '/dev/xvdcz'
    EBS_VOL_SIZE = '22'
    EBS_VOL_TYPE = 'gp2'
    AUTO_SCALE_MAX_SIZE = 1  # Instance count to start for cluster

    # ECS Optimized AMI to use, different per region. ID changes when an updated AMI is released.
    # https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-optimized_AMI.html
    AMI_IDS = {
        'ca-central-1': 'ami-192fa27d',
        'us-east-1': 'ami-00129b193dc81bc31',
    }

# TODO: Auto-scaling
# https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service-autoscaling-targettracking.html  (service)
# https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch_alarm_autoscaling.html (cluster)
class Ecs(object):
    """
    ECS deployment core functions
    """

    def __init__(self, ecr_image_name, ecr_image_tag, service_family, vpc, cluster, region,
                 task_container_port, task_env_vars, app_env,
                 task_host_port=None,
                 service_task_count=None,
                 service_max_percent=None,
                 service_min_healthy_percent=None,
                 service_scheduling_strategy=None,
                 service_launch_type=None,
                 service_force_deploy=None,
                 service_placement_constraint=None,
                 elb_port=None,
                 elb_protocol=None,
                 elb_health_check_path=None,
                 elb_health_check_status_code=None,
                 elb_security_groups=None,
                 elb_subnets=None,
                 task_network_mode=None,
                 task_cpu=None,
                 task_memory=None,
                 task_protocol=None,
                 task_run_without_service=False,
                 instance_type=None,
                 instance_key_pair=None,
                 instance_availability_zones=None,
                 log_port=None,
                 log_host=None,
                 iam_role=None,
                 dns_name=None,
                 dns_domain=None,
                 ebs_device_name=None,
                 ebs_vol_type=None,
                 ebs_vol_size=None,
                 auto_scale_max_size=None):
        """
        Ecs Deployment init
        :param ecr_image_name: str, ecr image
        :param ecr_image_tag: str, version tag
        :param service_family: str, project name
        :param vpc: str, vpc name
        :param cluster: str, cluster name
        :param region: str, aws region
        :param task_container_port: str, container port
        :param task_env_vars: str, app env vars
        :param task_host_port: int, host port
        :param app_env: str, app env i.e. dev
        :param service_task_count: int, task count
        :param service_max_percent: int, max percent task up
        :param service_min_healthy_percent: int, min percent task up
        :param service_scheduling_strategy: str, scheduling strategy
        :param service_launch_type: str, launch type
        :param service_force_deploy: bool, force service deploy
        :param service_placement_constraint: str, service placement constraint
        :param elb_port: int, elb port
        :param elb_protocol: str, elb protocol
        :param elb_health_check_path: str, app health check path for elb
        :param elb_health_check_status_code: str, health check status code
        :param elb_security_groups: str, comma delimited security group names for elb
        :param elb_subnets: str, comma delimited elb subnets
        :param task_network_mode: str, network mode
        :param task_cpu: int, cpu per task
        :param task_memory: int, memory per task i.e. 1024
        :param task_protocol: str, task protocol i.e. tcp
        :param instance_type: str, ec2 instance type
        :param instance_key_pair: str, ec2 key pair
        :param instance_availability_zones: str, availability zones in region
        :param log_port: str, logstash port
        :param log_host: str, logstash host
        :param iam_role: str, IAM role to create for cluster
        :param dns_name: str, dns name for project (high level)
        :param dns_domain: str, dns domain for project
        :param ebs_device_name: str, ec2 ebs dev name
        :param ebs_vol_size: str, ec2 vol size
        :param ebs_vol_type: str, edc2 vol type
        :param auto_scale_max_size: int, number of instances to launch and register to the cluster
        """
        print("Running python version {}, boto3 version {}".format(sys.version, boto3.__version__))
        if not (vpc and region and service_family and app_env and cluster):
            raise EcsConfigError("__init__ missing vpc or region or service_family or app_env or cluster")

        # Primary params
        self.region = region
        self.app_env = app_env
        self.vpc = vpc
        self.cluster = cluster
        print("EcsDeployment got region {}, env {}, vpc {}, cluster {}".format(region, app_env, vpc, cluster))

        # Establish all required aws conns
        self.session = boto3.Session()
        self.ecs_client = self.session.client('ecs', region_name=self.region)
        self.ecr_client = self.session.client('ecr', region_name=self.region)
        self.elb_client = self.session.client('elbv2', region_name=self.region)
        self.ec2_client = self.session.client('ec2', region_name=self.region)
        self.logs_client = self.session.client('logs', region_name=self.region)
        self.route53_client = self.session.client('route53', region_name=self.region)
        self.autoscaling_client = self.session.client('autoscaling', region_name=self.region)
        self.iam_client = self.session.client('iam', region_name=self.region)
        self.cloudformation_client = self.session.client('cloudformation', region_name=self.region)

        # Coming from env-vars will be a strings but need list
        if isinstance(task_env_vars, str):
            task_env_vars = literal_eval(task_env_vars)
        if isinstance(elb_security_groups, str):
            elb_security_groups = list(filter(None, elb_security_groups.split(',')))
        elb_security_groups = elb_security_groups or []
        if isinstance(elb_subnets, str):
            elb_subnets = list(filter(None, elb_subnets.split(',')))
        elb_subnets = elb_subnets or []

        self.ecr_image_name = ecr_image_name
        self.ecr_image_tag = ecr_image_tag  # Version tag of release, from github & package

        self.service_family = service_family
        self.service_launch_type = service_launch_type or EcsDefaults.SERVICE_LAUNCH_TYPE
        self.service_scheduling_strategy = service_scheduling_strategy or EcsDefaults.SERVICE_SCHEDULING_STRATEGY
        self.service_min_healthy_percent = int(service_min_healthy_percent) \
            if service_min_healthy_percent else EcsDefaults.SERVICE_MIN_HEALTHY_PERCENT
        self.service_max_percent = int(service_max_percent) if service_max_percent else EcsDefaults.SERVICE_MAX_PERCENT
        self.service_task_count = int(service_task_count) if service_task_count else EcsDefaults.SERVICE_TASK_COUNT
        self.service_force_deploy = True if str(service_force_deploy) == 1 else EcsDefaults.SERVICE_FORCE_DEPLOY

        self.task_host_port = task_host_port or EcsDefaults.TASK_HOST_PORT
        self.task_container_port = task_container_port or EcsDefaults.TASK_CONTAINER_PORT
        self.task_protocol = task_protocol or EcsDefaults.TASK_PROTOCOL
        self.task_network_mode = task_network_mode or EcsDefaults.TASK_NETWORK_MODE
        self.task_env_vars = task_env_vars
        self.task_cpu = task_cpu or EcsDefaults.TASK_CPU
        self.task_memory = task_memory or EcsDefaults.TASK_MEMORY
        self.task_run_without_service = int(task_run_without_service) \
            if task_run_without_service else EcsDefaults.TASK_RUN_WITHOUT_SERVICE
        self.port_mappings = []
        if self.task_container_port:
            self.task_container_port = int(self.task_container_port)
            self.port_mappings = [{
                'containerPort': self.task_container_port,
                'hostPort': int(self.task_host_port),
                'protocol': self.task_protocol,
            }]

        self.elb_port = elb_port or EcsDefaults.ELB_PORT
        self.elb_protocol = elb_protocol or EcsDefaults.ELB_PROTOCOL
        self.elb_health_check_path = elb_health_check_path or EcsDefaults.ELB_HEALTH_CHECK_PATH
        self.elb_health_check_status_code = elb_health_check_status_code or EcsDefaults.ELB_HEALTH_CHECK_STATUS_CODE
        self.elb_security_groups = [self._get_security_group_by_name(sg_name) for sg_name in elb_security_groups]
        self.elb_subnets = [self._get_subnet_by_name_tag(subnet_name) for subnet_name in elb_subnets]

        # This is different from the instance SG, it neexds access to the dynamic port range but ELB only port 80
        # EC2 instance for the cluster, sec groups. Also include the common sg
        self.instance_type = instance_type or EcsDefaults.INSTANCE_TYPE
        self.env_common_sg = self._get_security_group_by_name('{}-common-sg'.format(self.app_env), force_error=False)
        self.instance_security_groups = [self.env_common_sg, ] if self.env_common_sg else []
        self.instance_subnet = self.elb_subnets[0] if self.elb_subnets else None
        self.instance_key_pair = instance_key_pair or EcsDefaults.INSTANCE_KEY_PAIR
        # Allows instance to join cluster
        self.instance_user_data = "#!/bin/bash\n" \
                                  "echo ECS_CLUSTER={} >> /etc/ecs/ecs.config;" \
                                  "echo ECS_BACKEND_HOST= >> /etc/ecs/ecs.config;".format(self.cluster)
        self.instance_availability_zones = instance_availability_zones or \
                                           ['{}a'.format(self.region), '{}b'.format(self.region), ]

        # Should generally not be used, reduces efficiency
        self.placement_constraints = []
        if service_placement_constraint:
            self.placement_constraints.append({'type': service_placement_constraint})  # i.e. distinctInstance

        # First part of the dns name
        self.dns_name = dns_name or self.service_family.replace('-', '').replace('_', '')
        self.dns_domain = dns_domain or EcsDefaults.DNS_DOMAIN

        self.iam_role = iam_role or EcsDefaults.IAM_ROLE
        self.iam_instance_profile_arn = None  # Created later
        self.target_group_arn = None  # Defined dynamically at target group create
        self.auto_scale_name = 'EC2ContainerService(ecs_deploy.py)-{}-EcsInstance'.format(self.cluster)

        self.auto_scale_max_size = auto_scale_max_size or EcsDefaults.AUTO_SCALE_MAX_SIZE

        self.ebs_device_name = ebs_device_name or EcsDefaults.EBS_DEVICE_NAME
        self.ebs_vol_size = ebs_vol_size or EcsDefaults.EBS_VOL_SIZE
        self.ebs_vol_type= ebs_vol_type or EcsDefaults.EBS_VOL_TYPE

        # Add log_config if passed
        self.log_configuration = None
        if log_host and log_port:
            self.log_configuration = {
                "logDriver": "syslog",
                "options": {
                    "syslog-address": 'tcp://{}:{}'.format(log_host, log_port),
                    "syslog-format": 'rfc3164',
                    "tag": "{{.ImageName}}/{{.Name}}/{{.ID}}"
                }
            }

        self.stack_name = 'EC2ContainerService-{}-ForEcsClusterByEcsDeployPy'.format(self.cluster)


    def create_ecs_stack_and_cluster(self):
        """
        Creates everything needed to form a cluster
        along with supporting iam roles, security groups,
        stack, elb and target groups
        :return: dict, response
        """
        self._create_iam_role()
        self._create_ecs_dynamic_port_sg()
        response = self._create_cluster()
        self._create_stack()
        self._create_elb_and_tg()
        return response

    def create_ecr_repo(self):
        """
        Create ECR Repo if not exists
        :return: dict, response
        """
        self.service_family='django2'
        print("Creating repo {}".format(self.service_family))

        if not self.service_family:
            raise EcsConfigError("create_ecr_repo missing service_family")

        try:
            response = self.ecr_client.describe_repositories(repositoryNames=[self.service_family, ])
            print("Repository already exists")
        except self.ecr_client.exceptions.RepositoryNotFoundException:
            response = self.ecr_client.create_repository(repositoryName=self.service_family)
            print("Created repo, arn {}".format(response['repository']['repositoryArn']))

        return response

    def deploy_task(self):
        """
        Deploy latest task to service or direct
        Registers new task & updates service
        if appicable
        :return: bool, success
        """
        response = self._register_task_definition()
        if self.task_run_without_service:
            self._create_task_without_service(response['taskDefinition']['taskDefinitionArn'])
        else:
            self._create_or_update_service()
        return True

    def create_stack(self):
        """
        Create the stack
        Run self._create_iam_role() first to get
        instance profile arn
        :return: dict, response
        """
        print("Creating stack")
        try:
            response = self.cloudformation_client.create_stack(
                StackName=self.stack_name,
                TemplateURL=EcsDefaults.STACK_TEMPLATE_URL,
                # TemplateBody=json.dumps(template_object)  # TODO: Use for version control later
                Parameters=self._get_stack_params(),
                TimeoutInMinutes=300,
                Tags=[{'Key': 'Description', 'Value': "AWS CF template for ECS deployment (ecs_deploy.py) NEW"}, ],
                OnFailure='ROLLBACK', # Also DO_NOTHING or DELETE
                EnableTerminationProtection=False
            )
            print("Created stack, arn {}".format(response['StackId']))
        except self.cloudformation_client.exceptions.AlreadyExistsException:
            print("Stack already exists")
            response = None

        return response

    def update_stack(self):
        """
        Update CF stack
        :return: dict, response
        """
        print("Updating stack")
        # For whatever reason the Key Values have to change or no update is performed
        response = self.cloudformation_client.update_stack(
            StackName=self.stack_name,
            # TemplateBody=json.dumps(template_object)  # TODO: Use for version control later
            TemplateURL=EcsDefaults.STACK_TEMPLATE_URL,
            Parameters=self._get_stack_params(),
            Tags=[{'Key': 'Description',
                   'Value': "AWS CF template for ECS deployment (ecs_deploy.py) {}".format(time.time)}],
        )
        print("Updated stack, arn {}".format(response['StackId']))

        return response

    def _create_or_update_service(self):
        """
        Creates or updates ecs service
        :return: dict, response
        """
        if not (self.service_family and self.cluster and self.vpc):
            raise EcsConfigError("create_or_update_service missing key environment variables")

        if self.is_service_created:
            print("Service already created")
            response = self._update_service()
        else:
            response = self._create_service()

        print("create_or_update_service response {}".format(response))
        return response

    def _create_service(self):
        """
        Create new ecs service
        Will always have a load balancer when creating service
        if not required use run task without service
        :return: dict, response
        """
        print("Creating new service")
        response = self.ecs_client.create_service(
            launchType=self.service_launch_type,
            taskDefinition=self.service_family,
            cluster=self.cluster,
            serviceName=self.service_family,
            schedulingStrategy=self.service_scheduling_strategy,
            desiredCount=self.service_task_count,
            deploymentConfiguration={
                'maximumPercent': self.service_max_percent,
                'minimumHealthyPercent': self.service_min_healthy_percent,
            },
            placementConstraints=self.placement_constraints,
            loadBalancers=[
                {
                    'containerName': self.service_family,
                    'containerPort': self.task_container_port,
                    'targetGroupArn': self.target_group_arn,
                },
            ],
        )
        return response

    def _update_service(self):
        """
        Update ecs service
        :return: dict, response
        """
        print("Updating existing service")
        response = self.ecs_client.update_service(
            taskDefinition=self.service_family,
            cluster=self.cluster,
            service=self.service_family,
            desiredCount=self.service_task_count,
            deploymentConfiguration={
                'maximumPercent': self.service_max_percent,
                'minimumHealthyPercent': self.service_min_healthy_percent,
            },
            forceNewDeployment=self.service_force_deploy,
        )
        return response

    def _get_security_group_by_name(self, name, force_error=True):
        """
        Get SG id by name
        :param name: str, name of group
        :param force_error: bool, force error
        :return: str, sec group id
        """
        response = self.ec2_client.describe_security_groups(
            Filters=[{'Name': 'group-name', 'Values': [name, ]},
                     {'Name': 'vpc-id', 'Values': [self.vpc, ]}],
            DryRun=False,
        )

        _id = None
        if response['SecurityGroups']:
            _id = response['SecurityGroups'][0]['GroupId']

        if force_error and not _id:
            raise EcsConfigError("_get_security_group_by_name unable to get '{}' in region {}, vpc {}"
                                           "".format(name, self.region, self.vpc))

        return _id

    def _get_subnet_by_name_tag(self, name, force_error=True):
        """
        Get Subnet id by name
        :param name: str, name of subnet
        :param force_error: bool, force error
        :return: str, subnet id
        """
        response = self.ec2_client.describe_subnets(
            Filters=[{'Name': 'tag:Name', 'Values': [name, ]},
                     {'Name': 'vpc-id', 'Values': [self.vpc, ]}],
            DryRun=False,
        )

        _id = None
        if response['Subnets']:
            _id = response['Subnets'][0]['SubnetId']

        if force_error and not _id:
            raise EcsConfigError("_get_subnet_by_name_tag unable to get '{}' in region {}, vpc {}"
                                           "".format(name, self.region, self.vpc))

        return _id

    def _create_ecs_dynamic_port_sg(self):
        """
        Creates dynamic port mapping security group
        To allow multiple containers of same app running
        on a single instance with different ports
        :return: str, group_id
        """
        print("Creating dynamic port sg")
        if not (self.app_env and self.vpc):
            raise EcsConfigError("create_ecs_sg missing key environment variables")

        group_name = '{}-ecs-dynamic-ports-sg'.format(self.app_env)
        response = self.ec2_client.describe_security_groups(
            Filters=[{'Name': 'vpc-id', 'Values': [self.vpc, ]},
                     {'Name': 'group-name', 'Values': [group_name, ]}],
            DryRun=False
        )

        if response['SecurityGroups']:
            print("Dynamic port sg already exists")
            group_id = response['SecurityGroups'][0]['GroupId']
        else:
            response = self.ec2_client.create_security_group(
                Description='dynamic port mapping for ecs dev',
                GroupName=group_name,
                VpcId=self.vpc,
                DryRun=False
            )
            group_id = response['GroupId']

            # Can also specify list of rules using IpPermissions (to add Description)
            response = self.ec2_client.authorize_security_group_ingress(
                GroupId=group_id,
                CidrIp='0.0.0.0/0',
                FromPort=32768,
                IpProtocol='tcp',
                ToPort=61000,
                DryRun=False
            )
            print("Created dyanmic port sg, id {}".format(group_id))

        self.instance_security_groups.append(group_id)
        return response

    def _create_launch_config(self):
        """
        Create launch config
        To update delete the old launch config manually
        No need to run this if using cf stack
        :return:
        """
        print("Creating launch config")
        try:
            response = self.autoscaling_client.create_launch_configuration(
                LaunchConfigurationName=self.auto_scale_name + 'Lc',
                ImageId=EcsDefaults.AMI_IDS[self.region],
                KeyName=self.instance_key_pair,
                SecurityGroups=self.instance_security_groups,
                UserData=self.instance_user_data,
                InstanceType=self.instance_type,
                AssociatePublicIpAddress=True,
                EbsOptimized=False,
                BlockDeviceMappings=[
                    {
                        'DeviceName': '/dev/xvdcz',
                        'Ebs': {
                            'VolumeSize': 22,
                            'VolumeType': 'gp2',
                            'DeleteOnTermination': True,
                        },
                    },
                ],
                IamInstanceProfile=self.iam_role,
            )
            print("Created launch config")
        except self.autoscaling_client.exceptions.AlreadyExistsFault:
            print("Launch configuration already exists")
            response = None

        return response

    def _create_auto_scale_group(self):
        """
        Create a scale group
        No need to run this if using cf stack
        :return: dict, response
        """
        print("Creating auto scale group")
        role = 'arn:aws:iam::584374059506:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling'

        response = self.autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName=self.auto_scale_name + 'Asg',
            LaunchConfigurationName=self.auto_scale_name + 'Lc',
            MinSize=0,
            MaxSize=2,
            DesiredCapacity=2,
            DefaultCooldown=300,
            AvailabilityZones=self.instance_availability_zones,
            NewInstancesProtectedFromScaleIn=True|False,
            ServiceLinkedRoleARN=role,
            VPCZoneIdentifier=self.instance_subnet
        )
        print(response)

        # https://boto3.readthedocs.io/en/latest/reference/services/application-autoscaling.html#ApplicationAutoScaling.Client.register_scalable_target
        # response = self.autoscaling_client.register_scalable_target(
        #     ServiceNamespace='ecs',
        #     ResourceId='service/{}/{}'.format(self.cluster, self.service_family),
        #     ScalableDimension='ecs:service:DesiredCount',
        #     MinCapacity=1,
        #     MaxCapacity=1,
        #     RoleARN=self.iam_role
        # )
        # print(response)
        print("Created auto scale group")

        return response

    def _get_stack_params(self):
        """
        Get all the stack params for stac
        creation or update
        :return: list of dicts, stack params
        """
        if not self.iam_instance_profile_arn:
            self._create_iam_role()
            # raise EcsConfigError("_create_stack iam_instance_profile_arn required")

        # All parameters must be strings
        availability_zones = ','.join(self.instance_availability_zones)
        from_to_port = str(self.elb_port)
        params = [
            {'ParameterKey': 'AsgMaxSize', 'ParameterValue': str(self.auto_scale_max_size), 'UsePreviousValue': False},
            {'ParameterKey': 'DeviceName', 'ParameterValue': self.ebs_device_name, 'UsePreviousValue': False},
            {'ParameterKey': 'EbsVolumeSize', 'ParameterValue': self.ebs_vol_size, 'UsePreviousValue': False},
            {'ParameterKey': 'EbsVolumeType', 'ParameterValue': self.ebs_vol_type, 'UsePreviousValue': False},
            {'ParameterKey': 'EcsAmiId', 'ParameterValue': EcsDefaults.AMI_IDS[self.region], 'UsePreviousValue': False},
            {'ParameterKey': 'EcsClusterName', 'ParameterValue': self.cluster, 'UsePreviousValue': False},
            {'ParameterKey': 'EcsEndpoint', 'ParameterValue': '', 'UsePreviousValue': False},
            {'ParameterKey': 'EcsInstanceType', 'ParameterValue': self.instance_type, 'UsePreviousValue': False},
            {'ParameterKey': 'IamRoleInstanceProfile', 'ParameterValue': self.iam_instance_profile_arn,
             'UsePreviousValue': False},
            {'ParameterKey': 'IamSpotFleetRoleArn', 'ParameterValue': '', 'UsePreviousValue': False},
            {'ParameterKey': 'IsWindows', 'ParameterValue': 'false', 'UsePreviousValue': False},
            {'ParameterKey': 'KeyName', 'ParameterValue': self.instance_key_pair, 'UsePreviousValue': False},
            {'ParameterKey': 'SecurityGroupId', 'ParameterValue': self.instance_security_groups[0],
             'UsePreviousValue': False},
            {'ParameterKey': 'SecurityIngressCidrIp', 'ParameterValue': '0.0.0.0/0', 'UsePreviousValue': False},
            {'ParameterKey': 'SecurityIngressFromPort', 'ParameterValue': from_to_port, 'UsePreviousValue': False},
            {'ParameterKey': 'SecurityIngressToPort', 'ParameterValue': from_to_port, 'UsePreviousValue': False},
            {'ParameterKey': 'SpotAllocationStrategy', 'ParameterValue': 'diversified', 'UsePreviousValue': False},
            {'ParameterKey': 'SpotPrice', 'ParameterValue': '', 'UsePreviousValue': False},
            {'ParameterKey': 'SubnetCidr1', 'ParameterValue': '10.0.0.0/24', 'UsePreviousValue': False},
            {'ParameterKey': 'SubnetCidr2', 'ParameterValue': '10.0.1.0/24', 'UsePreviousValue': False},
            {'ParameterKey': 'SubnetCidr3', 'ParameterValue': '', 'UsePreviousValue': False},
            {'ParameterKey': 'SubnetIds', 'ParameterValue': self.instance_subnet, 'UsePreviousValue': False},
            {'ParameterKey': 'UserData', 'ParameterValue': self.instance_user_data, 'UsePreviousValue': False},
            {'ParameterKey': 'UseSpot', 'ParameterValue': 'false', 'UsePreviousValue': False},
            {'ParameterKey': 'VpcAvailabilityZones', 'ParameterValue': availability_zones, 'UsePreviousValue': False},
            {'ParameterKey': 'VpcCidr', 'ParameterValue': '10.0.0.0/16', 'UsePreviousValue': False},
            {'ParameterKey': 'VpcId', 'ParameterValue': self.vpc, 'UsePreviousValue': False},

        ]

        print("Stack params are: {}".format(params))
        return params

    def _create_iam_role(self):
        """
        Create IAM role and instance profile
        There are 4 steps to creating an instance profile:
        create a role
        add a policy to the role
        create an instance profile
        add the role to the profile
        Once you have an instance profile, you can run instances with this profile
        :return: tuple(dict, response , str instance profile arn)
        """
        print("Creating IAM role and instance profile")

        # May only need ec2 trust for now
        assume_role_policy_trust_doc = """{
          "Version": "2008-10-17",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": "ec2.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            },
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": "ecs.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            },
            {
              "Effect": "Allow",
              "Principal": {
                "Service": "application-autoscaling.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        }"""

        # May not need AmazonEC2ContainerServiceRole or AmazonEC2ContainerServiceAutoscaleRole for now
        role_policies = ['arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role',
                         'arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole',
                         'arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceAutoscaleRole']

        # May not need autoscaling right now
        inline_policy = """{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ecs:CreateCluster",
                        "ecs:DeregisterContainerInstance",
                        "ecs:DiscoverPollEndpoint",
                        "ecs:Poll",
                        "ecs:RegisterContainerInstance",
                        "ecs:StartTelemetrySession",
                        "ecs:UpdateContainerInstancesState",
                        "ecs:Submit*",
                        "ecr:GetAuthorizationToken",
                        "ecr:BatchCheckLayerAvailability",
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:BatchGetImage",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:Describe*",
                        "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                        "elasticloadbalancing:DeregisterTargets",
                        "elasticloadbalancing:Describe*",
                        "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
                        "elasticloadbalancing:RegisterTargets"
                        "application-autoscaling:*",
                        "cloudwatch:DescribeAlarms",
                        "cloudwatch:PutMetricAlarm"
                    ],
                    "Resource": [
                        "*"
                    ]
                }
            ]
        }"""

        try:
            response = self.iam_client.create_role(
                RoleName=self.iam_role,
                AssumeRolePolicyDocument=assume_role_policy_trust_doc,
                Description='{}(ecs_deploy.py)'.format(self.iam_role),
            )
            print("Created IAM role, arn {}".format(response['Role']['Arn']))

            # Get AWS managed policies by name & attach
            for policy_arn in role_policies:
                self.iam_client.attach_role_policy(
                    RoleName=self.iam_role,
                    PolicyArn=policy_arn
                )

            # Inline policy
            self.iam_client.put_role_policy(
                RoleName=self.iam_role,
                PolicyName='AccessToStageRepository',
                PolicyDocument=inline_policy
            )

        except self.iam_client.exceptions.EntityAlreadyExistsException:
            response = self.iam_client.get_role(RoleName=self.iam_role)
            iam_role_arn = response['Role']['Arn']
            print("IAM role already exists, arn {}".format(iam_role_arn))


        response = self.iam_client.list_instance_profiles_for_role(RoleName=self.iam_role)
        profile_found = False
        for profile in response['InstanceProfiles']:
            if profile['InstanceProfileName'] == self.iam_role:
                profile_found = True
                self.iam_instance_profile_arn = profile['Arn']
                print("Instance profile already exists, arn {}".format(self.iam_instance_profile_arn))
                break

        if not profile_found:
            response = self.iam_client.create_instance_profile(InstanceProfileName=self.iam_role)
            self.iam_instance_profile_arn = response['InstanceProfile']['Arn']
            print("Created instance profile, arn".format(self.iam_instance_profile_arn))

            response = self.iam_client.add_role_to_instance_profile(
                InstanceProfileName=self.iam_role,
                RoleName=self.iam_role
            )
            print("Added role to instance profile")


        return response

    def _create_instance_for_cluster(self):

        """
        Creates ec2 instances for the cluster
        By default, your container instance launches into your default cluster.
        If you want to launch into your own cluster instead of the default,
        choose the Advanced Details list and paste the following script
        into the User data field, replacing your_cluster_name with the name of your cluster.
        !/bin/bash
        echo ECS_CLUSTER=your_cluster_name >> /etc/ecs/ecs.config
        No need to run this if using cf stack
        :return:
        """
        print("Creating ec2 instances for cluster")
        print("Creating ec2 instance for cluster {}, type {}, ssh key {}, sg {}, subnet {}"
              "".format(self.cluster, self.instance_type, self.instance_key_pair, self.instance_security_groups,
                        self.instance_subnet))

        if not self.instance_subnet:
            raise EcsConfigError("_create_instance_for_cluster ebs subnets are required")

        response = self.ec2_client.run_instances(
            # Use the official ECS image
            ImageId=EcsDefaults.AMI_IDS[self.region],
            MinCount=1,
            MaxCount=1,
            InstanceType=self.instance_type,
            KeyName=self.instance_key_pair,  # operations is prod
            IamInstanceProfile={
                "Name": self.iam_role  # Same name as role
            },
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': "EC2Instance-{}-(ecs_deploy.py)-EcsInstance".format(self.cluster)
                        },
                    ]
                },
            ],
            SecurityGroupIds=self.instance_security_groups,
            SubnetId=self.instance_subnet,
            UserData="#!/bin/bash \n echo ECS_CLUSTER=" + self.cluster + " >> /etc/ecs/ecs.config"
        )
        print("Created instances: {}".format([instance['InstanceId'] for instance in response['Instances']]))
        return response

    def _create_cluster(self):
        """
        Create cluster if not exists
        :return: dict, response
        """
        response = self.ecs_client.describe_clusters(clusters=[self.cluster, ])
        clusters_found = response['clusters']
        if clusters_found and clusters_found[0]['status'] == 'ACTIVE':
            instance_count = clusters_found[0]['registeredContainerInstancesCount']
            print("Cluster already exists, has {} instances".format(instance_count))
        else:
            print("Creating cluster")
            response = self.ecs_client.create_cluster(clusterName=self.cluster)
            print("Created cluster with arn {}".format(response['cluster']['clusterArn']))

        return response

    def _create_target_group(self):
        """
        Create the target group if not exists
        :return: dict, response
        """
        print("Creating target group")
        target_group_name = '{}-tg'.format(self.service_family)
        try:
            response = self.elb_client.describe_target_groups(
                Names=[target_group_name, ],
            )
            self.target_group_arn = response['TargetGroups'][0]['TargetGroupArn']
            print("Target group already exists, arn {}".format(self.target_group_arn))
        except self.elb_client.exceptions.TargetGroupNotFoundException:
            response = self.elb_client.create_target_group(
                Name=target_group_name,
                Protocol=self.elb_protocol,
                Port=self.elb_port,
                VpcId=self.vpc,
                HealthCheckProtocol=self.elb_protocol,
                HealthCheckPort='traffic-port',
                HealthCheckPath=self.elb_health_check_path,
                HealthCheckIntervalSeconds=35,
                HealthCheckTimeoutSeconds=15,
                HealthyThresholdCount=2,
                UnhealthyThresholdCount=10,
                Matcher={'HttpCode': str(self.elb_health_check_status_code)},
                TargetType='instance'
            )
            self.target_group_arn = response['TargetGroups'][0]['TargetGroupArn']
            print("Created target group")

        # TODO: try sessions and auth in rds, or session in redis (easy to check why not working)
        # Need to update the attributes to include sticky sessions, seems to be required
        # for dynamic port mapping. So same client will continue to hit same server.
        # May be able to drop this if we have all auth, session tables in rds. Adding session cache in
        # memcache didn't seem to fix this.
        response = self.elb_client.modify_target_group_attributes(
            TargetGroupArn=self.target_group_arn,
            Attributes=[
                {'Key': 'stickiness.enabled', 'Value': 'true'},
                {'Key': 'stickiness.type', 'Value': 'lb_cookie'},
            ]
        )

        return response

    def _create_public_dns_record(self):
        """
        Creates public DNS record to proxy
        This probably only applies to dev env
        :return: dict, response
        """
        print("Creating public dns record")
        return self._create_route53_dns_record(
            zone_name='{}.{}.'.format(self.app_env, self.dns_domain),
            record_name='{}.{}.{}.'.format(self.dns_name, self.app_env, self.dns_domain),
            record_type='CNAME',
            record_value='proxy.{}.{}'.format(self.app_env, self.dns_domain))

    def _create_internal_dns_record(self, record_value):
        """
        Creates internal DNS record to the ELB
        :param record_value: str, DNS CNAME to point internal
            DNS to i.e. of ELB
        :return: dict, response
        """
        print("Creating private dns record")
        return self._create_route53_dns_record(
            zone_name='internal.{}.{}.'.format(self.app_env, self.dns_domain),
            record_name='{}.internal.{}.{}.'.format(self.dns_name, self.app_env, self.dns_domain),
            record_type='CNAME',
            record_value=record_value)

    def _create_route53_dns_record(self, zone_name, record_name, record_type, record_value):
        """
        Create a route 53 dns record if not exists
        :param zone_name: str, zone name
        :param record_name: str, record name
        :param record_type: str, record type
        :return: dict, response
        """
        response = self.route53_client.list_hosted_zones_by_name(DNSName=zone_name)
        if response['HostedZones']:
            host_zone_id = response['HostedZones'][0]['Id']
            response = self.route53_client.list_resource_record_sets(
                HostedZoneId=host_zone_id,
                StartRecordName=record_name,
                StartRecordType=record_type
            )
            found_record = None
            for record in response['ResourceRecordSets']:
                if record['Name'] == record_name:
                    found_record = record
                    break

            if found_record:
                print("DNS record-set in zone '{}' with name '{}' already exists".format(zone_name, record_name))
                if record_type != found_record['Type']:
                    print("WARNING: record type of existing record set is {}, instead of {}"
                          "".format(found_record['Type'], record_type))
            else:
                print("Creating DNS record-set {}".format(record_name))
                response = self.route53_client.change_resource_record_sets(
                    HostedZoneId=host_zone_id,
                    ChangeBatch={
                        'Comment': 'aws_deploy created at {}'.format(time.time()),
                        'Changes': [
                            {
                                'Action': 'UPSERT',
                                'ResourceRecordSet': {
                                    'Name': record_name,
                                    'Type': record_type,
                                    'ResourceRecords': [{'Value': record_value}, ],
                                    'TTL': 60,
                                }
                            },
                        ]
                    }
                )
        else:
            print("WARNING: Hosted zone not found, skipping DNS record creation")

        return response

    def _create_dns_records(self, elb_dns):
        """
        Create Route53 DNS records
        :return:
        """
        # TODO: Figure it out for other envs
        # Special case for dev. Not sure if needed for other environments at the moment.
        if self.app_env == 'dev':
            print("Creating DNS records")
            public_dns = '{}.internal.{}.{}.'.format(
                self.service_family.replace('-', ''), self.app_env, self.dns_domain)
            print("WARNING: Add DNS CNAME entry for {} to {} and restart proxy".format(public_dns, elb_dns))
            self._create_internal_dns_record(elb_dns)
            self._create_public_dns_record()
        else:
            print("WARNING: Creating DNS records not configured for env {}".format(self.app_env))

    def _create_elb(self):
        """
        Create the load balancer if not exists
        Add listeners
        :return: dict, response
        """
        print("Creating ELB")
        lb_name = '{}-lb'.format(self.service_family)
        try:
            response = self.elb_client.describe_load_balancers(Names=[lb_name, ])
            print("ELB already exists")
        except self.elb_client.exceptions.LoadBalancerNotFoundException:
            response = self.elb_client.create_load_balancer(
                Name=lb_name,
                Subnets=self.elb_subnets,
                SecurityGroups=self.elb_security_groups,
                Scheme='internal',
                Type='application',
                IpAddressType='ipv4',
            )
            print("ELB created")

            # Add listener, i.e. http on port 80 Forward to target group defined earlier
            print("Adding target group as listener to ELB")
            response = self.elb_client.create_listener(
                LoadBalancerArn=response['LoadBalancers'][0]['LoadBalancerArn'],
                Protocol=self.elb_protocol,
                Port=self.elb_port,
                DefaultActions=[{'Type': 'forward', 'TargetGroupArn': self.target_group_arn}, ]
            )

            self._create_dns_records(response['LoadBalancers'][0]['DNSName'])

        return response

    def _create_elb_and_tg(self):
        """
        Create app load balancer and target groups if
        not already exists and adds listeners to the tb
        :return: dict, response of last command
        """
        self._create_target_group()
        response = self._create_elb()
        return response

    def _create_cloud_watch_log(self, log_group_name):
        """
        Creates log group for service
        :return: dict, response
        """
        print("Creating cloudWatch log")
        if not self.service_family:
            raise EcsConfigError("create_log missing service_family")

        try:
            response = self.logs_client.create_log_group(logGroupName=log_group_name)
        except self.logs_client.exceptions.ResourceAlreadyExistsException:
            response = None

        return response

    def _register_task_definition(self, cleanup_old=False):
        """
        Register a ECS service task definition
        :return: dict, response
        """
        print("Registering task definition")
        if not (self.region and self.ecr_image_name and self.ecr_image_tag):
            raise EcsConfigError("create_log missing key environment variables")

        # Use default logging (aws cloud watch) if no other logging is configured
        if not self.log_configuration:
            cloud_watch_log_group = "/ecs/{}".format(self.service_family)
            self._create_cloud_watch_log(cloud_watch_log_group)
            self.log_configuration = {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": cloud_watch_log_group,
                    "awslogs-region": self.region,
                    "awslogs-stream-prefix": "ecs"
                }
            }

        response = self.ecs_client.register_task_definition(
            family=self.service_family,
            networkMode=self.task_network_mode,
            containerDefinitions=[
                {
                    'name': self.service_family,
                    'image': "{}:{}".format(self.ecr_image_name, self.ecr_image_tag),

                    'portMappings': self.port_mappings,
                    'essential': True,
                    "environment": self.task_env_vars,
                    'logConfiguration': self.log_configuration,
                },
            ],
            requiresCompatibilities=[
                self.service_launch_type,
            ],
            cpu=str(self.task_cpu),
            memory=str(self.task_memory),
        )
        print("Created task definition,\n {}".format(response))  # TODO

        if cleanup_old:
            self._remove_task_definitions()

        return response

    def _remove_task_definitions(self, keep_last_count=50):
        """
        Remove old task definitions
        :param keep_last_count:
        :return: dict, response
        """
        print("Removing old task definitions")
        # TODO: Figure out newly crated td and - keep_last_count
        # TODO: list all task defs response["taskDefinitionArns"]
        task_defs_to_remove = []
        response = None
        for task_definition in task_defs_to_remove:
            # De-register task definition(s)
            response = ecs_client.deregister_task_definition(
                taskDefinition=task_definition
            )
            print(response)
        return response

    def _create_task_without_service(self, new_task_arn):
        """
        Run standalone task without attaching it to
        a service. Can be used for stuff like cron jobs
        :param new_task_arn: str, task arn
        :return: dict, response
        """
        print("Creating task without service")
        response_list_tasks = self.ecs_client.list_tasks(
            cluster=self.cluster,
            family=self.service_family,
            desiredStatus='RUNNING'
        )

        for task_arn in response_list_tasks['taskArns']:
            response_task_stop = self.ecs_client.stop_task(
                cluster=self.cluster,
                task=task_arn,
                reason='Stopping running tasks to deploy the new version of the software'
            )
            print(response_task_stop)

        response = self.ecs_client.run_task(
            cluster=self.cluster,
            startedBy='jenkins-job',
            taskDefinition=new_task_arn
        )
        print("Created task without service")
        return response


def main():
    parser = argparse.ArgumentParser(description='Description of what the program does goes here.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--do-deploy', '--create-deploy', '--deploy', action='store_true',
                       dest='do_deploy', default=False, help='Deploy latest code to ECS')
    group.add_argument('--create-repo', '--create-repository', action='store_true',
                       dest='create_repo', default=False, help='Create the ECR repo')
    group.add_argument('--create-cluster', '--add-cluster', '--cluster', action='store_true',
                       dest='create_cluster', default=False, help='Create the entire ecs cluster and stack')
    group.add_argument('--create-stack', action='store_true',
                       dest='create_stack_only', default=False, help='Create the cf stack only')
    group.add_argument('--update-stack', action='store_true',
                       dest='update_stack_only', default=False, help='Update the cf stack only')

    args = vars(parser.parse_args())
    do_deploy = args.get('do_deploy')
    create_repo = args.get('create_repo')
    create_cluster = args.get('create_cluster')
    create_stack_only = args.get('create_stack_only')
    update_stack_only = args.get('update_stack_only')

    # Setup deploy using environment variables
    ecs = Ecs(
        cluster=os.environ.get('ECS_CLUSTER_NAME'),
        region=os.environ.get('AWS_REGION'),
        vpc=os.environ.get('AWS_VPC'),
        ecr_image_name=os.environ.get('ECR_IMAGE_NAME', ''),
        ecr_image_tag=os.environ.get('GIT_TAG_VERSION', ''),  # Created in Jenkinsfile
        app_env=os.environ.get('APP_ENV'),
        service_family=os.environ.get('ECS_SERVICE_FAMILY'),
        service_launch_type=os.environ.get('SERVICE_LAUNCH_TYPE'),
        service_scheduling_strategy=os.environ.get('SERVICE_SCHEDULING_STRATEGY'),
        service_min_healthy_percent=os.environ.get('SERVICE_MIN_HEALTHY_PERCENT'),
        service_max_percent=os.environ.get('SERVICE_MAX_PERCENT'),
        service_placement_constraint=os.environ.get('SERVICE_PLACEMENT_CONSTRAINT'),
        service_force_deploy=os.environ.get('SERVICE_FORCE_NEW_DEPLOYMENT'),
        service_task_count=os.environ.get('SERVICE_TASK_COUNT'),
        task_host_port=os.environ.get('TASK_HOST_PORT'),
        task_container_port=os.environ.get('TASK_CONTAINER_PORT'),
        task_env_vars=os.environ.get('TASK_ENV_VARS'),
        task_cpu=os.environ.get('TASK_CPU'),
        task_memory=os.environ.get('TASK_MEMORY'),
        task_run_without_service=os.environ.get('TASK_RUN_WITHOUT_SERVICE'),
        elb_health_check_path=os.environ.get('ELB_HEALTH_CHECK_PATH'),
        elb_health_check_status_code=os.environ.get('ELB_HEALTH_CHECK_STATUS_CODE'),
        elb_security_groups=os.environ.get('ELB_SECURITY_GROUPS'),
        elb_subnets=os.environ.get('ELB_SUBNETS'),
        log_host=os.environ.get('LOG_HOST'),
        log_port=os.environ.get('LOG_PORT'),
        # Cluster build specific vars below
        instance_key_pair=os.environ.get('INSTANCE_KEY_PAIR'),
        instance_type=os.environ.get('INSTANCE_TYPE'),
        instance_availability_zones=os.environ.get('INSTANCE_AVAILABILITY_ZONES'),
        iam_role=os.environ.get('IAM_ROLE'),
        dns_name=os.environ.get('DNS_NAME'),
        dns_domain=os.environ.get('DNS_DOMAIN'),
        ebs_device_name=os.environ.get('EBS_DEVICE_NAME'),
        ebs_vol_type=os.environ.get('EBS_VOL_TYPE'),
        ebs_vol_size=os.environ.get('EBS_VOL_SIZE'),
        auto_scale_max_size=os.environ.get('AUTO_SCALE_MAX_SIZE'),
    )

    # Create cluster and supporting infrastructure3
    if create_cluster:
        response = ecs.create_ecs_stack_and_cluster()
        logging.info("Create cluster response is {}".format(response))

    # Update or create stack only
    elif create_stack_only:
        response = ecs.create_stack()
        logging.info("Create stack response is {}".format(response))

    elif update_stack_only:
        response = ecs.update_stack()
        logging.info("Update stack response is {}".format(response))

    # Create ECR Repo
    elif create_repo:
        response = ecs.create_ecr_repo()
        logging.info("Create repo response is {}".format(response))

    # Do deploy
    elif do_deploy:
        response = ecs.deploy_task()
        logging.info("Deploy task response is {}".format(response))

    print('done')


if __name__ == "__main__":
    main()
