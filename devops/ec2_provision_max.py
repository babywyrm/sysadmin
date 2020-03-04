#!/usr/bin/python3

##
## c/o
## https://github.com/jamesdmorgan/ec2-boto3-provision
##   _please_test_under_pyth3__
##   _thank_u__
##
##
## 
########################################################

from botocore.exceptions import ClientError
import boto3
import logging
import argparse
import yaml
import sys
import time

logger = logging.getLogger(__name__)
args = None
doc = None
vpc_id = None


class Tag(object):

    def __init__(self, name, value):
        self.name = name
        self.value = value
        self.tag_string = self.make_tag(name, value)

        return None

    @classmethod
    def make_tag(cls, name, value):
        tag_dict = {'Key': name, 'Value': str(value)}
        logger.debug("Created tag {0} {1}".format(name, value))
        return tag_dict


def global_tags():

    tag_string = []

    tag_list = [
        {'CostCentre': 'cost_centre'},
        {'Role': 'role'},
        {'Team': 'team'},
    ]

    for d in tag_list:
        for k, v in d.iteritems():
            tag_value = doc["account"][v]
            tag_string.append(Tag(k, tag_value).tag_string)

    return tag_string


def setup_logging(verbose=False):
    '''
    Setup logging

    :param verbose: bool - Enable verbose debug mode
    '''

    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('[%(asctime)s] %(message)s'))
    logger.addHandler(ch)
    logger.setLevel(logging.INFO)
    if verbose:
        logger.setLevel(logging.DEBUG)
        boto3.set_stream_logger('boto3.resources', logging.DEBUG)


class Ec2(object):

    def __init__(self, profile_name):
        self.profile_name = profile_name
        self.resource = self.init_session()
        self.vpc = self.resource.Vpc(vpc_id)
        self.client = self.resource.meta.client

        logger.info("Initiased connection to vpc {0} using profile {1}"
                    .format(self.vpc.id, self.profile_name))

    def init_session(self):
        '''
        Initialise an EC2 session using defined profile
        '''
        s = boto3.session.Session(profile_name=self.profile_name)

        return s.resource('ec2')


class Parser(object):

    def __init__(self):

        global args

        help_text = '''
EC2 Utilities to manage security groups and instances
        '''

        yaml_text = '''
YAML defintion file with security groups and instances
        '''

        profile_text = '''
EC2 Authentication profile (.aws/credentials)
        '''

        parser = argparse.ArgumentParser(
            description=help_text,
            formatter_class=argparse.RawTextHelpFormatter
        )

        parser.add_argument('--verbose', '-v', action="count", default=0,
                            help='Verbose Logging')

        parser.add_argument('--profile', '-p', default='saml',
                            help=profile_text)

        parser.add_argument('--definitions', '-d',
                            required=True, help=yaml_text)

        parser.add_argument('--add_security_groups',
                            action='store_true',
                            default=False,
                            help='Add security groups')

        parser.add_argument('--add_instances',
                            action='store_true',
                            default=False,
                            help='Add instances')

        args = parser.parse_args()

        return None

    def parse_yaml(self, yaml_file):
        '''
        Parse the YAML input file
        '''

        global doc
        global vpc_id

        try:
            with open(yaml_file, 'r') as f:
                doc = yaml.load(f.read())

        except IOError:
            logger.error("{0} not found".format(yaml_file))
            sys.exit(1)

        vpc_id = doc["vpc_id"]

    def get_definition(self, key):
        if key not in doc:
            return []

        return doc[key]


class SecurityGroup(object):
    '''
    Manage EC2 Security groups and firewall rules
    '''

    def __init__(self, ec2, d):
        self.ec2 = ec2
        self.name = d.get('group_name')
        self.desc = d.get('description')
        self.permissions_ingress = d.get('permissions_ingress', [])
        self.permissions_egress = d.get('permissions_enress', [])
        self.obj = None

    def create(self):
        # Create the group if it doesn't exist
        self.obj = self.get_group_by_name(self.name)
        if not self.obj:
            self.obj = self.create_group()

        # Tag up the group with the global tags
        self.ec2.resource.create_tags(
            Resources=[self.obj.id],
            Tags=global_tags(),
        )

        self.revoke_permissions()
        self.authorize_permissions()

        return self.obj

    @staticmethod
    def get_group_ids(ec2, group_names):
        ids = []
        for g in ec2.vpc.security_groups.all():
            for name in group_names:
                if g.group_name == name:
                    ids.append(g.id)

        return ids

    def get_group_by_name(self, name):

        for g in self.ec2.vpc.security_groups.all():
            logger.debug("VPC {0} {1} {2}".format(
                g.vpc_id, g.group_name, g.description))
            if g.group_name == name:
                return g

        return None

    def create_group(self):
        logger.info("Creating group {0}".format(self.name))
        g = self.ec2.vpc.create_security_group(
            GroupName=self.name, Description=self.desc)

        return g

    def delete_group(self):
        '''
        Delete security group
        '''

        logger.info("Deleting group {0}".format(self.name))
        self.obj.delete()

    class IpPermissions(object):

        def __init__(self, type):
            self.type = type

    def revoke_permissions(self):
        '''
        TODO improve model for ingress/egress and remove duplication
        '''

        # Remove existing ingress (Inbound rules)
        current_ingress = self.obj.ip_permissions

        for perm_list in current_ingress:
            logger.debug("")
            for k, v in perm_list.iteritems():
                logger.debug("\t{0:<20} {1}".format(k, v))

        if current_ingress:
            logger.info("Revoking {0} ingress IP permissions"
                        .format(len(current_ingress)))
            self.obj.revoke_ingress(IpPermissions=current_ingress)

        # Remove existing egress (Outbound rules)
        current_egress = self.obj.ip_permissions_egress
        if current_egress:
            logger.info("Revoking {0} egress IP permissions"
                        .format(len(current_egress)))
            self.obj.revoke_egress(IpPermissions=current_egress)

    def authorize_permissions(self):
        # Process rules for each groups
        for new_ingress in self.permissions_ingress:
            self.obj.authorize_ingress(IpPermissions=[new_ingress])

        logger.info("Authorizing {0} ingress IP permissions"
                    .format(len(self.permissions_ingress)))

        for new_egress in self.permissions_egress:
            self.obj.authorize_egress(IpPermissions=[new_egress])

        logger.info("Authorizing {0} egress IP permissions"
                    .format(len(self.permissions_egress)))

        for perm_list in self.permissions_ingress:
            logger.debug("")
            for k, v in perm_list.iteritems():
                logger.debug("\t{0:<20} {1}".format(k, v))


class Instance(object):

    '''
    Details on creating an instance can be found

    http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.ServiceResource.create_instances

    Spot instances are requested instead of created

    http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.request_spot_instances

    After the instance has been created or modified we need to associate
    it with the groups defined

    See modify_attribute (Groups)

    http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Instance.modify_attribute

    '''

    def __init__(self, ec2, d):
        self.ec2 = ec2
        self.enabled = d.get('enabled', True)
        self.name = d['Name']
        self.image_id = d['ImageId']
        self.count = d['InstanceCount']
        self.key_name = d['KeyName']
        self.security_group_ids = SecurityGroup.get_group_ids(
            ec2, d['SecurityGroups'])

        self.instance_type = d['InstanceType']
        self.block_device_mappings = [d['BlockDeviceMappings']]
        self.subnet_id = d['SubnetId']
        self.instance_id = None

        # Extra tags that should be applied to the instance
        self.extra_tags = d.get('tags', [])

        logger.debug("Creating {0} {1}".format(
            self.__class__.__name__, self))

    def __str__(self):
        return str(self.__dict__)

    @staticmethod
    def build(ec2, d):
        if "SpotPrice" in d:
            return SpotInstance(ec2, d)
        else:
            return OnDemandInstance(ec2, d)

    @staticmethod
    def search_by_tag(ec2_obj, tag, value):
        '''
        Search for an instance using its tag. Usually you would search by Name
        '''
        logger.info("Searching for tag {0} value {1}".format(tag, value))

        for o in ec2_obj.filter(
                Filters=[{'Name': 'tag:' + tag, 'Values': [value]}]):
            return o

        return None

    def tag_instance(self):

        # Add Name to the global tag list
        instance_tags = global_tags()
        instance_tags.append(Tag('Name', self.name).tag_string)
        for tag_dict in self.extra_tags:
            instance_tags.append(
                Tag(tag_dict['name'], tag_dict['value']).tag_string)

        inst_obj = self.ec2.resource.Instance(self.instance_id)

        # Tag instances and associated volumes
        self.ec2.resource.create_tags(
            Resources=[self.instance_id],
            Tags=instance_tags,
        )

        devlst = []
        while not devlst:
            devlst = inst_obj.block_device_mappings
            if devlst:
                break

            logger.info("Waiting for {0} block devices..."
                        .format(self.name))
            time.sleep(1)
            inst_obj.reload()

        for dev in devlst:
            self.ec2.resource.create_tags(
                Resources=[dev['Ebs']['VolumeId']],
                Tags=instance_tags
            )


class OnDemandInstance(Instance):
    '''
    Request ec2 on demand instance
    '''

    def __init__(self, ec2, d):
        super(OnDemandInstance, self).__init__(ec2, d)

        if self.enabled:
            self.instance_id = self.create()
        else:
            logger.info("Skipping disabled instance {0}".format(self.name))

    def create(self):
        obj = self.search_by_tag(
            self.ec2.vpc.instances.all(), 'Name', self.name)

        if obj:
            logger.info("Found existing instance {0} id {1} ({2})"
                        .format(self.name, obj.id, obj.private_ip_address))
            return obj.id

        try:
            rc = self.ec2.resource.create_instances(
                ImageId=self.image_id,
                MinCount=self.count,
                MaxCount=self.count,
                KeyName=self.key_name,
                SecurityGroupIds=self.security_group_ids,
                InstanceType=self.instance_type,
                BlockDeviceMappings=self.block_device_mappings,
                SubnetId=self.subnet_id,
            )
        except ClientError:
            logger.error("Unable to create instance {0}".format(self.name))
            logger.error(sys.exc_info())
            sys.exit(1)

        return rc[0].id


class SpotInstance(Instance):
    '''
    Request ec2 spot instance
    '''

    def __init__(self, ec2, d):
        super(SpotInstance, self).__init__(ec2, d)
        self.price = d["SpotPrice"]
        self.availability_zone = d["AvailabilityZone"]
        self.req_id = None

        if self.enabled:
            self.instance_id = self.create()
        else:
            logger.info("Skipping disabled instance {0}".format(self.name))

    def create(self):

        obj = self.search_by_tag(
            self.ec2.vpc.instances.all(), 'Name', self.name)

        if obj:
            logger.info("Found existing instance {0} id {1} ({2})"
                        .format(self.name, obj.id, obj.private_ip_address))
            return obj.id

        try:
            req = self.ec2.client.request_spot_instances(
                SpotPrice=self.price,
                InstanceCount=self.count,
                LaunchSpecification={
                    'ImageId': self.image_id,
                    'KeyName': self.key_name,
                    'InstanceType': self.instance_type,
                    'Placement': {
                        'AvailabilityZone': self.availability_zone,
                    },
                    'BlockDeviceMappings': self.block_device_mappings,
                    'SubnetId': self.subnet_id,
                    'SecurityGroupIds': self.security_group_ids
                },
            )
        except ClientError:
            logger.error("Unable to create spot instance {0}".format(
                self.name))

            logger.error(sys.exc_info())
            sys.exit(1)

        self.req_id = req['SpotInstanceRequests'][0]['SpotInstanceRequestId']

        logger.info("Waiting for {0} spot request {1}..."
                    .format(self.name, self.req_id))

        waiter = self.ec2.client.get_waiter('spot_instance_request_fulfilled')
        waiter.wait(SpotInstanceRequestIds=[self.req_id])

        req = self.ec2.client.describe_spot_instance_requests(
            SpotInstanceRequestIds=[self.req_id])

        return req['SpotInstanceRequests'][0]['InstanceId']


def main():

    p = Parser()
    setup_logging(args.verbose)

    p.parse_yaml(args.definitions)

    ec2 = Ec2(args.profile)

    if args.add_security_groups:
        for definition in p.get_definition('security_groups'):
            group = SecurityGroup(ec2, definition)
            group.create()

    if args.add_instances:
        for definition in p.get_definition('instances'):
            inst = Instance.build(ec2, definition)
            inst.tag_instance()

if __name__ == '__main__':
    main()
    
#################################################
######
##
##
