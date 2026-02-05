# aws_ir_orchestrator.py
"""
AWS Incident Response Orchestrator 
Handles EC2 and S3 security incidents with automated triage, isolation,
and forensics preparation.. (testing)..
"""

import boto3
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field
from enum import Enum

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IncidentType(Enum):
    EC2_COMPROMISE = "ec2_compromise"
    S3_DATA_BREACH = "s3_data_breach"


class ActionStatus(Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class IncidentContext:
    incident_id: str
    incident_type: IncidentType
    resource_id: str
    severity: str  # critical, high, medium, low
    description: str
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'incident_type': self.incident_type.value,
            'detected_at': self.detected_at.isoformat()
        }


@dataclass
class ActionResult:
    action: str
    status: ActionStatus
    details: Dict[str, Any]
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict:
        return {
            'action': self.action,
            'status': self.status.value,
            'details': self.details,
            'error': self.error,
            'timestamp': self.timestamp.isoformat()
        }


class AWSIROrchestrator:
    """Orchestrates AWS incident response workflows"""
    
    SUSPICIOUS_EVENTS = {
        'RunInstances', 'CreateSecurityGroup',
        'AuthorizeSecurityGroupIngress', 'ModifyInstanceAttribute'
    }
    
    def __init__(
        self,
        region: str = 'us-east-1',
        forensics_bucket: str = 'forensics-bucket',
        dry_run: bool = False
    ):
        self.region = region
        self.forensics_bucket = forensics_bucket
        self.dry_run = dry_run
        self.actions_taken: List[ActionResult] = []
        
        # Initialize clients
        self.ec2 = boto3.client('ec2', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)
        self.iam = boto3.client('iam', region_name=region)
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        self.ssm = boto3.client('ssm', region_name=region)
        self.sts = boto3.client('sts', region_name=region)
        self.account_id = self.sts.get_caller_identity()['Account']
    
    def respond(
        self,
        context: IncidentContext,
        auto_isolate: bool = True,
        auto_snapshot: bool = True
    ) -> Dict:
        """Execute incident response workflow"""
        logger.info(f"Starting IR workflow: {context.incident_id}")
        
        try:
            if context.incident_type == IncidentType.EC2_COMPROMISE:
                return self._handle_ec2(context, auto_isolate, auto_snapshot)
            elif context.incident_type == IncidentType.S3_DATA_BREACH:
                return self._handle_s3(context)
            raise ValueError(f"Unknown incident type: {context.incident_type}")
        except Exception as e:
            logger.error(f"IR workflow failed: {e}", exc_info=True)
            raise
        finally:
            self._finalize_report(context)
    
    # ==================== EC2 Handlers ====================
    
    def _handle_ec2(
        self,
        ctx: IncidentContext,
        auto_isolate: bool,
        auto_snapshot: bool
    ) -> Dict:
        """EC2 incident response pipeline"""
        instance_id = ctx.resource_id
        
        triage = self._ec2_triage(instance_id, ctx)
        
        if auto_isolate and triage.get('requires_isolation'):
            self._ec2_isolate(instance_id, ctx)
        
        if auto_snapshot:
            self._ec2_snapshot(instance_id, ctx)
            self._ec2_memory_capture(instance_id, ctx)
        
        self._ec2_revoke_creds(instance_id, ctx)
        
        return self._build_report(ctx, triage)
    
    def _ec2_triage(self, instance_id: str, ctx: IncidentContext) -> Dict:
        """Assess EC2 instance state and threat level"""
        logger.info(f"Triaging {instance_id}")
        
        try:
            resp = self.ec2.describe_instances(InstanceIds=[instance_id])
            instance = resp['Reservations'][0]['Instances'][0]
            
            events = self.cloudtrail.lookup_events(
                LookupAttributes=[{
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': instance_id
                }],
                MaxResults=50
            )
            
            suspicious_count = sum(
                1 for e in events.get('Events', [])
                if e.get('EventName') in self.SUSPICIOUS_EVENTS
            )
            
            triage = {
                'instance_id': instance_id,
                'state': instance['State']['Name'],
                'vpc_id': instance.get('VpcId'),
                'public_ip': instance.get('PublicIpAddress'),
                'iam_role': instance.get('IamInstanceProfile', {}).get('Arn'),
                'security_groups': [sg['GroupId'] for sg in instance['SecurityGroups']],
                'suspicious_api_calls': suspicious_count,
                'requires_isolation': (
                    ctx.severity == 'critical' or
                    instance.get('PublicIpAddress') or
                    suspicious_count > 5
                )
            }
            
            self._record_action('triage', ActionStatus.COMPLETED, triage)
            return triage
            
        except Exception as e:
            self._record_action('triage', ActionStatus.FAILED, {}, str(e))
            raise
    
    def _ec2_isolate(self, instance_id: str, ctx: IncidentContext) -> None:
        """Isolate instance with forensic security group"""
        logger.info(f"Isolating {instance_id}")
        
        if self.dry_run:
            self._record_action('isolation', ActionStatus.SKIPPED, {'dry_run': True})
            return
        
        try:
            resp = self.ec2.describe_instances(InstanceIds=[instance_id])
            vpc_id = resp['Reservations'][0]['Instances'][0]['VpcId']
            
            sg = self.ec2.create_security_group(
                GroupName=f'ir-isolation-{ctx.incident_id}',
                Description=f'IR isolation {ctx.incident_id}',
                VpcId=vpc_id,
                TagSpecifications=[{
                    'ResourceType': 'security-group',
                    'Tags': [
                        {'Key': 'IncidentID', 'Value': ctx.incident_id},
                        {'Key': 'Purpose', 'Value': 'IncidentResponse'}
                    ]
                }]
            )
            
            self.ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[sg['GroupId']]
            )
            
            self.ec2.create_tags(
                Resources=[instance_id],
                Tags=[
                    {'Key': 'IncidentID', 'Value': ctx.incident_id},
                    {'Key': 'SecurityStatus', 'Value': 'Isolated'}
                ]
            )
            
            self._record_action('isolation', ActionStatus.COMPLETED, {
                'security_group_id': sg['GroupId'],
                'instance_id': instance_id
            })
            
        except Exception as e:
            self._record_action('isolation', ActionStatus.FAILED, {}, str(e))
            raise
    
    def _ec2_snapshot(self, instance_id: str, ctx: IncidentContext) -> None:
        """Create forensic snapshots of all volumes"""
        logger.info(f"Creating snapshots for {instance_id}")
        
        if self.dry_run:
            self._record_action('snapshot', ActionStatus.SKIPPED, {'dry_run': True})
            return
        
        try:
            volumes = self.ec2.describe_volumes(
                Filters=[{
                    'Name': 'attachment.instance-id',
                    'Values': [instance_id]
                }]
            )
            
            snapshots = []
            for vol in volumes['Volumes']:
                snap = self.ec2.create_snapshot(
                    VolumeId=vol['VolumeId'],
                    Description=f'IR snapshot {ctx.incident_id}',
                    TagSpecifications=[{
                        'ResourceType': 'snapshot',
                        'Tags': [
                            {'Key': 'IncidentID', 'Value': ctx.incident_id},
                            {'Key': 'SourceInstance', 'Value': instance_id},
                            {'Key': 'Purpose', 'Value': 'Forensics'}
                        ]
                    }]
                )
                snapshots.append({
                    'volume_id': vol['VolumeId'],
                    'snapshot_id': snap['SnapshotId']
                })
            
            self._record_action('snapshot', ActionStatus.COMPLETED, {
                'snapshots': snapshots,
                'count': len(snapshots)
            })
            
        except Exception as e:
            self._record_action('snapshot', ActionStatus.FAILED, {}, str(e))
            raise
    
    def _ec2_memory_capture(self, instance_id: str, ctx: IncidentContext) -> None:
        """Attempt memory capture via SSM"""
        logger.info(f"Attempting memory capture for {instance_id}")
        
        if self.dry_run:
            self._record_action('memory_capture', ActionStatus.SKIPPED, {'dry_run': True})
            return
        
        try:
            resp = self.ssm.describe_instance_information(
                Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
            )
            
            if not resp['InstanceInformationList']:
                self._record_action('memory_capture', ActionStatus.SKIPPED, {
                    'reason': 'ssm_not_available'
                })
                return
            
            cmd = self.ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName='AWS-RunShellScript',
                Parameters={
                    'commands': [
                        f'mkdir -p /tmp/ir-{ctx.incident_id}',
                        'sudo ps auxf > /tmp/ir-${INCIDENT_ID}/processes.txt',
                        'sudo netstat -anp > /tmp/ir-${INCIDENT_ID}/network.txt',
                        f'aws s3 sync /tmp/ir-{ctx.incident_id}/ '
                        f's3://{self.forensics_bucket}/{ctx.incident_id}/live-data/'
                    ]
                }
            )
            
            self._record_action('memory_capture', ActionStatus.COMPLETED, {
                'command_id': cmd['Command']['CommandId']
            })
            
        except Exception as e:
            self._record_action('memory_capture', ActionStatus.FAILED, {}, str(e))
    
    def _ec2_revoke_creds(self, instance_id: str, ctx: IncidentContext) -> None:
        """Revoke IAM credentials for instance"""
        logger.info(f"Revoking credentials for {instance_id}")
        
        if self.dry_run:
            self._record_action('revoke_creds', ActionStatus.SKIPPED, {'dry_run': True})
            return
        
        try:
            resp = self.ec2.describe_instances(InstanceIds=[instance_id])
            instance = resp['Reservations'][0]['Instances'][0]
            
            iam_profile = instance.get('IamInstanceProfile')
            if not iam_profile:
                self._record_action('revoke_creds', ActionStatus.SKIPPED, {
                    'reason': 'no_iam_profile'
                })
                return
            
            role_name = iam_profile['Arn'].split('/')[-1]
            
            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName=f'IR-DenyAll-{ctx.incident_id}',
                PolicyDocument=json.dumps({
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Deny',
                        'Action': '*',
                        'Resource': '*'
                    }]
                })
            )
            
            self._record_action('revoke_creds', ActionStatus.COMPLETED, {
                'role_name': role_name
            })
            
        except Exception as e:
            self._record_action('revoke_creds', ActionStatus.FAILED, {}, str(e))
    
    # ==================== S3 Handlers ====================
    
    def _handle_s3(self, ctx: IncidentContext) -> Dict:
        """S3 incident response pipeline"""
        bucket = ctx.resource_id
        
        triage = self._s3_triage(bucket, ctx)
        self._s3_enable_logging(bucket, ctx)
        self._s3_preserve(bucket, ctx)
        self._s3_contain(bucket, ctx)
        analysis = self._s3_analyze(bucket, ctx)
        
        return self._build_report(ctx, {**triage, **analysis})
    
    def _s3_triage(self, bucket: str, ctx: IncidentContext) -> Dict:
        """Assess S3 bucket security posture"""
        logger.info(f"Triaging S3 bucket {bucket}")
        
        try:
            location = self.s3.get_bucket_location(Bucket=bucket)
            
            try:
                public_block = self.s3.get_public_access_block(Bucket=bucket)
                public_cfg = public_block['PublicAccessBlockConfiguration']
            except:
                public_cfg = {'BlockPublicAcls': False}
            
            versioning = self.s3.get_bucket_versioning(Bucket=bucket)
            
            triage = {
                'bucket': bucket,
                'location': location.get('LocationConstraint', 'us-east-1'),
                'public_access_blocked': all(public_cfg.values()),
                'versioning_enabled': versioning.get('Status') == 'Enabled',
                'requires_containment': not all(public_cfg.values())
            }
            
            self._record_action('s3_triage', ActionStatus.COMPLETED, triage)
            return triage
            
        except Exception as e:
            self._record_action('s3_triage', ActionStatus.FAILED, {}, str(e))
            raise
    
    def _s3_enable_logging(self, bucket: str, ctx: IncidentContext) -> None:
        """Enable S3 access logging"""
        logger.info(f"Enabling logging for {bucket}")
        
        if self.dry_run:
            self._record_action('s3_logging', ActionStatus.SKIPPED, {'dry_run': True})
            return
        
        try:
            self.s3.put_bucket_logging(
                Bucket=bucket,
                BucketLoggingStatus={
                    'LoggingEnabled': {
                        'TargetBucket': self.forensics_bucket,
                        'TargetPrefix': f's3-logs/{bucket}/'
                    }
                }
            )
            
            self._record_action('s3_logging', ActionStatus.COMPLETED, {
                'target': self.forensics_bucket
            })
            
        except Exception as e:
            self._record_action('s3_logging', ActionStatus.FAILED, {}, str(e))
    
    def _s3_preserve(self, bucket: str, ctx: IncidentContext) -> None:
        """Preserve bucket state for forensics"""
        logger.info(f"Preserving state for {bucket}")
        
        if self.dry_run:
            self._record_action('s3_preserve', ActionStatus.SKIPPED, {'dry_run': True})
            return
        
        try:
            self.s3.put_bucket_versioning(
                Bucket=bucket,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            inventory_id = f'ir-{ctx.incident_id}'
            self.s3.put_bucket_inventory_configuration(
                Bucket=bucket,
                Id=inventory_id,
                InventoryConfiguration={
                    'Destination': {
                        'S3BucketDestination': {
                            'Bucket': f'arn:aws:s3:::{self.forensics_bucket}',
                            'Format': 'CSV',
                            'Prefix': f'inventory/{ctx.incident_id}/'
                        }
                    },
                    'IsEnabled': True,
                    'Id': inventory_id,
                    'IncludedObjectVersions': 'All',
                    'Schedule': {'Frequency': 'Daily'}
                }
            )
            
            self._record_action('s3_preserve', ActionStatus.COMPLETED, {
                'inventory_id': inventory_id
            })
            
        except Exception as e:
            self._record_action('s3_preserve', ActionStatus.FAILED, {}, str(e))
    
    def _s3_contain(self, bucket: str, ctx: IncidentContext) -> None:
        """Lock down S3 bucket access"""
        logger.info(f"Containing {bucket}")
        
        if self.dry_run:
            self._record_action('s3_contain', ActionStatus.SKIPPED, {'dry_run': True})
            return
        
        try:
            self.s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            forensics_role = f'arn:aws:iam::{self.account_id}:role/ForensicsRole'
            
            policy = {
                'Version': '2012-10-17',
                'Statement': [{
                    'Sid': f'IRContainment{ctx.incident_id}',
                    'Effect': 'Deny',
                    'Principal': '*',
                    'Action': 's3:*',
                    'Resource': [
                        f'arn:aws:s3:::{bucket}',
                        f'arn:aws:s3:::{bucket}/*'
                    ],
                    'Condition': {
                        'StringNotEquals': {
                            'aws:PrincipalArn': forensics_role
                        }
                    }
                }]
            }
            
            self.s3.put_bucket_policy(
                Bucket=bucket,
                Policy=json.dumps(policy)
            )
            
            self._record_action('s3_contain', ActionStatus.COMPLETED, {
                'public_blocked': True,
                'policy_applied': True
            })
            
        except Exception as e:
            self._record_action('s3_contain', ActionStatus.FAILED, {}, str(e))
    
    def _s3_analyze(self, bucket: str, ctx: IncidentContext) -> Dict:
        """Analyze S3 access patterns"""
        logger.info(f"Analyzing {bucket}")
        
        try:
            events = self.cloudtrail.lookup_events(
                LookupAttributes=[{
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': bucket
                }],
                MaxResults=100
            )
            
            event_list = events.get('Events', [])
            reads = sum(1 for e in event_list if e.get('EventName') in ['GetObject', 'ListObjects'])
            writes = sum(1 for e in event_list if e.get('EventName') in ['PutObject', 'CopyObject'])
            deletes = sum(1 for e in event_list if 'Delete' in e.get('EventName', ''))
            
            unique_ips = {
                e.get('SourceIPAddress')
                for e in event_list
                if e.get('SourceIPAddress') and not e['SourceIPAddress'].startswith('AWS')
            }
            
            analysis = {
                'total_events': len(event_list),
                'read_count': reads,
                'write_count': writes,
                'delete_count': deletes,
                'unique_ips': len(unique_ips),
                'suspicious_ips': list(unique_ips)[:10]
            }
            
            self._record_action('s3_analyze', ActionStatus.COMPLETED, analysis)
            return analysis
            
        except Exception as e:
            self._record_action('s3_analyze', ActionStatus.FAILED, {}, str(e))
            return {}
    
    # ==================== Utilities ====================
    
    def _record_action(
        self,
        action: str,
        status: ActionStatus,
        details: Dict,
        error: Optional[str] = None
    ) -> None:
        """Record action result"""
        self.actions_taken.append(
            ActionResult(action, status, details, error)
        )
    
    def _build_report(self, ctx: IncidentContext, triage: Dict) -> Dict:
        """Compile incident report"""
        return {
            'incident': ctx.to_dict(),
            'triage': triage,
            'actions': [a.to_dict() for a in self.actions_taken],
            'next_steps': self._get_next_steps(ctx),
            'forensics_location': f's3://{self.forensics_bucket}/{ctx.incident_id}/'
        }
    
    def _get_next_steps(self, ctx: IncidentContext) -> List[str]:
        """Generate recommended next steps"""
        if ctx.incident_type == IncidentType.EC2_COMPROMISE:
            return [
                "Analyze forensic snapshots for malware",
                "Review CloudTrail for lateral movement",
                "Audit IAM policies for over-permissions",
                "Launch clean replacement from trusted AMI",
                "Update security groups with least privilege"
            ]
        return [
            "Review S3 access logs for exfiltration",
            "Check GuardDuty for additional findings",
            "Audit all bucket policies and ACLs",
            "Enable MFA Delete on critical buckets",
            "Review VPC endpoint configurations"
        ]
    
    def _finalize_report(self, ctx: IncidentContext) -> None:
        """Save final report to S3"""
        try:
            report = self._build_report(ctx, {})
            key = f'incident-reports/{ctx.incident_id}/report.json'
            
            self.s3.put_object(
                Bucket=self.forensics_bucket,
                Key=key,
                Body=json.dumps(report, indent=2),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            
            logger.info(f"Report saved: s3://{self.forensics_bucket}/{key}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='AWS Incident Response Orchestrator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # EC2 compromise (dry-run)
  python aws_ir_orchestrator.py ec2 i-0123456789abcdef0 \
    --severity critical \
    --description "Cryptominer detected" \
    --dry-run

  # S3 data breach (live)
  python aws_ir_orchestrator.py s3 my-bucket \
    --severity high \
    --description "Unauthorized access" \
    --region us-west-2

  # EC2 without auto-isolation
  python aws_ir_orchestrator.py ec2 i-0123456789abcdef0 \
    --severity medium \
    --description "Suspicious activity" \
    --no-isolate
        """
    )
    
    parser.add_argument('type', choices=['ec2', 's3'],
                       help='Incident type')
    parser.add_argument('resource', help='Resource ID (instance-id or bucket name)')
    parser.add_argument('--severity', default='high',
                       choices=['low', 'medium', 'high', 'critical'])
    parser.add_argument('--description', required=True,
                       help='Incident description')
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--forensics-bucket', default='forensics-bucket')
    parser.add_argument('--dry-run', action='store_true',
                       help='Simulate without making changes')
    parser.add_argument('--no-isolate', action='store_true',
                       help='Skip automatic isolation')
    parser.add_argument('--no-snapshot', action='store_true',
                       help='Skip automatic snapshots')
    
    args = parser.parse_args()
    
    # Generate incident ID
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    # Create context
    incident_type = (
        IncidentType.EC2_COMPROMISE if args.type == 'ec2'
        else IncidentType.S3_DATA_BREACH
    )
    
    context = IncidentContext(
        incident_id=incident_id,
        incident_type=incident_type,
        resource_id=args.resource,
        severity=args.severity,
        description=args.description
    )
    
    # Execute
    orchestrator = AWSIROrchestrator(
        region=args.region,
        forensics_bucket=args.forensics_bucket,
        dry_run=args.dry_run
    )
    
    result = orchestrator.respond(
        context,
        auto_isolate=not args.no_isolate,
        auto_snapshot=not args.no_snapshot
    )
    
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
