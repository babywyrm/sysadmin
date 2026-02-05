# ir_orchestrator.py
import boto3
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IncidentType(Enum):
    EC2_COMPROMISE = "ec2_compromise"
    S3_DATA_BREACH = "s3_data_breach"
    CREDENTIAL_EXPOSURE = "credential_exposure"


class ActionStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class IncidentContext:
    incident_id: str
    incident_type: IncidentType
    resource_id: str
    detected_at: datetime
    severity: str  # critical, high, medium, low
    description: str
    tags: Dict[str, str]
    
    def to_dict(self):
        data = asdict(self)
        data['incident_type'] = self.incident_type.value
        data['detected_at'] = self.detected_at.isoformat()
        return data


@dataclass
class ActionResult:
    action: str
    status: ActionStatus
    details: Dict
    error: Optional[str] = None
    
    def to_dict(self):
        data = asdict(self)
        data['status'] = self.status.value
        return data


class AWSIROrchestrator:
    def __init__(
        self,
        region: str = 'us-east-1',
        forensics_bucket: str = 'forensics-bucket',
        dry_run: bool = False
    ):
        self.region = region
        self.forensics_bucket = forensics_bucket
        self.dry_run = dry_run
        
        # AWS clients
        self.ec2 = boto3.client('ec2', region_name=region)
        self.s3 = boto3.client('s3', region_name=region)
        self.iam = boto3.client('iam', region_name=region)
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        self.ssm = boto3.client('ssm', region_name=region)
        self.sns = boto3.client('sns', region_name=region)
        
        self.actions_taken: List[ActionResult] = []
    
    def respond_to_incident(
        self,
        context: IncidentContext,
        auto_isolate: bool = True,
        auto_snapshot: bool = True
    ) -> Dict:
        """Main orchestration entry point"""
        logger.info(f"Starting IR for {context.incident_id}")
        
        try:
            if context.incident_type == IncidentType.EC2_COMPROMISE:
                return self._handle_ec2_incident(
                    context, auto_isolate, auto_snapshot
                )
            elif context.incident_type == IncidentType.S3_DATA_BREACH:
                return self._handle_s3_incident(context)
            else:
                raise ValueError(f"Unknown incident type: {context.incident_type}")
                
        except Exception as e:
            logger.error(f"IR orchestration failed: {e}")
            self._send_notification(context, f"FAILED: {str(e)}")
            raise
    
    def _handle_ec2_incident(
        self,
        context: IncidentContext,
        auto_isolate: bool,
        auto_snapshot: bool
    ) -> Dict:
        """EC2 incident response workflow"""
        instance_id = context.resource_id
        
        # Phase 1: Triage & Documentation
        triage = self._ec2_triage(instance_id, context)
        
        # Phase 2: Isolation
        if auto_isolate and triage['requires_isolation']:
            isolation = self._ec2_isolate(instance_id, context)
        else:
            isolation = ActionResult(
                "isolation", ActionStatus.SKIPPED, {}
            )
        
        # Phase 3: Preservation
        if auto_snapshot:
            snapshots = self._ec2_snapshot_volumes(instance_id, context)
            memory = self._ec2_capture_memory(instance_id, context)
        else:
            snapshots = ActionResult("snapshot", ActionStatus.SKIPPED, {})
            memory = ActionResult("memory", ActionStatus.SKIPPED, {})
        
        # Phase 4: Forensics prep
        forensics = self._ec2_prepare_forensics(instance_id, context)
        
        # Phase 5: Credential containment
        credentials = self._ec2_revoke_credentials(instance_id, context)
        
        # Compile report
        report = {
            'incident': context.to_dict(),
            'actions': [a.to_dict() for a in self.actions_taken],
            'triage': triage,
            'next_steps': self._generate_next_steps(context)
        }
        
        # Save to S3
        self._save_incident_report(context.incident_id, report)
        
        # Notify team
        self._send_notification(context, "EC2 IR workflow completed")
        
        return report
    
    def _ec2_triage(
        self, instance_id: str, context: IncidentContext
    ) -> Dict:
        """Initial EC2 triage and assessment"""
        logger.info(f"Triaging EC2 instance {instance_id}")
        
        try:
            # Get instance details
            response = self.ec2.describe_instances(
                InstanceIds=[instance_id]
            )
            instance = response['Reservations'][0]['Instances'][0]
            
            # Check CloudTrail recent activity
            ct_events = self.cloudtrail.lookup_events(
                LookupAttributes=[{
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': instance_id
                }],
                MaxResults=50
            )
            
            # Assess severity factors
            triage_data = {
                'instance_id': instance_id,
                'state': instance['State']['Name'],
                'vpc_id': instance.get('VpcId'),
                'subnet_id': instance.get('SubnetId'),
                'security_groups': [
                    sg['GroupId'] for sg in instance['SecurityGroups']
                ],
                'iam_role': instance.get('IamInstanceProfile', {}).get('Arn'),
                'public_ip': instance.get('PublicIpAddress'),
                'recent_api_calls': len(ct_events['Events']),
                'requires_isolation': self._assess_isolation_needed(
                    instance, ct_events, context
                ),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            self.actions_taken.append(ActionResult(
                'triage', ActionStatus.COMPLETED, triage_data
            ))
            
            return triage_data
            
        except Exception as e:
            logger.error(f"Triage failed: {e}")
            self.actions_taken.append(ActionResult(
                'triage', ActionStatus.FAILED, {}, str(e)
            ))
            raise
    
    def _assess_isolation_needed(
        self, instance: Dict, events: Dict, context: IncidentContext
    ) -> bool:
        """Determine if immediate isolation is required"""
        # Isolate if:
        # - Severity is critical
        # - Instance has public IP
        # - Suspicious API activity detected
        # - Active malware detected
        
        if context.severity == 'critical':
            return True
        
        if instance.get('PublicIpAddress'):
            return True
        
        suspicious_events = [
            e for e in events.get('Events', [])
            if e.get('EventName') in [
                'RunInstances', 'CreateSecurityGroup',
                'AuthorizeSecurityGroupIngress'
            ]
        ]
        
        return len(suspicious_events) > 5
    
    def _ec2_isolate(
        self, instance_id: str, context: IncidentContext
    ) -> ActionResult:
        """Isolate EC2 instance with forensic security group"""
        logger.info(f"Isolating instance {instance_id}")
        
        if self.dry_run:
            return ActionResult(
                'isolation', ActionStatus.SKIPPED,
                {'reason': 'dry_run_mode'}
            )
        
        try:
            # Get instance VPC
            response = self.ec2.describe_instances(
                InstanceIds=[instance_id]
            )
            vpc_id = response['Reservations'][0]['Instances'][0]['VpcId']
            
            # Create forensic isolation security group
            sg_name = f'ir-isolation-{context.incident_id}'
            sg_response = self.ec2.create_security_group(
                GroupName=sg_name,
                Description=f'IR isolation for {context.incident_id}',
                VpcId=vpc_id,
                TagSpecifications=[{
                    'ResourceType': 'security-group',
                    'Tags': [
                        {'Key': 'IncidentID', 'Value': context.incident_id},
                        {'Key': 'Purpose', 'Value': 'IncidentResponse'}
                    ]
                }]
            )
            
            sg_id = sg_response['GroupId']
            
            # Apply to instance (removes all other SGs)
            self.ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[sg_id]
            )
            
            # Tag instance
            self.ec2.create_tags(
                Resources=[instance_id],
                Tags=[
                    {'Key': 'IncidentID', 'Value': context.incident_id},
                    {'Key': 'SecurityStatus', 'Value': 'Isolated'},
                    {'Key': 'IsolatedAt',
                     'Value': datetime.now(timezone.utc).isoformat()}
                ]
            )
            
            result = ActionResult(
                'isolation',
                ActionStatus.COMPLETED,
                {
                    'security_group_id': sg_id,
                    'instance_id': instance_id,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            
            self.actions_taken.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Isolation failed: {e}")
            result = ActionResult(
                'isolation', ActionStatus.FAILED, {}, str(e)
            )
            self.actions_taken.append(result)
            raise
    
    def _ec2_snapshot_volumes(
        self, instance_id: str, context: IncidentContext
    ) -> ActionResult:
        """Create forensic snapshots of all volumes"""
        logger.info(f"Snapshotting volumes for {instance_id}")
        
        if self.dry_run:
            return ActionResult(
                'snapshot', ActionStatus.SKIPPED,
                {'reason': 'dry_run_mode'}
            )
        
        try:
            # Get all volumes attached to instance
            volumes = self.ec2.describe_volumes(
                Filters=[{
                    'Name': 'attachment.instance-id',
                    'Values': [instance_id]
                }]
            )
            
            snapshot_ids = []
            for volume in volumes['Volumes']:
                vol_id = volume['VolumeId']
                
                snapshot = self.ec2.create_snapshot(
                    VolumeId=vol_id,
                    Description=f'IR snapshot for {context.incident_id}',
                    TagSpecifications=[{
                        'ResourceType': 'snapshot',
                        'Tags': [
                            {'Key': 'IncidentID',
                             'Value': context.incident_id},
                            {'Key': 'SourceInstance',
                             'Value': instance_id},
                            {'Key': 'SourceVolume', 'Value': vol_id},
                            {'Key': 'Purpose', 'Value': 'Forensics'}
                        ]
                    }]
                )
                
                snapshot_ids.append({
                    'volume_id': vol_id,
                    'snapshot_id': snapshot['SnapshotId']
                })
            
            result = ActionResult(
                'snapshot',
                ActionStatus.COMPLETED,
                {
                    'snapshots': snapshot_ids,
                    'count': len(snapshot_ids),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            
            self.actions_taken.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Snapshot failed: {e}")
            result = ActionResult('snapshot', ActionStatus.FAILED, {}, str(e))
            self.actions_taken.append(result)
            raise
    
    def _ec2_capture_memory(
        self, instance_id: str, context: IncidentContext
    ) -> ActionResult:
        """Attempt memory capture via SSM"""
        logger.info(f"Attempting memory capture for {instance_id}")
        
        if self.dry_run:
            return ActionResult(
                'memory_capture', ActionStatus.SKIPPED,
                {'reason': 'dry_run_mode'}
            )
        
        try:
            # Check if SSM agent is online
            response = self.ssm.describe_instance_information(
                Filters=[{
                    'Key': 'InstanceIds',
                    'Values': [instance_id]
                }]
            )
            
            if not response['InstanceInformationList']:
                logger.warning(f"SSM not available on {instance_id}")
                return ActionResult(
                    'memory_capture',
                    ActionStatus.SKIPPED,
                    {'reason': 'ssm_not_available'}
                )
            
            # Send memory capture command (requires LiME or similar)
            command = self.ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName='AWS-RunShellScript',
                Parameters={
                    'commands': [
                        f'sudo mkdir -p /tmp/ir-{context.incident_id}',
                        f'# Memory capture would go here',
                        f'# Requires LiME kernel module or similar',
                        f'echo "Memory capture initiated" > '
                        f'/tmp/ir-{context.incident_id}/capture.log'
                    ]
                },
                Comment=f'IR memory capture {context.incident_id}'
            )
            
            result = ActionResult(
                'memory_capture',
                ActionStatus.IN_PROGRESS,
                {
                    'command_id': command['Command']['CommandId'],
                    'note': 'Manual verification required'
                }
            )
            
            self.actions_taken.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Memory capture failed: {e}")
            result = ActionResult(
                'memory_capture', ActionStatus.FAILED, {}, str(e)
            )
            self.actions_taken.append(result)
            return result
    
    def _ec2_prepare_forensics(
        self, instance_id: str, context: IncidentContext
    ) -> ActionResult:
        """Prepare forensic analysis environment"""
        logger.info(f"Preparing forensics for {instance_id}")
        
        # In production, this would:
        # 1. Launch forensic workstation
        # 2. Attach snapshot volumes
        # 3. Configure analysis tools
        
        forensics_data = {
            'incident_id': context.incident_id,
            'instance_id': instance_id,
            'analysis_checklist': [
                'Review /var/log/* logs',
                'Check ~/.bash_history',
                'Inspect /etc/crontab and /var/spool/cron/',
                'Scan /tmp and /var/tmp',
                'Review network connections',
                'Hash suspicious binaries',
                'Review CloudTrail IAM role usage'
            ],
            'forensics_bucket': self.forensics_bucket,
            'evidence_path': f's3://{self.forensics_bucket}/{context.incident_id}/'
        }
        
        result = ActionResult(
            'forensics_prep',
            ActionStatus.COMPLETED,
            forensics_data
        )
        
        self.actions_taken.append(result)
        return result
    
    def _ec2_revoke_credentials(
        self, instance_id: str, context: IncidentContext
    ) -> ActionResult:
        """Revoke IAM credentials associated with instance"""
        logger.info(f"Revoking credentials for {instance_id}")
        
        if self.dry_run:
            return ActionResult(
                'revoke_credentials', ActionStatus.SKIPPED,
                {'reason': 'dry_run_mode'}
            )
        
        try:
            # Get instance profile
            response = self.ec2.describe_instances(
                InstanceIds=[instance_id]
            )
            instance = response['Reservations'][0]['Instances'][0]
            
            iam_profile = instance.get('IamInstanceProfile')
            if not iam_profile:
                return ActionResult(
                    'revoke_credentials',
                    ActionStatus.SKIPPED,
                    {'reason': 'no_iam_profile'}
                )
            
            # Extract role name from ARN
            role_arn = iam_profile['Arn']
            role_name = role_arn.split('/')[-1]
            
            # Apply deny-all inline policy
            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName=f'IR-DenyAll-{context.incident_id}',
                PolicyDocument=json.dumps({
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Deny',
                        'Action': '*',
                        'Resource': '*',
                        'Condition': {
                            'DateGreaterThan': {
                                'aws:CurrentTime':
                                    datetime.now(timezone.utc).isoformat()
                            }
                        }
                    }]
                })
            )
            
            result = ActionResult(
                'revoke_credentials',
                ActionStatus.COMPLETED,
                {
                    'role_name': role_name,
                    'policy_applied': f'IR-DenyAll-{context.incident_id}'
                }
            )
            
            self.actions_taken.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Credential revocation failed: {e}")
            result = ActionResult(
                'revoke_credentials', ActionStatus.FAILED, {}, str(e)
            )
            self.actions_taken.append(result)
            return result
    
    def _handle_s3_incident(
        self, context: IncidentContext
    ) -> Dict:
        """S3 incident response workflow"""
        bucket_name = context.resource_id
        
        # Phase 1: Triage
        triage = self._s3_triage(bucket_name, context)
        
        # Phase 2: Enable logging
        logging_result = self._s3_enable_logging(bucket_name, context)
        
        # Phase 3: Preservation
        preservation = self._s3_preserve_state(bucket_name, context)
        
        # Phase 4: Containment
        containment = self._s3_contain(bucket_name, context)
        
        # Phase 5: Analysis
        analysis = self._s3_analyze_access(bucket_name, context)
        
        # Compile report
        report = {
            'incident': context.to_dict(),
            'actions': [a.to_dict() for a in self.actions_taken],
            'triage': triage,
            'next_steps': self._generate_next_steps(context)
        }
        
        self._save_incident_report(context.incident_id, report)
        self._send_notification(context, "S3 IR workflow completed")
        
        return report
    
    def _s3_triage(
        self, bucket_name: str, context: IncidentContext
    ) -> Dict:
        """Initial S3 triage"""
        logger.info(f"Triaging S3 bucket {bucket_name}")
        
        try:
            # Get bucket details
            location = self.s3.get_bucket_location(Bucket=bucket_name)
            
            # Check public access
            try:
                public_block = self.s3.get_public_access_block(
                    Bucket=bucket_name
                )
                public_config = public_block['PublicAccessBlockConfiguration']
            except:
                public_config = {'all_false': True}
            
            # Check bucket policy
            try:
                policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                has_policy = True
            except:
                has_policy = False
            
            # Check versioning
            versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
            
            # Check recent objects
            objects = self.s3.list_objects_v2(
                Bucket=bucket_name,
                MaxKeys=100
            )
            
            triage_data = {
                'bucket_name': bucket_name,
                'location': location.get('LocationConstraint', 'us-east-1'),
                'public_access_block': public_config,
                'has_bucket_policy': has_policy,
                'versioning_enabled': versioning.get('Status') == 'Enabled',
                'object_count_sample': objects.get('KeyCount', 0),
                'requires_containment': not all(public_config.values()),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            self.actions_taken.append(ActionResult(
                's3_triage', ActionStatus.COMPLETED, triage_data
            ))
            
            return triage_data
            
        except Exception as e:
            logger.error(f"S3 triage failed: {e}")
            self.actions_taken.append(ActionResult(
                's3_triage', ActionStatus.FAILED, {}, str(e)
            ))
            raise
    
    def _s3_enable_logging(
        self, bucket_name: str, context: IncidentContext
    ) -> ActionResult:
        """Enable S3 server access logging"""
        logger.info(f"Enabling logging for {bucket_name}")
        
        if self.dry_run:
            return ActionResult(
                's3_logging', ActionStatus.SKIPPED,
                {'reason': 'dry_run_mode'}
            )
        
        try:
            self.s3.put_bucket_logging(
                Bucket=bucket_name,
                BucketLoggingStatus={
                    'LoggingEnabled': {
                        'TargetBucket': self.forensics_bucket,
                        'TargetPrefix': f's3-logs/{bucket_name}/'
                    }
                }
            )
            
            result = ActionResult(
                's3_logging',
                ActionStatus.COMPLETED,
                {'target_bucket': self.forensics_bucket}
            )
            
            self.actions_taken.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Enable logging failed: {e}")
            result = ActionResult('s3_logging', ActionStatus.FAILED, {}, str(e))
            self.actions_taken.append(result)
            return result
    
    def _s3_preserve_state(
        self, bucket_name: str, context: IncidentContext
    ) -> ActionResult:
        """Preserve bucket state for forensics"""
        logger.info(f"Preserving state for {bucket_name}")
        
        if self.dry_run:
            return ActionResult(
                's3_preservation', ActionStatus.SKIPPED,
                {'reason': 'dry_run_mode'}
            )
        
        try:
            # Enable versioning if not already
            self.s3.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            # Create inventory configuration
            inventory_id = f'ir-{context.incident_id}'
            self.s3.put_bucket_inventory_configuration(
                Bucket=bucket_name,
                Id=inventory_id,
                InventoryConfiguration={
                    'Destination': {
                        'S3BucketDestination': {
                            'Bucket': f'arn:aws:s3:::{self.forensics_bucket}',
                            'Format': 'CSV',
                            'Prefix': f'inventory/{context.incident_id}/'
                        }
                    },
                    'IsEnabled': True,
                    'Id': inventory_id,
                    'IncludedObjectVersions': 'All',
                    'Schedule': {'Frequency': 'Daily'}
                }
            )
            
            result = ActionResult(
                's3_preservation',
                ActionStatus.COMPLETED,
                {
                    'versioning_enabled': True,
                    'inventory_id': inventory_id
                }
            )
            
            self.actions_taken.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Preservation failed: {e}")
            result = ActionResult(
                's3_preservation', ActionStatus.FAILED, {}, str(e)
            )
            self.actions_taken.append(result)
            return result
    
    def _s3_contain(
        self, bucket_name: str, context: IncidentContext
    ) -> ActionResult:
        """Contain S3 bucket access"""
        logger.info(f"Containing access to {bucket_name}")
        
        if self.dry_run:
            return ActionResult(
                's3_containment', ActionStatus.SKIPPED,
                {'reason': 'dry_run_mode'}
            )
        
        try:
            # Block all public access
            self.s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            # Apply restrictive bucket policy
            # (allow only forensics role)
            forensics_role_arn = f'arn:aws:iam::{self._get_account_id()}:role/ForensicsRole'
            
            policy = {
                'Version': '2012-10-17',
                'Statement': [{
                    'Sid': f'IRContainment{context.incident_id}',
                    'Effect': 'Deny',
                    'Principal': '*',
                    'Action': 's3:*',
                    'Resource': [
                        f'arn:aws:s3:::{bucket_name}',
                        f'arn:aws:s3:::{bucket_name}/*'
                    ],
                    'Condition': {
                        'StringNotEquals': {
                            'aws:PrincipalArn': forensics_role_arn
                        }
                    }
                }]
            }
            
            self.s3.put_bucket_policy(
                Bucket=bucket_name,
                Policy=json.dumps(policy)
            )
            
            result = ActionResult(
                's3_containment',
                ActionStatus.COMPLETED,
                {
                    'public_access_blocked': True,
                    'restrictive_policy_applied': True
                }
            )
            
            self.actions_taken.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Containment failed: {e}")
            result = ActionResult(
                's3_containment', ActionStatus.FAILED, {}, str(e)
            )
            self.actions_taken.append(result)
            return result
    
    def _s3_analyze_access(
        self, bucket_name: str, context: IncidentContext
    ) -> ActionResult:
        """Analyze S3 access patterns"""
        logger.info(f"Analyzing access for {bucket_name}")
        
        try:
            # Query CloudTrail for recent S3 access
            events = self.cloudtrail.lookup_events(
                LookupAttributes=[{
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': bucket_name
                }],
                MaxResults=100
            )
            
            # Categorize events
            read_events = []
            write_events = []
            delete_events = []
            
            for event in events.get('Events', []):
                event_name = event.get('EventName')
                if event_name in ['GetObject', 'ListObjects']:
                    read_events.append(event)
                elif event_name in ['PutObject', 'CopyObject']:
                    write_events.append(event)
                elif event_name in ['DeleteObject', 'DeleteObjects']:
                    delete_events.append(event)
            
            analysis = {
                'total_events': len(events.get('Events', [])),
                'read_events': len(read_events),
                'write_events': len(write_events),
                'delete_events': len(delete_events),
                'unique_principals': len(set(
                    e.get('Username') for e in events.get('Events', [])
                )),
                'suspicious_ips': self._extract_suspicious_ips(events)
            }
            
            result = ActionResult(
                's3_analysis',
                ActionStatus.COMPLETED,
                analysis
            )
            
            self.actions_taken.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            result = ActionResult('s3_analysis', ActionStatus.FAILED, {}, str(e))
            self.actions_taken.append(result)
            return result
    
    def _extract_suspicious_ips(self, events: Dict) -> List[str]:
        """Extract potentially suspicious IPs from CloudTrail events"""
        # Simplified - in production, cross-reference with threat intel
        ips = set()
        for event in events.get('Events', []):
            source_ip = event.get('SourceIPAddress', '')
            if source_ip and not source_ip.startswith('AWS'):
                ips.add(source_ip)
        return list(ips)
    
    def _get_account_id(self) -> str:
        """Get current AWS account ID"""
        return boto3.client('sts').get_caller_identity()['Account']
    
    def _generate_next_steps(self, context: IncidentContext) -> List[str]:
        """Generate recommended next steps"""
        if context.incident_type == IncidentType.EC2_COMPROMISE:
            return [
                "Review forensic snapshots for malware/backdoors",
                "Analyze CloudTrail for credential abuse",
                "Check for lateral movement to other instances",
                "Review IAM policies for over-permissive access",
                "Launch clean replacement from trusted AMI",
                "Update security groups with least privilege",
                "Enable GuardDuty if not already active"
            ]
        elif context.incident_type == IncidentType.S3_DATA_BREACH:
            return [
                "Review S3 access logs for data exfiltration",
                "Check GuardDuty for Exfiltration findings",
                "Audit bucket policies and ACLs",
                "Review IAM user/role access patterns",
                "Enable MFA Delete on versioned buckets",
                "Implement S3 Object Lock if needed",
                "Review and restrict VPC endpoints"
            ]
        return []
    
    def _save_incident_report(self, incident_id: str, report: Dict):
        """Save incident report to S3"""
        try:
            key = f'incident-reports/{incident_id}/report.json'
            self.s3.put_object(
                Bucket=self.forensics_bucket,
                Key=key,
                Body=json.dumps(report, indent=2),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            logger.info(f"Report saved to s3://{self.forensics_bucket}/{key}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
    
    def _send_notification(self, context: IncidentContext, message: str):
        """Send SNS notification"""
        try:
            # In production, configure SNS topic ARN
            logger.info(f"Notification: {message}")
            # self.sns.publish(
            #     TopicArn='arn:aws:sns:region:account:ir-notifications',
            #     Subject=f'IR Update: {context.incident_id}',
            #     Message=message
            # )
        except Exception as e:
            logger.error(f"Notification failed: {e}")


# CLI usage
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='AWS IR Orchestrator')
    parser.add_argument('--incident-type', required=True,
                       choices=['ec2', 's3'])
    parser.add_argument('--resource-id', required=True)
    parser.add_argument('--severity', default='high',
                       choices=['low', 'medium', 'high', 'critical'])
    parser.add_argument('--description', required=True)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--no-auto-isolate', action='store_true')
    parser.add_argument('--region', default='us-east-1')
    
    args = parser.parse_args()
    
    # Generate incident ID
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    # Map incident type
    incident_type_map = {
        'ec2': IncidentType.EC2_COMPROMISE,
        's3': IncidentType.S3_DATA_BREACH
    }
    
    # Create context
    context = IncidentContext(
        incident_id=incident_id,
        incident_type=incident_type_map[args.incident_type],
        resource_id=args.resource_id,
        detected_at=datetime.now(timezone.utc),
        severity=args.severity,
        description=args.description,
        tags={}
    )
    
    # Execute IR workflow
    orchestrator = AWSIROrchestrator(
        region=args.region,
        dry_run=args.dry_run
    )
    
    result = orchestrator.respond_to_incident(
        context,
        auto_isolate=not args.no_auto_isolate
    )
    
    print(json.dumps(result, indent=2))
