"""
models.py


Peewee ORM models for tracking CVEs across EKS microservices.
Uses SQLite JSONField for arbitrary scanner payloads.
"""
from datetime import datetime
import enum

from peewee import (
    Model,
    CharField,
    TextField,
    DateTimeField,
    ForeignKeyField,
    IntegerField,
    BooleanField,
    FloatField,
    CompositeKey,
    Check,
)
from playhouse.sqlite_ext import SqliteExtDatabase, JSONField

# Use SQLite with JSON extension enabled
db = SqliteExtDatabase(
    'cve_tracking.db',
    pragmas={'journal_mode': 'wal', 'foreign_keys': 1},
)

# --- Enumerations for fixed-choice fields ---
class SeverityLevel(enum.Enum):
    LOW = 'Low'
    MEDIUM = 'Medium'
    HIGH = 'High'
    CRITICAL = 'Critical'

class RemediationStatus(enum.Enum):
    OPEN = 'Open'
    IN_PROGRESS = 'In Progress'
    FIXED = 'Fixed'
    WONT_FIX = "Won't Fix"

class DeploymentKind(enum.Enum):
    DEPLOYMENT = "Deployment"
    STATEFULSET = "StatefulSet"
    DAEMONSET = "DaemonSet"

class AWSRegion(enum.Enum):
    US_EAST_1 = "us-east-1"
    US_EAST_2 = "us-east-2"
    US_WEST_1 = "us-west-1"
    US_WEST_2 = "us-west-2"
    EU_WEST_1 = "eu-west-1"
    EU_CENTRAL_1 = "eu-central-1"
    # Add other regions as needed

# --- Base Model ---
class BaseModel(Model):
    class Meta:
        database = db

# --- Model Definitions ---
class Team(BaseModel):
    name = CharField(unique=True)
    contact_email = CharField()
    slack_channel = CharField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class AWSAccount(BaseModel):
    account_id = CharField(unique=True)
    name = CharField()
    org_unit = CharField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        # Enforce account_id is exactly 12 digits at the DB level
        constraints = [Check("length(account_id) = 12 AND account_id GLOB '[0-9]*'")]

class Cluster(BaseModel):
    name = CharField(unique=True)
    aws_account = ForeignKeyField(AWSAccount, backref='clusters', on_delete='CASCADE')
    region = CharField(choices=[(r.value, r.name) for r in AWSRegion])
    eks_version = CharField(null=True)
    node_group_count = IntegerField(default=0)
    api_endpoint = CharField()
    created_at = DateTimeField(default=datetime.utcnow)

class Namespace(BaseModel):
    cluster = ForeignKeyField(Cluster, backref='namespaces', on_delete='CASCADE')
    name = CharField()
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        constraints = [db.UniqueConstraint('cluster', 'name')]

class Microservice(BaseModel):
    name = CharField(unique=True)
    repo_url = CharField(null=True)
    description = TextField(null=True)
    owning_team = ForeignKeyField(Team, backref='services', on_delete='SET NULL', null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class Environment(BaseModel):
    name = CharField()
    cluster = ForeignKeyField(Cluster, backref='environments', on_delete='CASCADE')
    is_production = BooleanField(default=False)
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        constraints = [db.UniqueConstraint('name', 'cluster')]

class Deployment(BaseModel):
    microservice = ForeignKeyField(Microservice, backref='deployments', on_delete='SET NULL', null=True)
    environment = ForeignKeyField(Environment, backref='deployments', on_delete='CASCADE')
    namespace = ForeignKeyField(Namespace, backref='deployments', on_delete='CASCADE')
    name = CharField()
    kind = CharField(choices=[(k.value, k.name) for k in DeploymentKind])
    replicas = IntegerField(default=1)
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        constraints = [db.UniqueConstraint('environment', 'namespace', 'name', 'kind')]

class Pod(BaseModel):
    deployment = ForeignKeyField(Deployment, backref='pods', on_delete='CASCADE')
    name = CharField(unique=True)
    node_name = CharField(null=True)
    phase = CharField(null=True)
    started_at = DateTimeField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class ContainerImage(BaseModel):
    registry = CharField()
    repository = CharField()
    tag = CharField(null=True)
    digest = CharField()
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        primary_key = CompositeKey('registry', 'repository', 'digest')

class Container(BaseModel):
    pod = ForeignKeyField(Pod, backref='containers', on_delete='CASCADE')
    name = CharField()
    image = ForeignKeyField(ContainerImage, backref='containers', on_delete='RESTRICT')
    ready = BooleanField(default=False)
    started_at = DateTimeField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class ImageScan(BaseModel):
    image = ForeignKeyField(ContainerImage, backref='scans', on_delete='CASCADE')
    scanner = CharField()
    scanned_at = DateTimeField(default=datetime.utcnow)
    report = JSONField()
    vulnerabilities = JSONField()
    created_at = DateTimeField(default=datetime.utcnow)

class Vulnerability(BaseModel):
    cve_id = CharField(unique=True)
    description = TextField(null=True)
    published_date = DateTimeField(null=True)
    cvss_score = FloatField(null=True)
    cvss_vector = CharField(null=True)
    severity = CharField(choices=[(s.value, s.name) for s in SeverityLevel])
    references = JSONField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class VulnerabilityOccurrence(BaseModel):
    """
    A specific CVE found in one ImageScan.
    The severity is derived from the associated Vulnerability to ensure a
    single source of truth.
    """
    scan = ForeignKeyField(ImageScan, backref='occurrences', on_delete='CASCADE')
    vulnerability = ForeignKeyField(Vulnerability, backref='occurrences', on_delete='CASCADE')
    package_name = CharField(null=True)
    package_version = CharField(null=True)
    # REMOVED: severity field to enforce single source of truth.
    detected_at = DateTimeField(default=datetime.utcnow)

    @property
    def severity(self):
        """Convenience property to get severity from the canonical vulnerability."""
        return self.vulnerability.severity

    class Meta:
        constraints = [db.UniqueConstraint('scan', 'vulnerability', 'package_name')]

class Remediation(BaseModel):
    occurrence = ForeignKeyField(VulnerabilityOccurrence, backref='remediation', on_delete='CASCADE', unique=True)
    status = CharField(choices=[(r.value, r.name) for r in RemediationStatus], default=RemediationStatus.OPEN.value)
    assigned_team = ForeignKeyField(Team, backref='remediations', on_delete='SET NULL', null=True)
    assigned_to = CharField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)
    due_date = DateTimeField(null=True)
    resolved_at = DateTimeField(null=True)
    notes = TextField(null=True)

class Notification(BaseModel):
    remediation = ForeignKeyField(Remediation, backref='notifications', on_delete='CASCADE')
    channel = CharField()
    destination = CharField()
    sent_at = DateTimeField(default=datetime.utcnow)
    payload = JSONField()

class JiraIssue(BaseModel):
    remediation = ForeignKeyField(Remediation, backref='jira_issues', on_delete='CASCADE', unique=True)
    issue_key = CharField(unique=True)
    issue_url = CharField()
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

class Snapshot(BaseModel):
    environment = ForeignKeyField(Environment, backref='snapshots', on_delete='CASCADE')
    snapshot_time = DateTimeField(default=datetime.utcnow)
    total_scans = IntegerField(default=0)
    total_vulnerabilities = IntegerField(default=0)
    created_at = DateTimeField(default=datetime.utcnow)

ALL_MODELS = [
    Team, AWSAccount, Cluster, Namespace, Microservice, Environment,
    Deployment, Pod, ContainerImage, Container, ImageScan, Vulnerability,
    VulnerabilityOccurrence, Remediation, Notification, JiraIssue, Snapshot,
]

if __name__ == '__main__':
    db.connect()
    db.create_tables(ALL_MODELS)
    print("All tables created successfully.")
