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
)
from playhouse.sqlite_ext import SqliteExtDatabase, JSONField

# Use SQLite with JSON extension enabled
db = SqliteExtDatabase(
    'cve_tracking.db',
    pragmas={'journal_mode': 'wal', 'foreign_keys': 1},
)

# Enumerations for fixed-choice fields
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

# Base model to set database
class BaseModel(Model):
    class Meta:
        database = db

class Team(BaseModel):
    """
    Logical team owning microservices. Used for assignment/
    notifications.
    """
    name = CharField(unique=True)
    contact_email = CharField()      # primary contact
    slack_channel = CharField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class AWSAccount(BaseModel):
    """
    AWS account metadata for multi-account setups.
    """
    account_id = CharField(unique=True)  # 12-digit AWS account ID
    name = CharField()                   # e.g. "Production"
    org_unit = CharField(null=True)      # AWS Org unit
    created_at = DateTimeField(default=datetime.utcnow)

class Cluster(BaseModel):
    """
    Represents an EKS cluster in a given AWS account & region.
    """
    name = CharField(unique=True)  # logical cluster name
    aws_account = ForeignKeyField(
        AWSAccount, backref='clusters', on_delete='CASCADE'
    )
    region = CharField()           # e.g. us-west-2
    eks_version = CharField(null=True)  # e.g. "1.24"
    node_group_count = IntegerField(default=0)
    api_endpoint = CharField()     # cluster API endpoint
    created_at = DateTimeField(default=datetime.utcnow)

class Namespace(BaseModel):
    """
    Kubernetes namespace, scoped to a Cluster.
    """
    cluster = ForeignKeyField(
        Cluster, backref='namespaces', on_delete='CASCADE'
    )
    name = CharField()             # e.g. "default", "prod"
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        # prevent duplicate namespace names in same cluster
        constraints = [db.UniqueConstraint('cluster', 'name')]

class Microservice(BaseModel):
    """
    Logical microservice, linked to code repo and Team.
    """
    name = CharField(unique=True)
    repo_url = CharField(null=True)   # e.g. GitHub link
    description = TextField(null=True)
    owning_team = ForeignKeyField(
        Team, backref='services', on_delete='SET NULL'
    )
    created_at = DateTimeField(default=datetime.utcnow)

class Environment(BaseModel):
    """
    Deployment environment (dev/staging/prod) on a cluster.
    """
    name = CharField()                # "dev", "staging", "prod"
    cluster = ForeignKeyField(
        Cluster, backref='environments', on_delete='CASCADE'
    )
    is_production = BooleanField(default=False)
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        constraints = [db.UniqueConstraint('name', 'cluster')]

class Deployment(BaseModel):
    """
    K8s Deployment/StatefulSet/DaemonSet for a microservice.
    """
    microservice = ForeignKeyField(
        Microservice, backref='deployments', on_delete='SET NULL'
    )
    environment = ForeignKeyField(
        Environment, backref='deployments', on_delete='CASCADE'
    )
    namespace = ForeignKeyField(
        Namespace, backref='deployments', on_delete='CASCADE'
    )
    name = CharField()                # k8s resource name
    kind = CharField()                # "Deployment", "StatefulSet", etc.
    replicas = IntegerField(default=1)
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        constraints = [
            db.UniqueConstraint('environment', 'namespace', 'name', 'kind')
        ]

class Pod(BaseModel):
    """
    A Pod instance belonging to a Deployment.
    """
    deployment = ForeignKeyField(
        Deployment, backref='pods', on_delete='CASCADE'
    )
    name = CharField(unique=True)     # full pod name
    node_name = CharField(null=True)
    phase = CharField(null=True)      # Pod phase: Running, Pending, etc.
    started_at = DateTimeField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class ContainerImage(BaseModel):
    """
    Immutable container image, deduped by registry/repo/digest.
    """
    registry = CharField()         # e.g. docker.io or ECR URL
    repository = CharField()       # e.g. myteam/service
    tag = CharField(null=True)     # e.g. "latest", "v1.2.3"
    digest = CharField()           # sha256:...
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        primary_key = CompositeKey('registry', 'repository', 'digest')

class Container(BaseModel):
    """
    Actual container in a Pod, pointing to a ContainerImage.
    """
    pod = ForeignKeyField(
        Pod, backref='containers', on_delete='CASCADE'
    )
    name = CharField()             # container name in spec
    image = ForeignKeyField(
        ContainerImage, backref='containers', on_delete='RESTRICT'
    )
    ready = BooleanField(default=False)
    started_at = DateTimeField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class ImageScan(BaseModel):
    """
    A scan run against a ContainerImage by a given scanner.
    Stores raw report and extracted vulns.
    """
    image = ForeignKeyField(
        ContainerImage, backref='scans', on_delete='CASCADE'
    )
    scanner = CharField()          # e.g. trivy, clair
    scanned_at = DateTimeField(default=datetime.utcnow)
    report = JSONField()           # full JSON payload
    vulnerabilities = JSONField()  # list of {cve_id,severity,package…}
    created_at = DateTimeField(default=datetime.utcnow)

class Vulnerability(BaseModel):
    """
    Canonical CVE info, enriched with CVSS data.
    """
    cve_id = CharField(unique=True)    # e.g. CVE-2025-1234
    description = TextField(null=True)
    published_date = DateTimeField(null=True)
    cvss_score = FloatField(null=True)
    cvss_vector = CharField(null=True)
    severity = CharField(
        choices=[(s.value, s.name) for s in SeverityLevel]
    )
    references = JSONField(null=True)  # list of URLs
    created_at = DateTimeField(default=datetime.utcnow)

class VulnerabilityOccurrence(BaseModel):
    """
    A specific CVE found in one ImageScan.
    """
    scan = ForeignKeyField(
        ImageScan, backref='occurrences', on_delete='CASCADE'
    )
    vulnerability = ForeignKeyField(
        Vulnerability, backref='occurrences', on_delete='CASCADE'
    )
    package_name = CharField(null=True)     # e.g. openssl
    package_version = CharField(null=True)  # e.g. 1.1.1k
    severity = CharField(
        choices=[(s.value, s.name) for s in SeverityLevel]
    )
    detected_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        constraints = [
            # avoid duplicates in same scan/package
            db.UniqueConstraint('scan', 'vulnerability', 'package_name')
        ]

class Remediation(BaseModel):
    """
    Tracks the lifecycle of a CVE fix (ticket).
    """
    occurrence = ForeignKeyField(
        VulnerabilityOccurrence, backref='remediation',
        on_delete='CASCADE'
    )
    status = CharField(
        choices=[(r.value, r.name) for r in RemediationStatus],
        default=RemediationStatus.OPEN.value
    )
    assigned_team = ForeignKeyField(
        Team, backref='remediations', on_delete='SET NULL'
    )
    assigned_to = CharField(null=True)   # individual engineer
    created_at = DateTimeField(default=datetime.utcnow)
    due_date = DateTimeField(null=True)
    resolved_at = DateTimeField(null=True)
    notes = TextField(null=True)

class Notification(BaseModel):
    """
    Records notifications sent about open remediations.
    """
    remediation = ForeignKeyField(
        Remediation, backref='notifications', on_delete='CASCADE'
    )
    channel = CharField()         # e.g. slack, email
    destination = CharField()     # e.g. "#sec", "ops@…"
    sent_at = DateTimeField(default=datetime.utcnow)
    payload = JSONField()         # raw message

class JiraIssue(BaseModel):
    """
    Links a Remediation to a JIRA issue for tracking.
    """
    remediation = ForeignKeyField(
        Remediation, backref='jira_issues', on_delete='CASCADE'
    )
    issue_key = CharField()       # e.g. "PROJ-123"
    issue_url = CharField()       # full URL to JIRA
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

class Snapshot(BaseModel):
    """
    Periodic summary of scans & vulns in an Environment.
    """
    environment = ForeignKeyField(
        Environment, backref='snapshots', on_delete='CASCADE'
    )
    snapshot_time = DateTimeField(default=datetime.utcnow)
    total_scans = IntegerField(default=0)
    total_vulnerabilities = IntegerField(default=0)
    created_at = DateTimeField(default=datetime.utcnow)

# List of all models for test binding
ALL_MODELS = [
    Team, AWSAccount, Cluster, Namespace, Microservice, Environment,
    Deployment, Pod, ContainerImage, Container, ImageScan, Vulnerability,
    VulnerabilityOccurrence, Remediation, Notification, JiraIssue, Snapshot,
]

if __name__ == '__main__':
    db.connect()
    db.create_tables(ALL_MODELS)
    print("All tables created successfully.")

##
##
