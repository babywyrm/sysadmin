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

# Use the SQLite extension DB to get JSONField support
db = SqliteExtDatabase('cve_tracking.db', pragmas={
    'journal_mode': 'wal',
    'foreign_keys': 1,
})

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

class BaseModel(Model):
    class Meta:
        database = db

class Team(BaseModel):
    name = CharField(unique=True)
    contact_email = CharField()
    slack_channel = CharField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class AWSAccount(BaseModel):
    account_id = CharField(unique=True)        # 12-digit AWS account
    name = CharField()
    org_unit = CharField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class Cluster(BaseModel):
    """
    Represents an EKS cluster.
    """
    name = CharField(unique=True)
    aws_account = ForeignKeyField(AWSAccount, backref='clusters', on_delete='CASCADE')
    region = CharField()                       # e.g. us-west-2
    eks_version = CharField(null=True)         # e.g. 1.24
    node_group_count = IntegerField(default=0)
    api_endpoint = CharField()
    created_at = DateTimeField(default=datetime.utcnow)

class Namespace(BaseModel):
    """
    Kubernetes namespace, scoped to a Cluster.
    """
    cluster = ForeignKeyField(Cluster, backref='namespaces', on_delete='CASCADE')
    name = CharField()
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        constraints = [
            # ensure no duplicate namespace names in same cluster
            db.UniqueConstraint('cluster', 'name')
        ]

class Microservice(BaseModel):
    """
    Logical service owned by a team, possibly deployed to multiple envs.
    """
    name = CharField(unique=True)
    repo_url = CharField(null=True)
    description = TextField(null=True)
    owning_team = ForeignKeyField(Team, backref='services', on_delete='SET NULL')
    created_at = DateTimeField(default=datetime.utcnow)

class Environment(BaseModel):
    """
    dev/staging/prod environments per cluster.
    """
    name = CharField()    # e.g. dev, staging, prod
    cluster = ForeignKeyField(Cluster, backref='environments', on_delete='CASCADE')
    is_production = BooleanField(default=False)
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        constraints = [
            db.UniqueConstraint('name', 'cluster')
        ]

class Deployment(BaseModel):
    """
    A Kubernetes Deployment/StatefulSet/etc.
    """
    microservice = ForeignKeyField(Microservice, backref='deployments', on_delete='SET NULL')
    environment = ForeignKeyField(Environment, backref='deployments', on_delete='CASCADE')
    namespace = ForeignKeyField(Namespace, backref='deployments', on_delete='CASCADE')
    name = CharField()              # k8s Deployment name
    kind = CharField()              # e.g. Deployment, StatefulSet, DaemonSet
    replicas = IntegerField(default=1)
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        constraints = [
            db.UniqueConstraint('environment', 'namespace', 'name', 'kind')
        ]

class Pod(BaseModel):
    deployment = ForeignKeyField(Deployment, backref='pods', on_delete='CASCADE')
    name = CharField(unique=True)   # full pod name
    node_name = CharField(null=True)
    phase = CharField(null=True)    # Pending, Running, Succeeded, Failed, Unknown
    started_at = DateTimeField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class ContainerImage(BaseModel):
    """
    A container image reference; deduped by registry/repo/digest.
    """
    registry = CharField()          # e.g. docker.io, 123456789012.dkr.ecr.us-west-2.amazonaws.com
    repository = CharField()        # e.g. myteam/microservice
    tag = CharField(null=True)      # e.g. latest, v1.2.3
    digest = CharField()            # immutable sha256:...
    created_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        constraints = [
            CompositeKey('registry', 'repository', 'digest')
        ]

class Container(BaseModel):
    pod = ForeignKeyField(Pod, backref='containers', on_delete='CASCADE')
    name = CharField()              # container name in the pod spec
    image = ForeignKeyField(ContainerImage, backref='containers', on_delete='RESTRICT')
    ready = BooleanField(default=False)
    started_at = DateTimeField(null=True)
    created_at = DateTimeField(default=datetime.utcnow)

class ImageScan(BaseModel):
    """
    A scan of a container image by some scanner.
    """
    image = ForeignKeyField(ContainerImage, backref='scans', on_delete='CASCADE')
    scanner = CharField()           # e.g. trivy, clair, anchore
    scanned_at = DateTimeField(default=datetime.utcnow)
    report = JSONField()            # full JSON payload from the scanner
    vulnerabilities = JSONField()   # extracted list of {'cve_id','severity','package',...}
    created_at = DateTimeField(default=datetime.utcnow)

class Vulnerability(BaseModel):
    cve_id = CharField(unique=True)              # e.g. CVE-2025-1234
    description = TextField(null=True)
    published_date = DateTimeField(null=True)
    cvss_score = FloatField(null=True)
    cvss_vector = CharField(null=True)
    severity = CharField(choices=[(s.value, s.name) for s in SeverityLevel])
    references = JSONField(null=True)            # list of URLs
    created_at = DateTimeField(default=datetime.utcnow)

class VulnerabilityOccurrence(BaseModel):
    """
    A specific CVE found in a particular image scan.
    """
    scan = ForeignKeyField(ImageScan, backref='occurrences', on_delete='CASCADE')
    vulnerability = ForeignKeyField(Vulnerability, backref='occurrences', on_delete='CASCADE')
    package_name = CharField(null=True)          # e.g. openssl
    package_version = CharField(null=True)       # e.g. 1.1.1k
    severity = CharField(choices=[(s.value, s.name) for s in SeverityLevel])
    detected_at = DateTimeField(default=datetime.utcnow)

    class Meta:
        constraints = [
            # avoid double-logging the same CVE in one scan for same package
            db.UniqueConstraint('scan', 'vulnerability', 'package_name')
        ]

class Remediation(BaseModel):
    """
    Tracks the process of fixing a detected CVE in a deployment/image.
    """
    occurrence = ForeignKeyField(VulnerabilityOccurrence, backref='remediation', on_delete='CASCADE')
    status = CharField(choices=[(r.value, r.name) for r in RemediationStatus],
                       default=RemediationStatus.OPEN.value)
    assigned_team = ForeignKeyField(Team, backref='remediations', on_delete='SET NULL')
    assigned_to = CharField(null=True)           # individual engineer
    created_at = DateTimeField(default=datetime.utcnow)
    due_date = DateTimeField(null=True)
    resolved_at = DateTimeField(null=True)
    notes = TextField(null=True)

class Notification(BaseModel):
    """
    Records when/where we notified teams about open remediations.
    """
    remediation = ForeignKeyField(Remediation, backref='notifications', on_delete='CASCADE')
    channel = CharField()         # e.g. slack, email, pagerduty
    destination = CharField()     # e.g. "#sec-team", "ops@example.com"
    sent_at = DateTimeField(default=datetime.utcnow)
    payload = JSONField()         # full message payload

if __name__ == '__main__':
    db.connect()
    db.create_tables([
        Team, AWSAccount, Cluster, Namespace, Microservice,
        Environment, Deployment, Pod, ContainerImage, Container,
        ImageScan, Vulnerability, VulnerabilityOccurrence,
        Remediation, Notification
    ])
    print("All tables created successfully.")

##
##
