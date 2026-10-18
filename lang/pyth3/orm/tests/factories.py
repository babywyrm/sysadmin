"""
factories.py

Test data factories using factory-boy for simplified test setup.
Place this file in a 'tests/' directory.
"""
import factory
from datetime import datetime

import models

class TeamFactory(factory.peewee.PeeweeModelFactory):
    class Meta:
        model = models.Team

    name = factory.Sequence(lambda n: f"Team-{n}")
    contact_email = factory.LazyAttribute(
        lambda obj: f"{obj.name.lower()}@example.com"
    )
    created_at = factory.LazyFunction(datetime.utcnow)

class AWSAccountFactory(factory.peewee.PeeweeModelFactory):
    class Meta:
        model = models.AWSAccount

    account_id = factory.Sequence(lambda n: f"{100000000000 + n:012d}")
    name = factory.Sequence(lambda n: f"AWS Account {n}")
    created_at = factory.LazyFunction(datetime.utcnow)

class ClusterFactory(factory.peewee.PeeweeModelFactory):
    class Meta:
        model = models.Cluster

    name = factory.Sequence(lambda n: f"cluster-{n}")
    aws_account = factory.SubFactory(AWSAccountFactory)
    region = models.AWSRegion.US_WEST_2.value
    api_endpoint = factory.LazyAttribute(
        lambda obj: f"https://{obj.name}.eks.amazonaws.com"
    )
    created_at = factory.LazyFunction(datetime.utcnow)

class NamespaceFactory(factory.peewee.PeeweeModelFactory):
    class Meta:
        model = models.Namespace

    cluster = factory.SubFactory(ClusterFactory)
    name = factory.Sequence(lambda n: f"namespace-{n}")
    created_at = factory.LazyFunction(datetime.utcnow)

class ContainerImageFactory(factory.peewee.PeeweeModelFactory):
    class Meta:
        model = models.ContainerImage

    registry = "docker.io"
    repository = factory.Sequence(lambda n: f"team/app-{n}")
    digest = factory.Sequence(lambda n: f"sha256:{'a' * 56}{n:08x}")
    created_at = factory.LazyFunction(datetime.utcnow)

class ImageScanFactory(factory.peewee.PeeweeModelFactory):
    class Meta:
        model = models.ImageScan

    image = factory.SubFactory(ContainerImageFactory)
    scanner = "trivy"
    report = {}
    vulnerabilities = []
    created_at = factory.LazyFunction(datetime.utcnow)

class VulnerabilityFactory(factory.peewee.PeeweeModelFactory):
    class Meta:
        model = models.Vulnerability

    cve_id = factory.Sequence(lambda n: f"CVE-2025-{n:04d}")
    severity = models.SeverityLevel.HIGH.value
    created_at = factory.LazyFunction(datetime.utcnow)

class VulnerabilityOccurrenceFactory(factory.peewee.PeeweeModelFactory):
    class Meta:
        model = models.VulnerabilityOccurrence

    scan = factory.SubFactory(ImageScanFactory)
    vulnerability = factory.SubFactory(VulnerabilityFactory)
    package_name = "openssl"
    package_version = "1.1.1k"
    detected_at = factory.LazyFunction(datetime.utcnow)

class RemediationFactory(factory.peewee.PeeweeModelFactory):
    class Meta:
        model = models.Remediation

    occurrence = factory.SubFactory(VulnerabilityOccurrenceFactory)
    assigned_team = factory.SubFactory(TeamFactory)
    created_at = factory.LazyFunction(datetime.utcnow)

class JiraIssueFactory(factory.peewee.PeeweeModelFactory):
    class Meta:
        model = models.JiraIssue

    remediation = factory.SubFactory(RemediationFactory)
    issue_key = factory.Sequence(lambda n: f"SEC-{n}")
    issue_url = factory.LazyAttribute(
        lambda obj: f"https://jira.example.com/browse/{obj.issue_key}"
    )
    created_at = factory.LazyFunction(datetime.utcnow)
  
