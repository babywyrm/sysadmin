"""
test_models.py

Pytest suite for the Peewee models, using freezegun
to freeze timestamps and an in-memory SQLite DB.
"""
import pytest
from datetime import datetime
from freezegun import freeze_time
from peewee import SqliteDatabase, IntegrityError

import models

@pytest.fixture(autouse=True)
def in_memory_db():
    # Swap out to in-memory DB for tests
    test_db = SqliteDatabase(':memory:', pragmas={'foreign_keys': 1})
    models.db._state.reset()  # clear any connections
    models.db.initialize(test_db)

    # Bind & create tables
    test_db.bind(models.ALL_MODELS, bind_refs=False, bind_backrefs=False)
    test_db.create_tables(models.ALL_MODELS)
    yield
    test_db.drop_tables(models.ALL_MODELS)
    test_db.close()

def test_create_basic_entities():
    # Freeze time so defaults are predictable
    with freeze_time("2025-07-15 12:00:00"):
        team = models.Team.create(
            name="Platform", contact_email="platform@example.com"
        )
        acct = models.AWSAccount.create(
            account_id="123456789012", name="ProdAcct"
        )
        cluster = models.Cluster.create(
            name="prod-us-west-2", aws_account=acct,
            region="us-west-2", api_endpoint="https://eks.aws"
        )
        # verify timestamps
        assert team.created_at == datetime(2025, 7, 15, 12, 0, 0)
        assert acct.created_at == datetime(2025, 7, 15, 12, 0, 0)
        assert cluster.created_at == datetime(2025, 7, 15, 12, 0, 0)

def test_namespace_uniqueness():
    acct = models.AWSAccount.create(
        account_id="111122223333", name="DevAcct"
    )
    cl = models.Cluster.create(
        name="dev-cluster", aws_account=acct,
        region="us-east-1", api_endpoint="https://eks.dev"
    )
    models.Namespace.create(cluster=cl, name="default")
    # duplicate should raise IntegrityError
    with pytest.raises(IntegrityError):
        models.Namespace.create(cluster=cl, name="default")

def test_image_scan_and_occurrence():
    img = models.ContainerImage.create(
        registry="docker.io",
        repository="team/app",
        digest="sha256:deadbeef"
    )
    scan = models.ImageScan.create(
        image=img,
        scanner="trivy",
        report={"Results": []},
        vulnerabilities=[{"cve_id":"CVE-2025-0001","severity":"High"}]
    )
    # create the canonical vuln and occurrence
    vuln = models.Vulnerability.create(
        cve_id="CVE-2025-0001",
        severity=models.SeverityLevel.HIGH.value
    )
    occ = models.VulnerabilityOccurrence.create(
        scan=scan,
        vulnerability=vuln,
        package_name="openssl",
        package_version="1.1.1k",
        severity=vuln.severity
    )
    assert occ.vulnerability.cve_id == "CVE-2025-0001"
    # duplicate occurrence in same scan/package should fail
    with pytest.raises(IntegrityError):
        models.VulnerabilityOccurrence.create(
            scan=scan,
            vulnerability=vuln,
            package_name="openssl",
            package_version="1.1.1k",
            severity=vuln.severity
        )

def test_remediation_and_jira_issue_flow():
    # Setup minimal occurrence
    img = models.ContainerImage.create(
        registry="x", repository="y", digest="d"
    )
    scan = models.ImageScan.create(
        image=img, scanner="clair", report={}, vulnerabilities=[]
    )
    vuln = models.Vulnerability.create(
        cve_id="CVE-2025-9999",
        severity=models.SeverityLevel.LOW.value
    )
    occ = models.VulnerabilityOccurrence.create(
        scan=scan, vulnerability=vuln, severity=vuln.severity
    )
    team = models.Team.create(
        name="SecOps", contact_email="secops@org"
    )
    rem = models.Remediation.create(
        occurrence=occ, assigned_team=team
    )
    jira = models.JiraIssue.create(
        remediation=rem,
        issue_key="SEC-42",
        issue_url="https://jira/org/browse/SEC-42"
    )
    # transitions
    assert rem.status == models.RemediationStatus.OPEN.value
    rem.status = models.RemediationStatus.IN_PROGRESS.value
    rem.save()
    assert rem.status == "In Progress"
    # ensure JIRA link is accessible
    assert jira.issue_key == "SEC-42"

def test_snapshot_counts():
    acct = models.AWSAccount.create("000011112222", "Acct")
    cl = models.Cluster.create(
        name="snap-cluster", aws_account=acct,
        region="eu-west-1", api_endpoint="https://eks.eu"
    )
    env = models.Environment.create(name="stage", cluster=cl)
    with freeze_time("2025-07-15T13:30:00"):
        snap = models.Snapshot.create(
            environment=env,
            total_scans=5,
            total_vulnerabilities=12
        )
        assert snap.snapshot_time == datetime(2025, 7, 15, 13, 30, 0)
        assert snap.total_scans == 5
        assert snap.total_vulnerabilities == 12
##
##
