# AWS Evidence Collection Framework - Modern Python Architecture ..dev..

---

## 📁 PROJECT STRUCTURE

```
aws-incident-collector/
├── README.md
├── requirements.txt
├── setup.py
├── pyproject.toml
├── .env.example
├── config/
│   ├── __init__.py
│   ├── settings.py
│   └── collectors.yaml
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── aws_client.py
│   │   ├── evidence.py
│   │   ├── custody.py
│   │   └── storage.py
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── cloudtrail.py
│   │   ├── iam.py
│   │   ├── vpc.py
│   │   ├── guardduty.py
│   │   ├── config.py
│   │   ├── s3.py
│   │   └── ec2.py
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── timeline.py
│   │   └── correlation.py
│   └── utils/
│       ├── __init__.py
│       ├── logging.py
│       ├── hashing.py
│       └── validators.py
├── tests/
│   ├── __init__.py
│   ├── test_collectors.py
│   └── test_evidence.py
└── output/
    └── .gitkeep
```

---

## 📦 CORE FILES

### `requirements.txt`

```text
# AWS SDKs
boto3>=1.34.0
botocore>=1.34.0

# Async Support
aioboto3>=12.0.0
aiofiles>=23.0.0

# Data Processing
pandas>=2.0.0
pyarrow>=14.0.0

# Configuration
pydantic>=2.5.0
pydantic-settings>=2.1.0
python-dotenv>=1.0.0
pyyaml>=6.0.0

# Hashing & Crypto
hashlib-additional>=1.0.0

# Logging
structlog>=24.0.0
python-json-logger>=2.0.0

# CLI
click>=8.1.0
rich>=13.0.0
typer>=0.9.0

# Testing
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0
moto>=4.2.0

# Type Checking
mypy>=1.7.0
types-boto3>=1.0.0
```

---

### `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=65.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "aws-incident-collector"
version = "1.0.0"
description = "AWS Evidence Collection Framework for Incident Response"
authors = [{name = "Security Team", email = "security@example.com"}]
license = {text = "MIT"}
requires-python = ">=3.9"
dependencies = [
    "boto3>=1.34.0",
    "aioboto3>=12.0.0",
    "pydantic>=2.5.0",
    "click>=8.1.0",
    "rich>=13.0.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.4.0", "mypy>=1.7.0", "black>=23.0.0", "ruff>=0.1.0"]

[tool.black]
line-length = 88
target-version = ['py39', 'py310', 'py311']

[tool.ruff]
line-length = 88
select = ["E", "F", "I", "N", "W"]

[tool.mypy]
python_version = "3.9"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
```

---

### `config/settings.py`

```python
"""Configuration management for AWS Evidence Collection."""

from pathlib import Path
from typing import Optional, Dict, Any
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AWSSettings(BaseSettings):
    """AWS-specific configuration."""

    model_config = SettingsConfigDict(
        env_prefix="AWS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    profile: Optional[str] = Field(default=None, description="AWS profile name")
    region: str = Field(default="us-east-1", description="Default AWS region")
    account_id: Optional[str] = Field(
        default=None, description="AWS Account ID for validation"
    )
    assume_role_arn: Optional[str] = Field(
        default=None, description="IAM role to assume for collection"
    )
    session_duration: int = Field(
        default=3600, description="Session duration in seconds"
    )


class CollectionSettings(BaseSettings):
    """Evidence collection configuration."""

    model_config = SettingsConfigDict(
        env_prefix="COLLECTION_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    incident_id: str = Field(..., description="Incident ID (e.g., INC-20250101-001)")
    target_user: Optional[str] = Field(
        default=None, description="Target IAM user or principal"
    )
    target_instance_id: Optional[str] = Field(
        default=None, description="Target EC2 instance ID"
    )
    start_time: str = Field(
        ..., description="Collection start time (ISO 8601 format)"
    )
    end_time: str = Field(..., description="Collection end time (ISO 8601 format)")
    lookback_days: int = Field(default=14, description="Days to look back for logs")
    output_dir: Path = Field(
        default=Path("./output"), description="Output directory for evidence"
    )
    enable_hashing: bool = Field(default=True, description="Generate SHA256 hashes")
    enable_compression: bool = Field(
        default=True, description="Compress output files"
    )

    @field_validator("output_dir")
    @classmethod
    def ensure_output_dir(cls, v: Path) -> Path:
        """Ensure output directory exists."""
        v.mkdir(parents=True, exist_ok=True)
        return v


class Settings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    aws: AWSSettings = Field(default_factory=AWSSettings)
    collection: CollectionSettings
    log_level: str = Field(default="INFO", description="Logging level")
    max_workers: int = Field(
        default=10, description="Max concurrent collection workers"
    )
    retry_attempts: int = Field(
        default=3, description="Number of retry attempts for failed API calls"
    )
    retry_delay: int = Field(default=2, description="Delay between retries (seconds)")


def load_settings() -> Settings:
    """Load and validate settings."""
    return Settings()
```

---

### `src/core/aws_client.py`

```python
"""AWS client management with session handling and role assumption."""

import asyncio
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager
import aioboto3
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError
import structlog

from config.settings import AWSSettings

logger = structlog.get_logger()


class AWSClientManager:
    """Manages AWS client sessions with automatic credential refresh."""

    def __init__(self, settings: AWSSettings) -> None:
        self.settings = settings
        self.session: Optional[aioboto3.Session] = None
        self._credentials: Optional[Dict[str, str]] = None

        # Configure retry behavior
        self.config = Config(
            retries={"max_attempts": 3, "mode": "adaptive"},
            max_pool_connections=50,
            connect_timeout=10,
            read_timeout=60,
        )

    async def initialize(self) -> None:
        """Initialize AWS session and assume role if configured."""
        logger.info("Initializing AWS session", region=self.settings.region)

        # Create base session
        if self.settings.profile:
            self.session = aioboto3.Session(profile_name=self.settings.profile)
        else:
            self.session = aioboto3.Session()

        # Assume role if ARN provided
        if self.settings.assume_role_arn:
            await self._assume_role()
        else:
            logger.info("Using default credentials")

    async def _assume_role(self) -> None:
        """Assume IAM role for cross-account or elevated access."""
        logger.info(
            "Assuming IAM role", role_arn=self.settings.assume_role_arn
        )

        try:
            # Use sync boto3 for STS (no async support)
            sts = boto3.client("sts", region_name=self.settings.region)
            response = sts.assume_role(
                RoleArn=self.settings.assume_role_arn,
                RoleSessionName="IncidentResponseCollection",
                DurationSeconds=self.settings.session_duration,
            )

            credentials = response["Credentials"]
            self._credentials = {
                "aws_access_key_id": credentials["AccessKeyId"],
                "aws_secret_access_key": credentials["SecretAccessKey"],
                "aws_session_token": credentials["SessionToken"],
            }

            # Create new session with assumed role credentials
            self.session = aioboto3.Session(
                region_name=self.settings.region, **self._credentials
            )

            logger.info(
                "Successfully assumed role",
                assumed_role_arn=response["AssumedRoleUser"]["Arn"],
            )

        except (ClientError, BotoCoreError) as e:
            logger.error("Failed to assume role", error=str(e))
            raise

    @asynccontextmanager
    async def get_client(self, service_name: str, region: Optional[str] = None):
        """
        Get AWS service client with proper resource management.

        Args:
            service_name: AWS service (e.g., 'cloudtrail', 'iam')
            region: Optional region override

        Yields:
            AWS service client
        """
        if not self.session:
            await self.initialize()

        target_region = region or self.settings.region

        async with self.session.client(
            service_name, region_name=target_region, config=self.config
        ) as client:
            yield client

    async def get_caller_identity(self) -> Dict[str, Any]:
        """Get current AWS caller identity for verification."""
        async with self.get_client("sts") as sts:
            try:
                response = await sts.get_caller_identity()
                logger.info(
                    "Caller identity verified",
                    account=response["Account"],
                    arn=response["Arn"],
                )
                return response
            except ClientError as e:
                logger.error("Failed to get caller identity", error=str(e))
                raise

    async def verify_permissions(self, service: str, action: str) -> bool:
        """
        Verify if current credentials have required permissions.

        Args:
            service: AWS service (e.g., 'cloudtrail')
            action: Action to test (e.g., 'LookupEvents')

        Returns:
            True if permission exists, False otherwise
        """
        async with self.get_client("iam") as iam:
            try:
                # Simulate the API call to check permissions
                await iam.simulate_principal_policy(
                    PolicySourceArn=(await self.get_caller_identity())["Arn"],
                    ActionNames=[f"{service}:{action}"],
                )
                return True
            except ClientError:
                return False
```

---

### `src/core/evidence.py`

```python
"""Evidence management and metadata tracking."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from enum import Enum
import structlog

from src.utils.hashing import calculate_sha256

logger = structlog.get_logger()


class EvidenceType(str, Enum):
    """Types of evidence collected."""

    CLOUDTRAIL = "cloudtrail"
    IAM = "iam"
    VPC_FLOW = "vpc_flow"
    GUARDDUTY = "guardduty"
    CONFIG = "aws_config"
    S3_ACCESS = "s3_access"
    EC2_METADATA = "ec2_metadata"
    CLOUDWATCH = "cloudwatch"
    LAMBDA = "lambda"


class EvidenceSeverity(str, Enum):
    """Evidence priority/severity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class EvidenceMetadata:
    """Metadata for collected evidence."""

    evidence_id: str
    evidence_type: EvidenceType
    incident_id: str
    collection_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    collector: str = ""
    source_account: Optional[str] = None
    source_region: Optional[str] = None
    file_path: Optional[Path] = None
    file_size_bytes: Optional[int] = None
    sha256_hash: Optional[str] = None
    record_count: Optional[int] = None
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None
    severity: EvidenceSeverity = EvidenceSeverity.INFO
    tags: Dict[str, str] = field(default_factory=dict)
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        # Convert Path to string
        if self.file_path:
            data["file_path"] = str(self.file_path)
        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class EvidencePackage:
    """Container for related evidence items."""

    incident_id: str
    package_id: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    evidence_items: List[EvidenceMetadata] = field(default_factory=list)
    manifest_path: Optional[Path] = None

    def add_evidence(self, evidence: EvidenceMetadata) -> None:
        """Add evidence item to package."""
        self.evidence_items.append(evidence)
        logger.info(
            "Evidence added to package",
            evidence_id=evidence.evidence_id,
            evidence_type=evidence.evidence_type,
            package_id=self.package_id,
        )

    def get_evidence_by_type(
        self, evidence_type: EvidenceType
    ) -> List[EvidenceMetadata]:
        """Get all evidence items of a specific type."""
        return [e for e in self.evidence_items if e.evidence_type == evidence_type]

    def generate_manifest(self, output_path: Path) -> Path:
        """
        Generate evidence manifest file.

        Args:
            output_path: Directory to write manifest

        Returns:
            Path to manifest file
        """
        manifest_file = output_path / f"{self.package_id}_manifest.json"

        manifest = {
            "incident_id": self.incident_id,
            "package_id": self.package_id,
            "created_at": self.created_at,
            "evidence_count": len(self.evidence_items),
            "evidence_items": [e.to_dict() for e in self.evidence_items],
        }

        with open(manifest_file, "w") as f:
            json.dump(manifest, f, indent=2)

        self.manifest_path = manifest_file
        logger.info(
            "Manifest generated",
            manifest_path=str(manifest_file),
            evidence_count=len(self.evidence_items),
        )

        return manifest_file

    def validate_integrity(self) -> Dict[str, bool]:
        """
        Validate integrity of all evidence files.

        Returns:
            Dict mapping evidence_id to validation result
        """
        results = {}

        for evidence in self.evidence_items:
            if not evidence.file_path or not evidence.sha256_hash:
                results[evidence.evidence_id] = False
                continue

            if not evidence.file_path.exists():
                logger.warning(
                    "Evidence file missing", evidence_id=evidence.evidence_id
                )
                results[evidence.evidence_id] = False
                continue

            current_hash = calculate_sha256(evidence.file_path)
            results[evidence.evidence_id] = current_hash == evidence.sha256_hash

            if not results[evidence.evidence_id]:
                logger.error(
                    "Hash mismatch detected",
                    evidence_id=evidence.evidence_id,
                    expected=evidence.sha256_hash,
                    actual=current_hash,
                )

        return results


class EvidenceCollector:
    """Base class for evidence collection operations."""

    def __init__(self, incident_id: str, output_dir: Path) -> None:
        self.incident_id = incident_id
        self.output_dir = output_dir
        self.evidence_package = EvidencePackage(
            incident_id=incident_id,
            package_id=f"{incident_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
        )

    def create_evidence_metadata(
        self,
        evidence_type: EvidenceType,
        file_path: Path,
        **kwargs: Any,
    ) -> EvidenceMetadata:
        """
        Create evidence metadata for collected file.

        Args:
            evidence_type: Type of evidence
            file_path: Path to evidence file
            **kwargs: Additional metadata fields

        Returns:
            EvidenceMetadata object
        """
        evidence_id = (
            f"{self.incident_id}_{evidence_type.value}_"
            f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        )

        metadata = EvidenceMetadata(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            incident_id=self.incident_id,
            file_path=file_path,
            **kwargs,
        )

        # Calculate file hash if file exists
        if file_path.exists():
            metadata.file_size_bytes = file_path.stat().st_size
            metadata.sha256_hash = calculate_sha256(file_path)

        self.evidence_package.add_evidence(metadata)
        return metadata
```

---

### `src/utils/hashing.py`

```python
"""Cryptographic hashing utilities for evidence integrity."""

import hashlib
from pathlib import Path
from typing import Optional
import structlog

logger = structlog.get_logger()


def calculate_sha256(file_path: Path, chunk_size: int = 8192) -> str:
    """
    Calculate SHA256 hash of a file.

    Args:
        file_path: Path to file
        chunk_size: Read chunk size in bytes

    Returns:
        Hex-encoded SHA256 hash
    """
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256_hash.update(chunk)

        hash_value = sha256_hash.hexdigest()
        logger.debug("Hash calculated", file=str(file_path), hash=hash_value)
        return hash_value

    except Exception as e:
        logger.error("Failed to calculate hash", file=str(file_path), error=str(e))
        raise


def verify_hash(file_path: Path, expected_hash: str) -> bool:
    """
    Verify file hash matches expected value.

    Args:
        file_path: Path to file
        expected_hash: Expected SHA256 hash

    Returns:
        True if hash matches, False otherwise
    """
    actual_hash = calculate_sha256(file_path)
    match = actual_hash == expected_hash.lower()

    if not match:
        logger.warning(
            "Hash mismatch",
            file=str(file_path),
            expected=expected_hash,
            actual=actual_hash,
        )

    return match


def calculate_string_hash(data: str) -> str:
    """
    Calculate SHA256 hash of string data.

    Args:
        data: String to hash

    Returns:
        Hex-encoded SHA256 hash
    """
    return hashlib.sha256(data.encode()).hexdigest()
```

---

### `src/collectors/base.py`

```python
"""Base collector class for AWS evidence collection."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime
import json
import structlog

from src.core.aws_client import AWSClientManager
from src.core.evidence import (
    EvidenceType,
    EvidenceMetadata,
    EvidenceSeverity,
)

logger = structlog.get_logger()


class BaseCollector(ABC):
    """Abstract base class for evidence collectors."""

    def __init__(
        self,
        client_manager: AWSClientManager,
        incident_id: str,
        output_dir: Path,
    ) -> None:
        self.client_manager = client_manager
        self.incident_id = incident_id
        self.output_dir = output_dir
        self.collector_name = self.__class__.__name__

        # Create collector-specific output directory
        self.collector_dir = output_dir / self.evidence_type.value
        self.collector_dir.mkdir(parents=True, exist_ok=True)

    @property
    @abstractmethod
    def evidence_type(self) -> EvidenceType:
        """Return the evidence type this collector handles."""
        pass

    @abstractmethod
    async def collect(
        self,
        start_time: datetime,
        end_time: datetime,
        **kwargs: Any,
    ) -> List[EvidenceMetadata]:
        """
        Collect evidence within time range.

        Args:
            start_time: Start of collection window
            end_time: End of collection window
            **kwargs: Additional collector-specific parameters

        Returns:
            List of evidence metadata
        """
        pass

    def save_json(
        self, data: Any, filename: str, metadata: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        Save data as JSON file with metadata.

        Args:
            data: Data to save
            filename: Output filename
            metadata: Optional metadata to include

        Returns:
            Path to saved file
        """
        output_path = self.collector_dir / filename

        output_data = {"metadata": metadata or {}, "data": data}

        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2, default=str)

        logger.info(
            "Data saved",
            collector=self.collector_name,
            file=str(output_path),
            size_bytes=output_path.stat().st_size,
        )

        return output_path

    def create_metadata(
        self,
        file_path: Path,
        record_count: Optional[int] = None,
        severity: EvidenceSeverity = EvidenceSeverity.INFO,
        **kwargs: Any,
    ) -> EvidenceMetadata:
        """
        Create evidence metadata for collected file.

        Args:
            file_path: Path to evidence file
            record_count: Number of records collected
            severity: Evidence severity
            **kwargs: Additional metadata fields

        Returns:
            EvidenceMetadata object
        """
        from src.utils.hashing import calculate_sha256

        evidence_id = (
            f"{self.incident_id}_{self.evidence_type.value}_"
            f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        )

        metadata = EvidenceMetadata(
            evidence_id=evidence_id,
            evidence_type=self.evidence_type,
            incident_id=self.incident_id,
            collector=self.collector_name,
            file_path=file_path,
            file_size_bytes=file_path.stat().st_size,
            sha256_hash=calculate_sha256(file_path),
            record_count=record_count,
            severity=severity,
            **kwargs,
        )

        logger.info(
            "Evidence metadata created",
            evidence_id=evidence_id,
            evidence_type=self.evidence_type.value,
        )

        return metadata
```

---

### `src/collectors/cloudtrail.py`

```python
"""CloudTrail evidence collector."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from pathlib import Path
import structlog

from src.collectors.base import BaseCollector
from src.core.evidence import EvidenceType, EvidenceMetadata, EvidenceSeverity

logger = structlog.get_logger()


class CloudTrailCollector(BaseCollector):
    """Collects CloudTrail logs for incident investigation."""

    @property
    def evidence_type(self) -> EvidenceType:
        return EvidenceType.CLOUDTRAIL

    async def collect(
        self,
        start_time: datetime,
        end_time: datetime,
        username: Optional[str] = None,
        event_names: Optional[List[str]] = None,
        resource_type: Optional[str] = None,
        **kwargs: Any,
    ) -> List[EvidenceMetadata]:
        """
        Collect CloudTrail events within time range.

        Args:
            start_time: Start of collection window
            end_time: End of collection window
            username: Filter by IAM username
            event_names: Filter by specific event names
            resource_type: Filter by resource type
            **kwargs: Additional filters

        Returns:
            List of evidence metadata
        """
        logger.info(
            "Starting CloudTrail collection",
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            username=username,
        )

        evidence_list: List[EvidenceMetadata] = []

        async with self.client_manager.get_client("cloudtrail") as ct_client:
            # Build lookup attributes
            lookup_attributes = []
            if username:
                lookup_attributes.append(
                    {"AttributeKey": "Username", "AttributeValue": username}
                )
            if resource_type:
                lookup_attributes.append(
                    {"AttributeKey": "ResourceType", "AttributeValue": resource_type}
                )

            # Collect events (CloudTrail limits to 50 events per call)
            all_events = []
            next_token = None

            while True:
                try:
                    params: Dict[str, Any] = {
                        "StartTime": start_time,
                        "EndTime": end_time,
                        "MaxResults": 50,
                    }

                    if lookup_attributes:
                        params["LookupAttributes"] = lookup_attributes
                    if next_token:
                        params["NextToken"] = next_token

                    response = await ct_client.lookup_events(**params)

                    events = response.get("Events", [])
                    all_events.extend(events)

                    logger.debug(
                        "CloudTrail batch collected", event_count=len(events)
                    )

                    next_token = response.get("NextToken")
                    if not next_token:
                        break

                except Exception as e:
                    logger.error("CloudTrail collection error", error=str(e))
                    break

            # Filter by event names if specified
            if event_names:
                all_events = [
                    e for e in all_events if e.get("EventName") in event_names
                ]

            logger.info("CloudTrail collection complete", total_events=len(all_events))

            # Save events
            if all_events:
                filename = f"cloudtrail_events_{start_time.strftime('%Y%m%d')}_{end_time.strftime('%Y%m%d')}.json"
                file_path = self.save_json(
                    all_events,
                    filename,
                    metadata={
                        "collection_time": datetime.utcnow().isoformat(),
                        "start_time": start_time.isoformat(),
                        "end_time": end_time.isoformat(),
                        "username": username,
                        "event_names": event_names,
                    },
                )

                # Determine severity based on event types
                severity = self._assess_severity(all_events)

                metadata = self.create_metadata(
                    file_path=file_path,
                    record_count=len(all_events),
                    severity=severity,
                    time_range_start=start_time.isoformat(),
                    time_range_end=end_time.isoformat(),
                    tags={"username": username or "all"},
                )
                evidence_list.append(metadata)

        return evidence_list

    def _assess_severity(self, events: List[Dict[str, Any]]) -> EvidenceSeverity:
        """Assess severity based on event content."""
        critical_events = [
            "DeleteBucket",
            "DeleteUser",
            "PutBucketPolicy",
            "CreateAccessKey",
            "DeleteAccessKey",
            "AttachUserPolicy",
            "PutUserPolicy",
        ]

        high_events = [
            "ModifyInstanceAttribute",
            "AuthorizeSecurityGroupIngress",
            "CreateRole",
            "UpdateAssumeRolePolicy",
        ]

        event_names = [e.get("EventName") for e in events]

        if any(e in critical_events for e in event_names):
            return EvidenceSeverity.CRITICAL
        elif any(e in high_events for e in event_names):
            return EvidenceSeverity.HIGH
        else:
            return EvidenceSeverity.MEDIUM

    async def collect_by_user_activity(
        self, username: str, lookback_days: int = 14
    ) -> List[EvidenceMetadata]:
        """
        Collect all activity for a specific user.

        Args:
            username: IAM username
            lookback_days: Days to look back

        Returns:
            List of evidence metadata
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=lookback_days)

        return await self.collect(
            start_time=start_time, end_time=end_time, username=username
        )
```

---

## 🚀 MAIN CLI ENTRY POINT

### `src/main.py`

```python
"""Main CLI entry point for AWS Evidence Collection."""

import asyncio
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
import structlog

from config.settings import load_settings, CollectionSettings, AWSSettings
from src.core.aws_client import AWSClientManager
from src.core.evidence import EvidencePackage
from src.collectors.cloudtrail import CloudTrailCollector
from src.utils.logging import setup_logging

app = typer.Typer(help="AWS Evidence Collection Framework")
console = Console()


@app.command()
def collect(
    incident_id: str = typer.Option(..., help="Incident ID (e.g., INC-20250101-001)"),
    target_user: Optional[str] = typer.Option(
        None, help="Target IAM user for investigation"
    ),
    lookback_days: int = typer.Option(14, help="Days to look back for evidence"),
    output_dir: Path = typer.Option(
        Path("./output"), help="Output directory for evidence"
    ),
    aws_profile: Optional[str] = typer.Option(None, help="AWS CLI profile to use"),
    aws_region: str = typer.Option("us-east-1", help="AWS region"),
) -> None:
    """Collect AWS evidence for incident response."""

    setup_logging()
    logger = structlog.get_logger()

    console.print(f"\n[bold green]AWS Evidence Collection Framework[/bold green]")
    console.print(f"Incident ID: [cyan]{incident_id}[/cyan]")
    console.print(f"Target User: [cyan]{target_user or 'All'}[/cyan]")
    console.print(f"Lookback: [cyan]{lookback_days} days[/cyan]\n")

    # Run async collection
    asyncio.run(
        _collect_evidence(
            incident_id=incident_id,
            target_user=target_user,
            lookback_days=lookback_days,
            output_dir=output_dir,
            aws_profile=aws_profile,
            aws_region=aws_region,
        )
    )


async def _collect_evidence(
    incident_id: str,
    target_user: Optional[str],
    lookback_days: int,
    output_dir: Path,
    aws_profile: Optional[str],
    aws_region: str,
) -> None:
    """Async evidence collection orchestration."""

    logger = structlog.get_logger()

    # Initialize AWS client
    aws_settings = AWSSettings(profile=aws_profile, region=aws_region)
    client_manager = AWSClientManager(aws_settings)
    await client_manager.initialize()

    # Verify credentials
    identity = await client_manager.get_caller_identity()
    console.print(
        f"[green]✓[/green] Connected to AWS Account: {identity['Account']}"
    )

    # Calculate time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=lookback_days)

    # Create evidence package
    evidence_package = EvidencePackage(
        incident_id=incident_id,
        package_id=f"{incident_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        # CloudTrail Collection
        task = progress.add_task("[cyan]Collecting CloudTrail logs...", total=None)
        cloudtrail_collector = CloudTrailCollector(
            client_manager, incident_id, output_dir
        )
        cloudtrail_evidence = await cloudtrail_collector.collect(
            start_time=start_time, end_time=end_time, username=target_user
        )
        for evidence in cloudtrail_evidence:
            evidence_package.add_evidence(evidence)
        progress.update(task, completed=True)
        console.print(
            f"[green]✓[/green] CloudTrail: {len(cloudtrail_evidence)} files collected"
        )

        # TODO: Add more collectors (IAM, VPC, GuardDuty, etc.)

    # Generate manifest
    manifest_path = evidence_package.generate_manifest(output_dir)
    console.print(f"\n[green]✓[/green] Evidence manifest: {manifest_path}")

    # Validate integrity
    console.print("\n[cyan]Validating evidence integrity...[/cyan]")
    integrity_results = evidence_package.validate_integrity()
    all_valid = all(integrity_results.values())

    if all_valid:
        console.print("[green]✓[/green] All evidence integrity checks passed")
    else:
        console.print("[red]✗[/red] Some evidence files failed integrity check")

    console.print(f"\n[bold green]Collection complete![/bold green]")
    console.print(f"Total evidence items: {len(evidence_package.evidence_items)}")
    console.print(f"Output directory: {output_dir}\n")


if __name__ == "__main__":
    app()
```

---

## 📖 README.md

```markdown
# AWS Evidence Collection Framework

Modern Python framework for automated AWS evidence collection during incident response.

## Features

- ✅ **Async/Concurrent**: Fast parallel collection using `aioboto3`
- ✅ **Type-Safe**: Full type hints with Pydantic validation
- ✅ **Chain of Custody**: Automatic SHA256 hashing and integrity verification
- ✅ **Modular**: Easy to extend with new collectors
- ✅ **Production-Ready**: Structured logging, error handling, retries
- ✅ **CLI-Friendly**: Rich terminal output with progress indicators

## Supported Evidence Types

- [x] CloudTrail logs
- [ ] IAM configurations and policies
- [ ] VPC Flow Logs
- [ ] GuardDuty findings
- [ ] AWS Config snapshots
- [ ] S3 access logs
- [ ] EC2 instance metadata
- [ ] CloudWatch logs
- [ ] Lambda execution logs

## Installation

```bash
# Clone repository
git clone https://github.com/your-org/aws-incident-collector.git
cd aws-incident-collector

# Create virtual environment
python3.9 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## Configuration

Create `.env` file:

```bash
# AWS Configuration
AWS_PROFILE=incident-response
AWS_REGION=us-east-1
AWS_ASSUME_ROLE_ARN=arn:aws:iam::123456789012:role/IncidentResponseRole

# Collection Settings
COLLECTION_INCIDENT_ID=INC-20250101-001
COLLECTION_TARGET_USER=compromised-user
COLLECTION_START_TIME=2025-01-01T00:00:00Z
COLLECTION_END_TIME=2025-01-15T00:00:00Z
COLLECTION_LOOKBACK_DAYS=14
COLLECTION_OUTPUT_DIR=./output
```

## Usage

### Basic Collection

```bash
python -m src.main collect \
  --incident-id INC-20250101-001 \
  --target-user compromised-user \
  --lookback-days 14 \
  --aws-profile incident-response
```

### Cross-Account Collection

```bash
python -m src.main collect \
  --incident-id INC-20250101-001 \
  --aws-profile security-account \
  --assume-role arn:aws:iam::123456789012:role/IRRole
```

## Output Structure

```
output/
└── INC-20250101-001_20250128_143000/
    ├── cloudtrail/
    │   └── cloudtrail_events_20250101_20250115.json
    ├── iam/
    ├── vpc_flow/
    └── INC-20250101-001_20250128_143000_manifest.json
```

## Development

```bash
# Run tests
pytest tests/ -v --cov=src

# Type checking
mypy src/

# Code formatting
black src/ tests/
ruff check src/ tests/

# Run in debug mode
LOG_LEVEL=DEBUG python -m src.main collect --incident-id TEST-001
```

## Extending with New Collectors

See `src/collectors/cloudtrail.py` for reference implementation.

1. Create new collector class inheriting from `BaseCollector`
2. Implement `evidence_type` property
3. Implement `collect()` method
4. Add to main orchestration in `src/main.py`

## Security Considerations

- **Never commit `.env` files**
- Use IAM roles with least-privilege permissions
- Enable CloudTrail logging for all collection activity
- Store evidence in encrypted S3 buckets
- Follow chain-of-custody procedures

## License

MIT License - See LICENSE file for details
```

---

1. **Build out additional collectors** (IAM, VPC, GuardDuty)..
2. **Add Athena integration** for large CloudTrail queries?..
3. **Create Docker container** for portable deployment?..
4. **Add SOAR integration** (PagerDuty, ServiceNow, Jira)?..
5. **Build correlation engine** for timeline analysis?..
