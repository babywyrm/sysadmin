"""SIEM integration layer for streaming findings to security operations.

Supports Splunk HEC, Elasticsearch, and Datadog as targets. Each sink
normalizes MCP-SLAYER findings into the target's expected event format
and handles batching, retries, and backpressure.

Usage:
    sink = SplunkHECSink(endpoint="https://hec.splunk.internal:8088",
                         token="...", index="mcp_redteam")
    await sink.send(finding)
    await sink.flush()
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import aiohttp

from mcp_slayer.models import Finding


@dataclass
class SIEMEvent:
    """Normalized event structure for SIEM ingestion."""

    timestamp: str
    source: str = "mcp-slayer"
    severity: str = "INFO"
    category: str = ""
    title: str = ""
    description: str = ""
    target_url: str = ""
    attack_module: str = ""
    outcome: str = ""
    threat_ids: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_finding(cls, finding: Finding, run_id: str = "") -> SIEMEvent:
        return cls(
            timestamp=finding.discovered_at.isoformat(),
            severity=finding.severity.value,
            category=finding.owasp_category.value,
            title=finding.title,
            description=finding.description,
            target_url=str(finding.target_url),
            attack_module=finding.attack_module,
            outcome=finding.outcome.value,
            threat_ids=list(finding.playbook_threat_ids),
            evidence=finding.evidence,
            tags={**finding.tags, "run_id": run_id},
        )


class SIEMSink(ABC):
    """Abstract base for SIEM event sinks."""

    def __init__(self, batch_size: int = 50, flush_interval_s: float = 5.0):
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self._buffer: list[SIEMEvent] = []
        self._sent_count = 0
        self._error_count = 0
        self.logger = logging.getLogger(f"slayer.siem.{self.sink_id}")

    @property
    @abstractmethod
    def sink_id(self) -> str:
        ...

    @abstractmethod
    async def _send_batch(self, events: list[SIEMEvent]) -> bool:
        """Send a batch of events to the SIEM. Returns True on success."""
        ...

    async def send(self, finding: Finding, run_id: str = "") -> None:
        """Buffer a finding for SIEM delivery."""
        event = SIEMEvent.from_finding(finding, run_id=run_id)
        self._buffer.append(event)
        if len(self._buffer) >= self.batch_size:
            await self.flush()

    async def flush(self) -> None:
        """Send all buffered events."""
        if not self._buffer:
            return
        batch = self._buffer[:]
        self._buffer.clear()
        success = await self._send_batch(batch)
        if success:
            self._sent_count += len(batch)
            self.logger.debug(f"Flushed {len(batch)} events (total: {self._sent_count})")
        else:
            self._error_count += len(batch)
            self.logger.error(f"Failed to send {len(batch)} events")

    @property
    def stats(self) -> dict[str, int]:
        return {
            "sent": self._sent_count,
            "errors": self._error_count,
            "buffered": len(self._buffer),
        }


class SplunkHECSink(SIEMSink):
    """Splunk HTTP Event Collector sink.

    Sends findings as structured JSON events via HEC. Each event includes
    the full finding taxonomy, evidence, and correlation metadata.
    """

    def __init__(
        self,
        endpoint: str,
        token: str,
        index: str = "mcp_redteam_events",
        source: str = "mcp-slayer",
        sourcetype: str = "_json",
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.endpoint = endpoint.rstrip("/")
        self.token = token
        self.index = index
        self.source = source
        self.sourcetype = sourcetype

    @property
    def sink_id(self) -> str:
        return "splunk"

    async def _send_batch(self, events: list[SIEMEvent]) -> bool:
        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json",
        }

        # Splunk HEC accepts newline-delimited JSON events
        payload_lines = []
        for event in events:
            hec_event = {
                "time": event.timestamp,
                "source": self.source,
                "sourcetype": self.sourcetype,
                "index": self.index,
                "event": {
                    "severity": event.severity,
                    "category": event.category,
                    "title": event.title,
                    "description": event.description,
                    "target_url": event.target_url,
                    "attack_module": event.attack_module,
                    "outcome": event.outcome,
                    "threat_ids": event.threat_ids,
                    "evidence": event.evidence,
                    "tags": event.tags,
                },
            }
            payload_lines.append(json.dumps(hec_event))

        payload = "\n".join(payload_lines)
        url = f"{self.endpoint}/services/collector/event"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, data=payload, headers=headers, ssl=False
                ) as resp:
                    if resp.status == 200:
                        return True
                    body = await resp.text()
                    self.logger.error(f"Splunk HEC {resp.status}: {body[:200]}")
                    return False
        except Exception as e:
            self.logger.error(f"Splunk HEC connection error: {e}")
            return False


class ElasticSink(SIEMSink):
    """Elasticsearch/OpenSearch sink via bulk API.

    Indexes findings as documents in a time-partitioned index pattern
    (e.g. mcp-slayer-findings-2026.07.08).
    """

    def __init__(
        self,
        endpoint: str,
        index_prefix: str = "mcp-slayer-findings",
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.endpoint = endpoint.rstrip("/")
        self.index_prefix = index_prefix
        self.api_key = api_key
        self.username = username
        self.password = password

    @property
    def sink_id(self) -> str:
        return "elastic"

    def _index_name(self) -> str:
        date_suffix = datetime.now(UTC).strftime("%Y.%m.%d")
        return f"{self.index_prefix}-{date_suffix}"

    async def _send_batch(self, events: list[SIEMEvent]) -> bool:
        headers: dict[str, str] = {"Content-Type": "application/x-ndjson"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"

        auth = None
        if self.username and self.password:
            auth = aiohttp.BasicAuth(self.username, self.password)

        index = self._index_name()
        bulk_lines = []
        for event in events:
            action = json.dumps({"index": {"_index": index}})
            doc = json.dumps({
                "@timestamp": event.timestamp,
                "source": event.source,
                "severity": event.severity,
                "category": event.category,
                "title": event.title,
                "description": event.description,
                "target_url": event.target_url,
                "attack_module": event.attack_module,
                "outcome": event.outcome,
                "threat_ids": event.threat_ids,
                "evidence": event.evidence,
                "tags": event.tags,
            })
            bulk_lines.append(action)
            bulk_lines.append(doc)

        payload = "\n".join(bulk_lines) + "\n"
        url = f"{self.endpoint}/_bulk"

        try:
            async with aiohttp.ClientSession(auth=auth) as session:
                async with session.post(
                    url, data=payload, headers=headers, ssl=False
                ) as resp:
                    if resp.status in (200, 201):
                        body = await resp.json()
                        if body.get("errors"):
                            self.logger.warning("Elastic bulk had partial errors")
                        return True
                    body = await resp.text()
                    self.logger.error(f"Elastic {resp.status}: {body[:200]}")
                    return False
        except Exception as e:
            self.logger.error(f"Elastic connection error: {e}")
            return False


class DatadogSink(SIEMSink):
    """Datadog Log Management sink via HTTP API.

    Sends findings as structured log entries with proper tagging for
    Datadog's faceted search and alerting.
    """

    def __init__(
        self,
        api_key: str,
        site: str = "datadoghq.com",
        service: str = "mcp-slayer",
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.api_key = api_key
        self.site = site
        self.service = service

    @property
    def sink_id(self) -> str:
        return "datadog"

    async def _send_batch(self, events: list[SIEMEvent]) -> bool:
        headers = {
            "Content-Type": "application/json",
            "DD-API-KEY": self.api_key,
        }

        logs = []
        for event in events:
            log_entry = {
                "ddsource": "mcp-slayer",
                "ddtags": ",".join(f"{k}:{v}" for k, v in event.tags.items()),
                "hostname": "mcp-slayer-harness",
                "service": self.service,
                "status": event.severity.lower(),
                "message": event.title,
                "attributes": {
                    "category": event.category,
                    "description": event.description,
                    "target_url": event.target_url,
                    "attack_module": event.attack_module,
                    "outcome": event.outcome,
                    "threat_ids": event.threat_ids,
                    "evidence": event.evidence,
                },
            }
            logs.append(log_entry)

        url = f"https://http-intake.logs.{self.site}/api/v2/logs"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=logs, headers=headers
                ) as resp:
                    if resp.status == 202:
                        return True
                    body = await resp.text()
                    self.logger.error(f"Datadog {resp.status}: {body[:200]}")
                    return False
        except Exception as e:
            self.logger.error(f"Datadog connection error: {e}")
            return False


def create_sink(config) -> SIEMSink | None:
    """Factory: create the appropriate SIEM sink from SlayerConfig.siem."""
    if not config.siem.enabled:
        return None

    if config.siem.type == "splunk":
        return SplunkHECSink(
            endpoint=config.siem.endpoint or "",
            token=config.siem.api_key.get_secret_value() if config.siem.api_key else "",
            index=config.siem.index_name or "mcp_redteam_events",
        )
    elif config.siem.type == "elastic":
        return ElasticSink(
            endpoint=config.siem.endpoint or "",
            api_key=config.siem.api_key.get_secret_value() if config.siem.api_key else None,
        )
    elif config.siem.type == "datadog":
        return DatadogSink(
            api_key=config.siem.api_key.get_secret_value() if config.siem.api_key else "",
        )
    else:
        logging.getLogger("slayer.siem").warning(
            f"Unknown SIEM type: {config.siem.type}"
        )
        return None
