"""Purple team automation — bridging red findings to blue detection.

Provides SIEM integration for real-time finding streaming, detection
validation for measuring MTTD/MTTR, and continuous regression testing
from confirmed vulnerabilities.
"""

from mcp_slayer.purple.siem import (
    DatadogSink,
    ElasticSink,
    SIEMEvent,
    SIEMSink,
    SplunkHECSink,
)
from mcp_slayer.purple.detection import (
    DetectionCorrelator,
    DetectionResult,
    DetectionWindow,
)

__all__ = [
    "DatadogSink",
    "DetectionCorrelator",
    "DetectionResult",
    "DetectionWindow",
    "ElasticSink",
    "SIEMEvent",
    "SIEMSink",
    "SplunkHECSink",
]
