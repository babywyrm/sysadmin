"""Purple team automation — bridging red findings to blue detection.

Provides SIEM integration for real-time finding streaming, detection
validation for measuring MTTD/MTTR, canary deployment and monitoring,
dashboard trending, and regression test generation from confirmed vulns.
"""

from mcp_slayer.purple.canary import (
    CanaryDeployer,
    CanaryMonitor,
    CanaryType,
    DeployedCanary,
)
from mcp_slayer.purple.dashboard import (
    DashboardStore,
    DrillSnapshot,
    TrendMetrics,
    format_dashboard,
)
from mcp_slayer.purple.detection import (
    DetectionCorrelator,
    DetectionResult,
    DetectionWindow,
)
from mcp_slayer.purple.regression import (
    RegressionCase,
    RegressionSuite,
)
from mcp_slayer.purple.siem import (
    DatadogSink,
    ElasticSink,
    SIEMEvent,
    SIEMSink,
    SplunkHECSink,
)

__all__ = [
    "CanaryDeployer",
    "CanaryMonitor",
    "CanaryType",
    "DashboardStore",
    "DatadogSink",
    "DeployedCanary",
    "DetectionCorrelator",
    "DetectionResult",
    "DetectionWindow",
    "DrillSnapshot",
    "ElasticSink",
    "RegressionCase",
    "RegressionSuite",
    "SIEMEvent",
    "SIEMSink",
    "SplunkHECSink",
    "TrendMetrics",
    "format_dashboard",
]
