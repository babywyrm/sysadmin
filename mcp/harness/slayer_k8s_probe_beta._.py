#!/usr/bin/env python3
"""
MCP-K8S-PROBE v0.7

Passive Kubernetes assessor for identifying MCP-style agentic infrastructure
using structural, behavioral, and topology-aligned heuristics.

This tool is intentionally conservative:
- read-only Kubernetes API usage
- no secret value extraction
- no pod exec
- no mutation of cluster state
- deterministic scoring logic
- namespace-scoped by default unless --cluster-wide is set

What it does:
- inspects Deployments and Services
- scores workloads using naming, port, environment, service, and resource hints
- infers likely MCP-oriented roles such as:
    * GATEWAY
    * TOOL_SERVER
    * AGENT_WORKER
    * LLM_RUNTIME

What it does not do:
- prove a workload is definitely "MCP"
- inspect runtime traffic
- exec into pods
- extract secret values
- modify cluster state

Examples:
    # Scan only the default namespace
    python3 mcp_k8s_probe.py

    # Scan one namespace
    python3 mcp_k8s_probe.py --namespace agents

    # Scan multiple namespaces
    python3 mcp_k8s_probe.py --namespace agents --namespace ai-platform

    # Scan all namespaces visible to your identity
    python3 mcp_k8s_probe.py --cluster-wide

    # Emit JSON findings
    python3 mcp_k8s_probe.py --cluster-wide --json

    # Show only stronger matches
    python3 mcp_k8s_probe.py --cluster-wide --min-score 5

    # Verbose logging + JSON + stricter output
    python3 mcp_k8s_probe.py --cluster-wide --json --min-score 6 -v
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import ClassVar, Dict, Iterable, List, Mapping, Optional, Set

from kubernetes import client, config
from kubernetes.client import ApiException
from kubernetes.client.models import V1Container, V1Deployment, V1Service


class Severity(str, Enum):
    """Severity assigned to findings."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MCPRole(str, Enum):
    """High-level workload roles inferred from accumulated evidence."""

    UNKNOWN = "UNKNOWN"
    GATEWAY = "GATEWAY"
    TOOL_SERVER = "TOOL_SERVER"
    AGENT_WORKER = "AGENT_WORKER"
    LLM_RUNTIME = "LLM_RUNTIME"


@dataclass(frozen=True)
class Finding:
    """
    Final user-facing finding.

    Attributes:
        title: Human-readable finding title.
        severity: Severity level for the finding.
        namespace: Namespace containing the resource.
        resource: Resource name, usually the Deployment name.
        description: Short summary of why the finding exists.
        role: Inferred workload role.
        score: Total heuristic score.
        confidence: Low/Medium/High confidence band derived from score.
        evidence: Individual evidence strings that explain the score.
    """

    title: str
    severity: Severity
    namespace: Optional[str]
    resource: Optional[str]
    description: str
    role: MCPRole = MCPRole.UNKNOWN
    score: int = 0
    confidence: str = "LOW"
    evidence: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProbeConfig:
    """
    Runtime configuration for the probe.

    Attributes:
        namespace_scope: Explicit namespaces to scan. If None, default is 'default'
            unless cluster_wide is enabled.
        cluster_wide: Whether to enumerate all visible namespaces.
        verbose: Enables verbose logging.
        output_json: Emits structured JSON instead of text output.
        min_score: Minimum finding score to emit.
    """

    namespace_scope: Optional[List[str]]
    cluster_wide: bool
    verbose: bool
    output_json: bool
    min_score: int


@dataclass
class WorkloadAssessment:
    """
    Internal scoring model for one Deployment.

    The tool gathers evidence into role-specific score buckets, then computes:
    - total score
    - best matching inferred role
    - confidence band

    This is intentionally simple and deterministic so results are explainable.
    """

    namespace: str
    name: str
    total_score: int = 0
    confidence: str = "LOW"
    evidence: Set[str] = field(default_factory=set)
    role_scores: Dict[MCPRole, int] = field(
        default_factory=lambda: {
            MCPRole.GATEWAY: 0,
            MCPRole.TOOL_SERVER: 0,
            MCPRole.AGENT_WORKER: 0,
            MCPRole.LLM_RUNTIME: 0,
        }
    )
    inferred_role: MCPRole = MCPRole.UNKNOWN

    def finalize(self) -> None:
        """
        Finalize the assessment after all scoring is complete.

        Chooses the highest-scoring role and derives a confidence band from the
        total score.

        Confidence bands:
            0-2   => LOW
            3-5   => MEDIUM
            6+    => HIGH
        """
        self.total_score = sum(self.role_scores.values())

        best_role = MCPRole.UNKNOWN
        best_score = 0
        for role, score in self.role_scores.items():
            if score > best_score:
                best_role = role
                best_score = score

        if best_score > 0:
            self.inferred_role = best_role

        if self.total_score >= 6:
            self.confidence = "HIGH"
        elif self.total_score >= 3:
            self.confidence = "MEDIUM"
        else:
            self.confidence = "LOW"


class K8sProbeContext:
    """
    Encapsulates Kubernetes clients and namespace resolution.

    Configuration loading behavior:
    - first tries in-cluster config
    - falls back to local kubeconfig

    Namespace selection behavior:
    - if --cluster-wide is used, list all visible namespaces
    - if --namespace is specified, scan only those namespaces
    - otherwise, default to ['default']
    """

    def __init__(self, cfg: ProbeConfig) -> None:
        self.config = cfg
        self.logger = logging.getLogger("mcp_k8s_probe")
        self.core_api: Optional[client.CoreV1Api] = None
        self.apps_api: Optional[client.AppsV1Api] = None

    def initialize(self) -> None:
        """
        Initialize Kubernetes API clients.

        This method does not mutate cluster state. It only establishes client
        access for read-only API usage.
        """
        try:
            config.load_incluster_config()
            self.logger.info("Using in-cluster Kubernetes configuration")
        except config.ConfigException:
            config.load_kube_config()
            self.logger.info("Using local kubeconfig")

        self.core_api = client.CoreV1Api()
        self.apps_api = client.AppsV1Api()

    def get_namespaces(self) -> List[str]:
        """
        Resolve the namespaces to scan.

        Returns:
            A sorted list of namespaces.

        Notes:
            - If cluster-wide enumeration fails, an empty list is returned safely.
            - If no namespace is specified, 'default' is used.
        """
        if self.config.cluster_wide and self.core_api:
            try:
                namespaces = self.core_api.list_namespace().items
                return sorted(
                    ns.metadata.name
                    for ns in namespaces
                    if ns.metadata and ns.metadata.name
                )
            except ApiException as exc:
                self.logger.warning("Failed to list namespaces: %s", exc)
                return []

        if self.config.namespace_scope:
            return sorted(set(self.config.namespace_scope))

        self.logger.info("No namespace specified; scanning default namespace only")
        return ["default"]


class MCPDiscoveryModule:
    """
    Heuristic discovery module for possible MCP-style workloads.

    Evidence categories:
    - workload naming hints
    - container ports
    - environment variable names
    - resource requests
    - service exposure type

    Category caps are used to reduce false positives caused by any one signal
    type dominating the score.
    """

    NAME_HINTS: ClassVar[Set[str]] = {
        "mcp",
        "agent",
        "gateway",
        "tool",
        "llm",
        "orchestrator",
        "model",
        "inference",
        "worker",
    }

    PORT_ROLE_HINTS: ClassVar[Dict[int, MCPRole]] = {
        8080: MCPRole.GATEWAY,
        8000: MCPRole.GATEWAY,
        5000: MCPRole.TOOL_SERVER,
        7000: MCPRole.AGENT_WORKER,
        9000: MCPRole.TOOL_SERVER,
        11434: MCPRole.LLM_RUNTIME,
    }

    ENV_ROLE_HINTS: ClassVar[Dict[str, MCPRole]] = {
        "MCP": MCPRole.GATEWAY,
        "AGENT": MCPRole.AGENT_WORKER,
        "TOOL": MCPRole.TOOL_SERVER,
        "MODEL": MCPRole.LLM_RUNTIME,
        "OPENAI": MCPRole.LLM_RUNTIME,
        "OLLAMA": MCPRole.LLM_RUNTIME,
        "LLM": MCPRole.LLM_RUNTIME,
    }

    NAME_CAP: ClassVar[int] = 2
    PORT_CAP: ClassVar[int] = 2
    ENV_CAP: ClassVar[int] = 2
    RESOURCE_CAP: ClassVar[int] = 2
    SERVICE_CAP: ClassVar[int] = 2

    def __init__(self, ctx: K8sProbeContext) -> None:
        self.ctx = ctx
        self.logger = logging.getLogger("mcp_k8s_probe.discovery")

    def run(self) -> List[Finding]:
        """
        Execute heuristic discovery across the selected namespaces.

        Returns:
            A list of findings.

        Findings are emitted only after a minimum evidence threshold is met.
        """
        findings: List[Finding] = []

        for namespace in self.ctx.get_namespaces():
            deployments = self._safe_list_deployments(namespace)
            services = self._safe_list_services(namespace)

            for deploy in deployments:
                assessment = self._assess_deployment(namespace, deploy, services)
                assessment.finalize()

                if assessment.total_score >= 3:
                    findings.append(
                        Finding(
                            title="Probable MCP Workload Detected",
                            severity=Severity.INFO,
                            namespace=namespace,
                            resource=assessment.name,
                            description=(
                                f"Role={assessment.inferred_role.value} "
                                f"Score={assessment.total_score} "
                                f"Confidence={assessment.confidence}"
                            ),
                            role=assessment.inferred_role,
                            score=assessment.total_score,
                            confidence=assessment.confidence,
                            evidence=sorted(assessment.evidence),
                        )
                    )

                if assessment.inferred_role == MCPRole.GATEWAY and assessment.total_score >= 4:
                    findings.append(
                        Finding(
                            title="MCP Gateway Exposure Pattern",
                            severity=Severity.MEDIUM,
                            namespace=namespace,
                            resource=assessment.name,
                            description=(
                                "Workload appears to expose gateway-like behavior. "
                                "Validate authentication, ingress policy, and network exposure."
                            ),
                            role=assessment.inferred_role,
                            score=assessment.total_score,
                            confidence=assessment.confidence,
                            evidence=sorted(assessment.evidence),
                        )
                    )

        return findings

    def _safe_list_deployments(self, namespace: str) -> List[V1Deployment]:
        """
        Safely list Deployments in a namespace.

        Returns:
            Deployment objects on success, or an empty list on failure.
        """
        if not self.ctx.apps_api:
            return []
        try:
            return self.ctx.apps_api.list_namespaced_deployment(namespace).items
        except ApiException as exc:
            self.logger.warning("Failed to list deployments in %s: %s", namespace, exc)
            return []

    def _safe_list_services(self, namespace: str) -> List[V1Service]:
        """
        Safely list Services in a namespace.

        Returns:
            Service objects on success, or an empty list on failure.
        """
        if not self.ctx.core_api:
            return []
        try:
            return self.ctx.core_api.list_namespaced_service(namespace).items
        except ApiException as exc:
            self.logger.warning("Failed to list services in %s: %s", namespace, exc)
            return []

    def _assess_deployment(
        self,
        namespace: str,
        deploy: V1Deployment,
        services: List[V1Service],
    ) -> WorkloadAssessment:
        """
        Build a heuristic assessment for a single Deployment.

        Scoring sources:
        - deployment name
        - container ports
        - env var names
        - requested CPU/memory
        - matching Services
        """
        name = deploy.metadata.name if deploy.metadata and deploy.metadata.name else "unknown"
        assessment = WorkloadAssessment(namespace=namespace, name=name)

        self._score_name(deploy, assessment)
        self._score_containers(deploy, assessment)
        self._score_services(deploy, services, assessment)

        return assessment

    def _score_name(self, deploy: V1Deployment, assessment: WorkloadAssessment) -> None:
        """
        Score the Deployment name against known MCP-adjacent terms.

        This is intentionally capped to avoid over-weighting creative naming.
        """
        name = deploy.metadata.name if deploy.metadata and deploy.metadata.name else ""
        name_lower = name.lower()
        matches = 0

        for hint in sorted(self.NAME_HINTS):
            if hint in name_lower:
                matches += 1
                assessment.evidence.add(f"name:{hint}")

                if hint in {"gateway", "mcp"}:
                    assessment.role_scores[MCPRole.GATEWAY] += 1
                elif hint in {"tool"}:
                    assessment.role_scores[MCPRole.TOOL_SERVER] += 1
                elif hint in {"agent", "worker", "orchestrator"}:
                    assessment.role_scores[MCPRole.AGENT_WORKER] += 1
                elif hint in {"llm", "model", "inference"}:
                    assessment.role_scores[MCPRole.LLM_RUNTIME] += 1

                if matches >= self.NAME_CAP:
                    break

    def _score_containers(self, deploy: V1Deployment, assessment: WorkloadAssessment) -> None:
        """
        Score all containers in the Deployment pod template.

        Category caps are shared across all containers in the workload.
        """
        template_spec = deploy.spec.template.spec if deploy.spec and deploy.spec.template else None
        if not template_spec or not template_spec.containers:
            return

        port_matches = 0
        env_matches = 0
        resource_matches = 0

        for container in template_spec.containers:
            port_matches += self._score_container_ports(
                container,
                assessment,
                remaining=self.PORT_CAP - port_matches,
            )
            env_matches += self._score_container_env(
                container,
                assessment,
                remaining=self.ENV_CAP - env_matches,
            )
            resource_matches += self._score_container_resources(
                container,
                assessment,
                remaining=self.RESOURCE_CAP - resource_matches,
            )

            if (
                port_matches >= self.PORT_CAP
                and env_matches >= self.ENV_CAP
                and resource_matches >= self.RESOURCE_CAP
            ):
                break

    def _score_container_ports(
        self,
        container: V1Container,
        assessment: WorkloadAssessment,
        remaining: int,
    ) -> int:
        """
        Score container ports against known role-aligned hints.

        Args:
            container: Kubernetes container object.
            assessment: Current workload assessment.
            remaining: Remaining port matches allowed under the category cap.

        Returns:
            Number of matched port signals added during this call.
        """
        if remaining <= 0 or not container.ports:
            return 0

        matched = 0
        seen_ports: Set[int] = set()

        for port_obj in container.ports:
            port = getattr(port_obj, "container_port", None)
            if port is None or port in seen_ports:
                continue
            seen_ports.add(port)

            role = self.PORT_ROLE_HINTS.get(port)
            if role:
                assessment.role_scores[role] += 1
                assessment.evidence.add(f"port:{port}")
                matched += 1
                if matched >= remaining:
                    break

        return matched

    def _score_container_env(
        self,
        container: V1Container,
        assessment: WorkloadAssessment,
        remaining: int,
    ) -> int:
        """
        Score environment variable names for MCP-adjacent terms.

        Only variable names are inspected. Values are not read or extracted.
        """
        if remaining <= 0 or not container.env:
            return 0

        matched = 0
        seen_hints: Set[str] = set()

        for env_var in container.env:
            env_name = getattr(env_var, "name", "") or ""
            upper_name = env_name.upper()

            for hint, role in self.ENV_ROLE_HINTS.items():
                if hint in upper_name and hint not in seen_hints:
                    seen_hints.add(hint)
                    assessment.role_scores[role] += 1
                    assessment.evidence.add(f"env:{hint}")
                    matched += 1
                    break

            if matched >= remaining:
                break

        return matched

    def _score_container_resources(
        self,
        container: V1Container,
        assessment: WorkloadAssessment,
        remaining: int,
    ) -> int:
        """
        Score CPU and memory request sizes.

        Current interpretation:
        - memory >= 2Gi may indicate model-serving or heavier AI runtimes
        - cpu >= 1 may indicate a more substantial runtime footprint

        Returns:
            Number of matched resource signals added during this call.
        """
        if remaining <= 0:
            return 0

        resources = container.resources
        if not resources or not resources.requests:
            return 0

        matched = 0
        memory_raw = resources.requests.get("memory")
        cpu_raw = resources.requests.get("cpu")

        mem_bytes = parse_k8s_memory(memory_raw) if memory_raw else None
        cpu_cores = parse_k8s_cpu(cpu_raw) if cpu_raw else None

        if mem_bytes is not None and mem_bytes >= 2 * 1024 * 1024 * 1024:
            assessment.role_scores[MCPRole.LLM_RUNTIME] += 1
            assessment.evidence.add("memory:>=2Gi")
            matched += 1

        if matched < remaining and cpu_cores is not None and cpu_cores >= 1.0:
            assessment.role_scores[MCPRole.LLM_RUNTIME] += 1
            assessment.evidence.add("cpu:>=1")
            matched += 1

        return matched

    def _score_services(
        self,
        deploy: V1Deployment,
        services: List[V1Service],
        assessment: WorkloadAssessment,
    ) -> None:
        """
        Score Services that target the Deployment's pod template labels.

        Heuristic interpretation:
        - LoadBalancer / NodePort suggest external exposure and therefore a
          stronger gateway signal
        - ClusterIP may suggest an internal tool or service role
        """
        template_labels = (
            deploy.spec.template.metadata.labels
            if deploy.spec and deploy.spec.template and deploy.spec.template.metadata
            else None
        )
        if not template_labels:
            return

        matched = 0
        for svc in services:
            if matched >= self.SERVICE_CAP:
                break

            if not self._service_targets_labels(svc, template_labels):
                continue

            svc_type = svc.spec.type if svc.spec and svc.spec.type else "ClusterIP"
            svc_name = svc.metadata.name if svc.metadata and svc.metadata.name else "unknown"

            if svc_type in {"LoadBalancer", "NodePort"}:
                assessment.role_scores[MCPRole.GATEWAY] += 2
                assessment.evidence.add(f"service:{svc_type}:{svc_name}")
                matched += 1
            elif svc_type == "ClusterIP":
                assessment.role_scores[MCPRole.TOOL_SERVER] += 1
                assessment.evidence.add(f"service:ClusterIP:{svc_name}")
                matched += 1

    @staticmethod
    def _service_targets_labels(
        svc: V1Service,
        pod_labels: Mapping[str, str],
    ) -> bool:
        """
        Determine whether a Service selector matches pod template labels.

        Returns:
            True if every selector key/value pair is present in pod_labels.
        """
        if not svc.spec or not svc.spec.selector:
            return False
        return all(pod_labels.get(key) == value for key, value in svc.spec.selector.items())


class ProbeEngine:
    """
    Minimal engine wrapper for executing probe modules.

    Kept intentionally small for single-file maintainability.
    """

    def __init__(self, ctx: K8sProbeContext) -> None:
        self.ctx = ctx
        self.discovery = MCPDiscoveryModule(ctx)

    def run(self) -> List[Finding]:
        """
        Run the discovery module and fail safely.

        Returns:
            A list of findings, or an empty list if the module fails.
        """
        self.ctx.logger.info("Running module: mcp-discovery")
        try:
            return self.discovery.run()
        except Exception as exc:
            self.ctx.logger.error("Discovery module failed safely: %s", exc)
            return []


def parse_k8s_cpu(value: object) -> Optional[float]:
    """
    Parse a Kubernetes CPU quantity into cores.

    Supported examples:
        "250m" -> 0.25
        "500m" -> 0.5
        "1"    -> 1.0
        "2"    -> 2.0

    Returns:
        CPU in cores as a float, or None if parsing fails.
    """
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    try:
        if raw.endswith("m"):
            return float(raw[:-1]) / 1000.0
        return float(raw)
    except ValueError:
        return None


def parse_k8s_memory(value: object) -> Optional[int]:
    """
    Parse a Kubernetes memory quantity into bytes.

    Supported examples:
        "512Mi" -> 536870912
        "2Gi"   -> 2147483648
        "1G"    -> 1000000000
        "4096"  -> 4096

    Returns:
        Memory in bytes as an int, or None if parsing fails.
    """
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    binary_units = {
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "Pi": 1024**5,
        "Ei": 1024**6,
    }
    decimal_units = {
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
        "P": 1000**5,
        "E": 1000**6,
    }

    for unit, factor in binary_units.items():
        if raw.endswith(unit):
            try:
                return int(float(raw[: -len(unit)]) * factor)
            except ValueError:
                return None

    for unit, factor in decimal_units.items():
        if raw.endswith(unit):
            try:
                return int(float(raw[: -len(unit)]) * factor)
            except ValueError:
                return None

    try:
        return int(float(raw))
    except ValueError:
        return None


def filter_findings(findings: Iterable[Finding], min_score: int) -> List[Finding]:
    """
    Filter findings by minimum score.

    Args:
        findings: Findings to evaluate.
        min_score: Minimum score required for a finding to be emitted.

    Returns:
        Filtered findings list.
    """
    return [finding for finding in findings if finding.score >= min_score]


def setup_logging(verbose: bool) -> None:
    """
    Configure process-wide logging.

    Args:
        verbose: If True, use DEBUG logging. Otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s | %(message)s")


def findings_to_json(findings: Iterable[Finding]) -> str:
    """
    Convert findings into pretty-printed JSON.

    Enum fields are normalized to their string values for operator-friendly
    output and easy downstream parsing.
    """
    payload = []
    for finding in findings:
        item = asdict(finding)
        item["severity"] = finding.severity.value
        item["role"] = finding.role.value
        payload.append(item)
    return json.dumps(payload, indent=2, sort_keys=True)


def print_text_results(findings: List[Finding]) -> None:
    """
    Render findings in human-readable text form.
    """
    print("MCP-K8S-PROBE RESULTS")
    print(f"Total Findings: {len(findings)}")

    for finding in findings:
        print(
            f"[{finding.severity.value}] {finding.title} "
            f"(namespace={finding.namespace}, resource={finding.resource}, "
            f"role={finding.role.value}, score={finding.score}, "
            f"confidence={finding.confidence})"
        )
        print(f"  {finding.description}")
        if finding.evidence:
            print(f"  Evidence: {', '.join(finding.evidence)}")


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line argument parser.

    Supported usage patterns:
        python3 mcp_k8s_probe.py
        python3 mcp_k8s_probe.py --namespace agents
        python3 mcp_k8s_probe.py --cluster-wide --json
        python3 mcp_k8s_probe.py --cluster-wide --min-score 5 -v
    """
    parser = argparse.ArgumentParser(
        description="Passive MCP Kubernetes Assessment Tool"
    )
    parser.add_argument(
        "--namespace",
        action="append",
        help="Namespace to scan. Repeatable.",
    )
    parser.add_argument(
        "--cluster-wide",
        action="store_true",
        help="Scan all namespaces visible to the current identity.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as JSON.",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=3,
        help="Minimum score required to emit a finding. Default: 3.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    return parser


def main() -> None:
    """
    Main entrypoint.

    Initialization flow:
    1. Parse CLI arguments
    2. Configure logging
    3. Initialize Kubernetes clients
    4. Run the probe engine
    5. Filter findings by minimum score
    6. Emit text or JSON output
    """
    parser = build_parser()
    args = parser.parse_args()

    if args.min_score < 0:
        parser.error("--min-score must be >= 0")

    setup_logging(args.verbose)

    cfg = ProbeConfig(
        namespace_scope=args.namespace,
        cluster_wide=args.cluster_wide,
        verbose=args.verbose,
        output_json=args.json,
        min_score=args.min_score,
    )

    ctx = K8sProbeContext(cfg)

    try:
        ctx.initialize()
    except Exception as exc:
        logging.getLogger("mcp_k8s_probe").error(
            "Failed to initialize Kubernetes client: %s", exc
        )
        sys.exit(1)

    engine = ProbeEngine(ctx)
    findings = engine.run()
    findings = filter_findings(findings, cfg.min_score)

    if cfg.output_json:
        print(findings_to_json(findings))
    else:
        print_text_results(findings)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
