#!/usr/bin/env python3
"""
MCP-K8S-PROBE v0.5

Passive Kubernetes assessor for identifying MCP-style agentic infrastructure
using structural, behavioral, and topology-aligned heuristics.

Security Guarantees:
    - Read-only Kubernetes API usage
    - No secret value extraction
    - No pod exec
    - No mutation of cluster state
    - Namespace-scoped by default
    - Deterministic scoring logic
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
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MCPRole(str, Enum):
    UNKNOWN = "UNKNOWN"
    GATEWAY = "GATEWAY"
    TOOL_SERVER = "TOOL_SERVER"
    AGENT_WORKER = "AGENT_WORKER"
    LLM_RUNTIME = "LLM_RUNTIME"


@dataclass(frozen=True)
class Finding:
    title: str
    severity: Severity
    namespace: Optional[str]
    resource: Optional[str]
    description: str
    role: MCPRole = MCPRole.UNKNOWN
    score: int = 0
    evidence: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProbeConfig:
    namespace_scope: Optional[List[str]]
    cluster_wide: bool
    verbose: bool
    output_json: bool


@dataclass
class WorkloadAssessment:
    namespace: str
    name: str
    total_score: int = 0
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
        self.total_score = sum(self.role_scores.values())
        best_role = MCPRole.UNKNOWN
        best_score = 0

        for role, score in self.role_scores.items():
            if score > best_score:
                best_role = role
                best_score = score

        if best_score > 0:
            self.inferred_role = best_role


class K8sProbeContext:
    """
    Encapsulates Kubernetes clients and safe namespace resolution.
    """

    def __init__(self, cfg: ProbeConfig) -> None:
        self.config = cfg
        self.logger = logging.getLogger("mcp_k8s_probe")
        self.core_api: Optional[client.CoreV1Api] = None
        self.apps_api: Optional[client.AppsV1Api] = None

    def initialize(self) -> None:
        try:
            config.load_incluster_config()
            self.logger.info("Using in-cluster Kubernetes configuration")
        except config.ConfigException:
            config.load_kube_config()
            self.logger.info("Using local kubeconfig")

        self.core_api = client.CoreV1Api()
        self.apps_api = client.AppsV1Api()

    def get_namespaces(self) -> List[str]:
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
    Advanced heuristic MCP topology detection with capped evidence scoring.
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
                                f"Score={assessment.total_score}"
                            ),
                            role=assessment.inferred_role,
                            score=assessment.total_score,
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
                                "Workload appears to expose MCP gateway-like behavior. "
                                "Validate authentication, ingress policy, and network exposure."
                            ),
                            role=assessment.inferred_role,
                            score=assessment.total_score,
                            evidence=sorted(assessment.evidence),
                        )
                    )

        return findings

    def _safe_list_deployments(self, namespace: str) -> List[V1Deployment]:
        if not self.ctx.apps_api:
            return []
        try:
            return self.ctx.apps_api.list_namespaced_deployment(namespace).items
        except ApiException as exc:
            self.logger.warning("Failed to list deployments in %s: %s", namespace, exc)
            return []

    def _safe_list_services(self, namespace: str) -> List[V1Service]:
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
        name = deploy.metadata.name if deploy.metadata and deploy.metadata.name else "unknown"
        assessment = WorkloadAssessment(namespace=namespace, name=name)

        self._score_name(deploy, assessment)
        self._score_containers(deploy, assessment)
        self._score_services(deploy, services, assessment)

        return assessment

    def _score_name(self, deploy: V1Deployment, assessment: WorkloadAssessment) -> None:
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
        template_spec = deploy.spec.template.spec if deploy.spec and deploy.spec.template else None
        if not template_spec or not template_spec.containers:
            return

        port_matches = 0
        env_matches = 0
        resource_matches = 0

        for container in template_spec.containers:
            port_matches += self._score_container_ports(container, assessment, remaining=self.PORT_CAP - port_matches)
            env_matches += self._score_container_env(container, assessment, remaining=self.ENV_CAP - env_matches)
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
        if not svc.spec or not svc.spec.selector:
            return False
        return all(pod_labels.get(key) == value for key, value in svc.spec.selector.items())


class ProbeEngine:
    def __init__(self, ctx: K8sProbeContext) -> None:
        self.ctx = ctx
        self.discovery = MCPDiscoveryModule(ctx)

    def run(self) -> List[Finding]:
        self.ctx.logger.info("Running module: mcp-discovery")
        try:
            return self.discovery.run()
        except Exception as exc:
            self.ctx.logger.error("Discovery module failed safely: %s", exc)
            return []


def parse_k8s_cpu(value: object) -> Optional[float]:
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
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    binary_units = {
        "Ki": 1024,
        "Mi": 1024 ** 2,
        "Gi": 1024 ** 3,
        "Ti": 1024 ** 4,
        "Pi": 1024 ** 5,
        "Ei": 1024 ** 6,
    }
    decimal_units = {
        "K": 1000,
        "M": 1000 ** 2,
        "G": 1000 ** 3,
        "T": 1000 ** 4,
        "P": 1000 ** 5,
        "E": 1000 ** 6,
    }

    for unit, factor in binary_units.items():
        if raw.endswith(unit):
            try:
                return int(float(raw[:-len(unit)]) * factor)
            except ValueError:
                return None

    for unit, factor in decimal_units.items():
        if raw.endswith(unit):
            try:
                return int(float(raw[:-len(unit)]) * factor)
            except ValueError:
                return None

    try:
        return int(float(raw))
    except ValueError:
        return None


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s | %(message)s")


def findings_to_json(findings: Iterable[Finding]) -> str:
    payload = []
    for finding in findings:
        item = asdict(finding)
        item["severity"] = finding.severity.value
        item["role"] = finding.role.value
        payload.append(item)
    return json.dumps(payload, indent=2, sort_keys=True)


def print_text_results(findings: List[Finding]) -> None:
    print("MCP-K8S-PROBE RESULTS")
    print(f"Total Findings: {len(findings)}")

    for finding in findings:
        print(
            f"[{finding.severity.value}] {finding.title} "
            f"(namespace={finding.namespace}, resource={finding.resource}, "
            f"role={finding.role.value}, score={finding.score})"
        )
        print(f"  {finding.description}")
        if finding.evidence:
            print(f"  Evidence: {', '.join(finding.evidence)}")


def build_parser() -> argparse.ArgumentParser:
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
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)

    cfg = ProbeConfig(
        namespace_scope=args.namespace,
        cluster_wide=args.cluster_wide,
        verbose=args.verbose,
        output_json=args.json,
    )

    ctx = K8sProbeContext(cfg)

    try:
        ctx.initialize()
    except Exception as exc:
        logging.getLogger("mcp_k8s_probe").error("Failed to initialize Kubernetes client: %s", exc)
        sys.exit(1)

    engine = ProbeEngine(ctx)
    findings = engine.run()

    if cfg.output_json:
        print(findings_to_json(findings))
    else:
        print_text_results(findings)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
