#!/usr/bin/env python3
"""
MCP-K8S-PROBE v0.4 ..beta..

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
import asyncio
import logging
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar, Dict, List, Optional, Set

from kubernetes import client, config
from kubernetes.client import ApiException
from kubernetes.client.models import (
    V1Container,
    V1Deployment,
    V1Service,
)


# ============================================================================
# ENUMS & DATA MODELS
# ============================================================================


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


@dataclass(frozen=True)
class ProbeConfig:
    namespace_scope: Optional[List[str]]
    cluster_wide: bool
    verbose: bool


@dataclass
class MCPWorkloadSignals:
    namespace: str
    name: str
    score: int = 0
    signals: Set[str] = field(default_factory=set)
    inferred_role: MCPRole = MCPRole.UNKNOWN


# ============================================================================
# CONTEXT
# ============================================================================


class K8sProbeContext:
    """
    Encapsulates Kubernetes clients and safe namespace resolution.
    """

    def __init__(self, cfg: ProbeConfig) -> None:
        self.config = cfg
        self.logger = logging.getLogger("mcp_k8s_probe")

        self.core_api: Optional[client.CoreV1Api] = None
        self.apps_api: Optional[client.AppsV1Api] = None

    async def initialize(self) -> None:
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
                return [ns.metadata.name for ns in namespaces]
            except ApiException:
                return []

        if self.config.namespace_scope:
            return self.config.namespace_scope

        return ["default"]


# ============================================================================
# BASE MODULE
# ============================================================================


class ClusterModule(ABC):
    id: ClassVar[str]
    description: ClassVar[str]

    def __init__(self, ctx: K8sProbeContext) -> None:
        self.ctx = ctx
        self.logger = logging.getLogger(f"mcp_k8s_probe.{self.id}")

    @abstractmethod
    async def run(self) -> List[Finding]:
        ...


# ============================================================================
# ADVANCED MCP DISCOVERY MODULE
# ============================================================================


class MCPDiscoveryModule(ClusterModule):
    """
    Advanced heuristic MCP topology detection.

    Multi-signal scoring:
        - Naming patterns
        - Port alignment
        - Environment variables
        - Resource sizing
        - Service exposure type
    """

    id = "mcp-discovery-advanced"
    description = "Advanced heuristic MCP workload detection"

    NAME_HINTS: ClassVar[Set[str]] = {
        "mcp",
        "agent",
        "gateway",
        "tool",
        "llm",
        "orchestrator",
    }

    PORT_HINTS: ClassVar[Set[int]] = {
        8080,
        8000,
        5000,
        7000,
        9000,
        11434,
    }

    ENV_HINTS: ClassVar[Set[str]] = {
        "MCP",
        "AGENT",
        "TOOL",
        "MODEL",
        "OPENAI",
    }

    async def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for ns in self.ctx.get_namespaces():
            deployments = self._safe_list_deployments(ns)
            services = self._safe_list_services(ns)

            service_index = self._index_services(services)

            for deploy in deployments:
                profile = self._analyze_deployment(ns, deploy, service_index)

                if profile.score >= 3:
                    findings.append(
                        Finding(
                            title="Probable MCP Workload Detected",
                            severity=Severity.INFO,
                            namespace=ns,
                            resource=profile.name,
                            description=(
                                f"Role={profile.inferred_role.value} "
                                f"Score={profile.score} "
                                f"Signals={sorted(profile.signals)}"
                            ),
                        )
                    )

                if profile.inferred_role == MCPRole.GATEWAY:
                    findings.append(
                        Finding(
                            title="MCP Gateway Exposure Pattern",
                            severity=Severity.MEDIUM,
                            namespace=ns,
                            resource=profile.name,
                            description=(
                                "Workload appears to function as an MCP gateway. "
                                "Validate authentication and network exposure."
                            ),
                        )
                    )

        return findings

    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------

    def _safe_list_deployments(self, namespace: str) -> List[V1Deployment]:
        if not self.ctx.apps_api:
            return []
        try:
            return self.ctx.apps_api.list_namespaced_deployment(namespace).items
        except ApiException:
            return []

    def _safe_list_services(self, namespace: str) -> List[V1Service]:
        if not self.ctx.core_api:
            return []
        try:
            return self.ctx.core_api.list_namespaced_service(namespace).items
        except ApiException:
            return []

    def _index_services(self, services: List[V1Service]) -> Dict[str, V1Service]:
        return {svc.metadata.name: svc for svc in services}

    def _analyze_deployment(
        self,
        namespace: str,
        deploy: V1Deployment,
        service_index: Dict[str, V1Service],
    ) -> MCPWorkloadSignals:

        profile = MCPWorkloadSignals(
            namespace=namespace,
            name=deploy.metadata.name,
        )

        name_lower = deploy.metadata.name.lower()

        # Naming heuristics
        for hint in self.NAME_HINTS:
            if hint in name_lower:
                profile.score += 1
                profile.signals.add(f"name:{hint}")

        containers = deploy.spec.template.spec.containers

        for container in containers:
            self._analyze_container(container, profile)

        # Service exposure inference
        for svc in service_index.values():
            if svc.spec and svc.spec.selector:
                if deploy.spec.selector.match_labels:
                    if svc.spec.selector.items() <= deploy.spec.selector.match_labels.items():
                        if svc.spec.type in {"LoadBalancer", "NodePort"}:
                            profile.score += 1
                            profile.signals.add(f"service:{svc.spec.type}")
                            profile.inferred_role = MCPRole.GATEWAY

        if profile.score >= 4 and profile.inferred_role == MCPRole.UNKNOWN:
            profile.inferred_role = MCPRole.AGENT_WORKER

        return profile

    def _analyze_container(
        self,
        container: V1Container,
        profile: MCPWorkloadSignals,
    ) -> None:

        # Ports
        if container.ports:
            for p in container.ports:
                if p.container_port in self.PORT_HINTS:
                    profile.score += 1
                    profile.signals.add(f"port:{p.container_port}")

                    if p.container_port in {8080, 8000}:
                        profile.inferred_role = MCPRole.GATEWAY

                    if p.container_port == 11434:
                        profile.inferred_role = MCPRole.LLM_RUNTIME

        # Environment variables
        if container.env:
            for env_var in container.env:
                if env_var.name:
                    for hint in self.ENV_HINTS:
                        if hint in env_var.name.upper():
                            profile.score += 1
                            profile.signals.add(f"env:{hint}")

        # Resource sizing heuristics
        resources = container.resources
        if resources and resources.requests:
            mem = resources.requests.get("memory")
            cpu = resources.requests.get("cpu")

            if mem and any(unit in mem for unit in ["Gi", "G"]):
                profile.score += 1
                profile.signals.add("memory:large")

            if cpu and not cpu.startswith("0"):
                profile.score += 1
                profile.signals.add("cpu:dedicated")


# ============================================================================
# ENGINE
# ============================================================================


class ProbeEngine:
    def __init__(self, ctx: K8sProbeContext) -> None:
        self.ctx = ctx
        self.modules: List[ClusterModule] = [
            MCPDiscoveryModule(ctx),
        ]

    async def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for module in self.modules:
            self.ctx.logger.info(f"Running module: {module.id}")
            try:
                results = await module.run()
                findings.extend(results)
            except Exception as exc:
                self.ctx.logger.error(
                    f"Module {module.id} failed safely: {exc}"
                )

        return findings


# ============================================================================
# CLI
# ============================================================================


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s | %(message)s",
    )


async def main_async() -> None:
    parser = argparse.ArgumentParser(
        description="Passive MCP Kubernetes Assessment Tool"
    )
    parser.add_argument("--namespace", action="append")
    parser.add_argument("--cluster-wide", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    cfg = ProbeConfig(
        namespace_scope=args.namespace,
        cluster_wide=args.cluster_wide,
        verbose=args.verbose,
    )

    ctx = K8sProbeContext(cfg)
    await ctx.initialize()

    engine = ProbeEngine(ctx)
    findings = await engine.run()

    print("MCP-K8S-PROBE RESULTS")
    print(f"Total Findings: {len(findings)}")

    for f in findings:
        print(
            f"[{f.severity.value}] {f.title} "
            f"(namespace={f.namespace}, resource={f.resource})"
        )
        print(f"  {f.description}")


def main() -> None:
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
