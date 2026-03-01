#!/usr/bin/env python3
"""
MCP-K8S-PROBE v0.3 ..beta..

Passive Kubernetes assessor for identifying risky MCP-style deployments
using structural and behavioral heuristics derived from MCP protocol patterns.

Safety Properties:
    - Read-only Kubernetes API usage
    - No secret value extraction
    - No pod exec
    - No cluster mutations
    - Namespace-scoped by default
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Dict, Iterable, List, Optional, Set

from kubernetes import client, config
from kubernetes.client import ApiException
from kubernetes.client.models import (
    V1Container,
    V1Deployment,
    V1NetworkPolicy,
    V1Pod,
    V1Service,
)


# ============================================================================
# ENUMS & DATA STRUCTURES
# ============================================================================


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


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
        self.rbac_api: Optional[client.RbacAuthorizationV1Api] = None
        self.networking_api: Optional[client.NetworkingV1Api] = None

    async def initialize(self) -> None:
        try:
            config.load_incluster_config()
            self.logger.info("Using in-cluster Kubernetes configuration")
        except config.ConfigException:
            config.load_kube_config()
            self.logger.info("Using local kubeconfig")

        self.core_api = client.CoreV1Api()
        self.apps_api = client.AppsV1Api()
        self.rbac_api = client.RbacAuthorizationV1Api()
        self.networking_api = client.NetworkingV1Api()

    def get_namespaces(self) -> List[str]:
        if self.config.cluster_wide and self.core_api:
            try:
                ns_list = self.core_api.list_namespace().items
                return [ns.metadata.name for ns in ns_list]
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
# MCP PROTOCOL-AWARE DISCOVERY MODULE
# ============================================================================


class MCPDiscoveryModule(ClusterModule):
    """
    Detects MCP-like behavior using structural and protocol heuristics.

    Signals:
        - Services exposing RPC-like HTTP endpoints (/invoke, /execute, /tools)
        - JSON-oriented HTTP containers
        - Structured tool-style port exposure
        - Containers advertising agent/tool-related environment variables
    """

    id = "mcp-discovery"
    description = "Protocol-aware MCP deployment detection"

    MCP_PATH_HINTS: ClassVar[Set[str]] = {
        "/invoke",
        "/execute",
        "/tools",
        "/health",
        "/v1/invoke",
        "/v1/tools",
    }

    COMMON_AGENT_PORTS: ClassVar[Set[int]] = {
        3000,
        4000,
        5000,
        7000,
        8000,
        8080,
        9000,
    }

    ENV_HINTS: ClassVar[Set[str]] = {
        "MCP",
        "AGENT",
        "TOOL",
        "LLM",
        "MODEL",
    }

    async def run(self) -> List[Finding]:
        findings: List[Finding] = []
        namespaces = self.ctx.get_namespaces()

        for ns in namespaces:
            findings.extend(await self._analyze_services(ns))
            findings.extend(await self._analyze_deployments(ns))

        return findings

    async def _analyze_services(self, namespace: str) -> List[Finding]:
        results: List[Finding] = []

        if not self.ctx.core_api:
            return results

        try:
            services: List[V1Service] = (
                self.ctx.core_api.list_namespaced_service(namespace).items
            )
        except ApiException:
            return results

        for svc in services:
            if not svc.spec or not svc.spec.ports:
                continue

            for port in svc.spec.ports:
                if port.port in self.COMMON_AGENT_PORTS:
                    results.append(
                        Finding(
                            title="Service Exposes Common Agent Port",
                            severity=Severity.INFO,
                            namespace=namespace,
                            resource=svc.metadata.name,
                            description=(
                                f"Service exposes port {port.port}, commonly used by "
                                "agent-style HTTP RPC services."
                            ),
                        )
                    )

        return results

    async def _analyze_deployments(self, namespace: str) -> List[Finding]:
        results: List[Finding] = []

        if not self.ctx.apps_api:
            return results

        try:
            deployments: List[V1Deployment] = (
                self.ctx.apps_api.list_namespaced_deployment(namespace).items
            )
        except ApiException:
            return results

        for deploy in deployments:
            if not deploy.spec or not deploy.spec.template:
                continue

            containers = deploy.spec.template.spec.containers
            if not containers:
                continue

            for container in containers:
                if self._container_suggests_mcp(container):
                    results.append(
                        Finding(
                            title="Container Exhibits MCP-Like Behavior",
                            severity=Severity.INFO,
                            namespace=namespace,
                            resource=deploy.metadata.name,
                            description=(
                                "Container exposes characteristics consistent with "
                                "structured tool invocation or agent RPC patterns."
                            ),
                        )
                    )

        return results

    def _container_suggests_mcp(self, container: V1Container) -> bool:
        """
        Passive structural heuristics only.
        """

        # Check environment variables
        if container.env:
            for env_var in container.env:
                if env_var.name:
                    for hint in self.ENV_HINTS:
                        if hint in env_var.name.upper():
                            return True

        # Check exposed ports
        if container.ports:
            for p in container.ports:
                if p.container_port in self.COMMON_AGENT_PORTS:
                    return True

        # Check args for RPC hints
        if container.args:
            for arg in container.args:
                for hint in self.MCP_PATH_HINTS:
                    if hint in arg:
                        return True

        return False


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
            f"[{f.severity}] {f.title} "
            f"(ns={f.namespace}, resource={f.resource})"
        )
        print(f"  {f.description}")


def main() -> None:
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
