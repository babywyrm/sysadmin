#!/usr/bin/env python3
"""
MCP-K8S-PROBE (Skeleton v0.1)

A passive, namespace-scoped Kubernetes assessment framework
for identifying risky MCP (Model Context Protocol) deployments.

SAFE BY DEFAULT:
    - Passive read-only inspection
    - No secret value extraction
    - No pod exec
    - No mutation of cluster state
    - Namespace-scoped unless --cluster-wide explicitly set

This is the foundational scaffold. Modules will be expanded later.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Dict, List, Optional

from kubernetes import client, config
from kubernetes.client import ApiException


# ============================================================================
# ENUMS & DATA MODELS
# ============================================================================


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    """
    Minimal structured finding model (expand later).
    """

    title: str
    severity: Severity
    namespace: Optional[str]
    resource: Optional[str]
    description: str


@dataclass
class ProbeConfig:
    """
    Core execution configuration.
    """

    namespace_scope: Optional[List[str]]
    cluster_wide: bool
    dry_run: bool
    verbose: bool


# ============================================================================
# K8S CONTEXT
# ============================================================================


class K8sProbeContext:
    """
    Holds Kubernetes API clients and shared state.
    """

    def __init__(self, config_obj: ProbeConfig):
        self.config = config_obj
        self.logger = logging.getLogger("mcp-k8s-probe")

        self.core_api: Optional[client.CoreV1Api] = None
        self.apps_api: Optional[client.AppsV1Api] = None
        self.rbac_api: Optional[client.RbacAuthorizationV1Api] = None
        self.networking_api: Optional[client.NetworkingV1Api] = None

    async def initialize(self) -> None:
        """
        Initialize Kubernetes client configuration.
        Attempts in-cluster config first, falls back to kubeconfig.
        """
        try:
            config.load_incluster_config()
            self.logger.info("Loaded in-cluster Kubernetes configuration")
        except config.ConfigException:
            config.load_kube_config()
            self.logger.info("Loaded kubeconfig from local environment")

        self.core_api = client.CoreV1Api()
        self.apps_api = client.AppsV1Api()
        self.rbac_api = client.RbacAuthorizationV1Api()
        self.networking_api = client.NetworkingV1Api()

    def get_namespaces(self) -> List[str]:
        """
        Determine which namespaces should be scanned.
        """
        if self.config.cluster_wide:
            ns_list = self.core_api.list_namespace().items
            return [ns.metadata.name for ns in ns_list]

        if self.config.namespace_scope:
            return self.config.namespace_scope

        # Default fallback: current namespace if in cluster
        try:
            with open(
                "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
            ) as f:
                return [f.read().strip()]
        except FileNotFoundError:
            return ["default"]


# ============================================================================
# MODULE BASE CLASS
# ============================================================================


class ClusterModule(ABC):
    """
    Base class for passive Kubernetes analysis modules.
    """

    id: ClassVar[str]
    description: ClassVar[str]

    def __init__(self, ctx: K8sProbeContext):
        self.ctx = ctx
        self.logger = logging.getLogger(f"mcp-k8s-probe.{self.id}")

    @abstractmethod
    async def run(self) -> List[Finding]:
        """
        Execute passive analysis.
        """
        ...


# ============================================================================
# SAMPLE MODULE (Placeholder)
# ============================================================================


class ServiceAccountAuditModule(ClusterModule):
    """
    Identifies potentially overprivileged service accounts
    used by MCP-like deployments.

    (Skeleton logic only — real RBAC inspection added later.)
    """

    id = "service-account-audit"
    description = "Inspect ServiceAccounts associated with MCP pods"

    async def run(self) -> List[Finding]:
        findings: List[Finding] = []

        namespaces = self.ctx.get_namespaces()

        for ns in namespaces:
            try:
                sa_list = self.ctx.core_api.list_namespaced_service_account(ns)
            except ApiException as e:
                self.logger.error(f"Failed to list SAs in {ns}: {e}")
                continue

            for sa in sa_list.items:
                # Skeleton placeholder logic
                if "mcp" in sa.metadata.name.lower():
                    findings.append(
                        Finding(
                            title="MCP-like ServiceAccount Detected",
                            severity=Severity.INFO,
                            namespace=ns,
                            resource=sa.metadata.name,
                            description=(
                                "ServiceAccount name suggests MCP usage. "
                                "RBAC privileges not yet evaluated."
                            ),
                        )
                    )

        return findings


# ============================================================================
# ENGINE
# ============================================================================


class ProbeEngine:
    """
    Orchestrates module execution.
    """

    def __init__(self, ctx: K8sProbeContext):
        self.ctx = ctx
        self.modules: List[ClusterModule] = [
            ServiceAccountAuditModule(ctx),
        ]

    async def run(self) -> List[Finding]:
        all_findings: List[Finding] = []

        for module in self.modules:
            self.ctx.logger.info(f"Running module: {module.id}")
            findings = await module.run()
            all_findings.extend(findings)

        return all_findings


# ============================================================================
# CLI
# ============================================================================


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MCP Kubernetes Passive Assessment Probe (Skeleton)"
    )

    parser.add_argument(
        "--namespace",
        action="append",
        help="Namespace(s) to scan (repeatable)",
    )

    parser.add_argument(
        "--cluster-wide",
        action="store_true",
        help="Scan all namespaces (requires RBAC permissions)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Dry-run mode (default: true, no active actions)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    return parser.parse_args()


# ============================================================================
# MAIN
# ============================================================================


async def main_async() -> None:
    args = parse_args()
    setup_logging(args.verbose)

    probe_config = ProbeConfig(
        namespace_scope=args.namespace,
        cluster_wide=args.cluster_wide,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )

    ctx = K8sProbeContext(probe_config)
    await ctx.initialize()

    engine = ProbeEngine(ctx)
    findings = await engine.run()

    print("\n=== MCP-K8S-PROBE RESULTS ===")
    print(f"Total Findings: {len(findings)}\n")

    for f in findings:
        print(f"[{f.severity}] {f.title}")
        print(f"  Namespace: {f.namespace}")
        print(f"  Resource: {f.resource}")
        print(f"  Description: {f.description}")
        print("")


def main() -> None:
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(130)


if __name__ == "__main__":
    main()
