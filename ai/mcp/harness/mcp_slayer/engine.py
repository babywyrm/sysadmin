"""Core execution engine and context manager."""

from __future__ import annotations

import logging
import signal
import ssl
import uuid
from collections import defaultdict

import aiohttp
from cryptography.hazmat.primitives.asymmetric import ed25519

from mcp_slayer.config import AuthProfile, SlayerConfig
from mcp_slayer.exceptions import SlayerKillSwitchError
from mcp_slayer.models import Finding, Severity
from mcp_slayer.modules import MODULE_REGISTRY
from mcp_slayer.reporting import ReportGenerator


class SlayerContext:
    """Central execution context providing HTTP client, auth, and safety controls."""

    def __init__(self, config: SlayerConfig):
        self.config = config
        self.logger = logging.getLogger("slayer.context")
        self.http_client: aiohttp.ClientSession | None = None
        self.signing_key = ed25519.Ed25519PrivateKey.generate()
        self.verify_key = self.signing_key.public_key()
        self.kill_switch_active = False
        self.findings_by_severity: dict[Severity, int] = defaultdict(int)
        self.modules_executed: set[str] = set()

    async def __aenter__(self) -> SlayerContext:
        await self._initialize_http_client()
        self._register_signal_handlers()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.http_client:
            await self.http_client.close()

    async def _initialize_http_client(self):
        ssl_context = ssl.create_default_context()
        if not self.config.verify_tls:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            self.logger.warning("TLS verification disabled")

        timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
        connector = aiohttp.TCPConnector(ssl=ssl_context, limit=10)

        self.http_client = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                "User-Agent": "MCP-SLAYER/3.1",
                "X-Slayer-Run-ID": str(uuid.uuid4()),
            },
        )

    def _register_signal_handlers(self):
        def handle_kill_switch(signum, frame):
            self.logger.critical(f"Kill switch via signal {signum}")
            self.kill_switch_active = True

        signal.signal(signal.SIGINT, handle_kill_switch)
        signal.signal(signal.SIGTERM, handle_kill_switch)

    def get_auth_profile(self, name: str = "default") -> AuthProfile:
        for profile in self.config.auth_profiles:
            if profile.name == name:
                return profile
        return self.config.auth_profiles[0]

    def get_auth_headers(self, profile_name: str = "default") -> dict[str, str]:
        profile = self.get_auth_profile(profile_name)
        if profile.type == "bearer" and profile.token:
            return {"Authorization": f"Bearer {profile.token.get_secret_value()}"}
        if profile.type == "basic" and profile.username and profile.password:
            import base64

            cred = f"{profile.username}:{profile.password.get_secret_value()}"
            encoded = base64.b64encode(cred.encode()).decode()
            return {"Authorization": f"Basic {encoded}"}
        return {}

    def sign_finding(self, finding: Finding) -> None:
        finding.sign(self.signing_key)

    def verify_finding(self, finding: Finding) -> bool:
        return finding.verify(self.verify_key)


async def run_assessment(config: SlayerConfig) -> list[Finding]:
    """Execute full security assessment with all enabled modules."""
    logger = logging.getLogger("slayer.engine")

    if "all" in config.enabled_modules:
        enabled = MODULE_REGISTRY
    else:
        enabled = {
            k: v
            for k, v in MODULE_REGISTRY.items()
            if k in config.enabled_modules and k not in config.skip_modules
        }

    logger.info(f"Executing {len(enabled)} attack modules")
    all_findings: list[Finding] = []

    async with SlayerContext(config) as ctx:
        for module_id, module_class in enabled.items():
            logger.info(f"[*] Running module: {module_id}")
            try:
                module = module_class(ctx)
                findings = await module.run()
                for finding in findings:
                    ctx.sign_finding(finding)
                all_findings.extend(findings)
                ctx.modules_executed.add(module_id)
                logger.info(f"[+] {module_id}: {len(findings)} findings")
            except SlayerKillSwitchError:
                logger.critical("Kill switch — aborting")
                raise
            except Exception as e:
                logger.exception(f"Module {module_id} failed: {e}")

        reporter = ReportGenerator(ctx)
        await reporter.generate_reports(all_findings)

    return all_findings
