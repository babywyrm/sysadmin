"""CLI entry point for MCP-SLAYER."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

from mcp_slayer.config import load_config
from mcp_slayer.engine import run_assessment
from mcp_slayer.exceptions import SlayerKillSwitchError
from mcp_slayer.models import Severity


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(name)-20s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("aiohttp").setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="mcp-slayer",
        description="MCP-SLAYER v3.1 — OWASP MCP Security Assessment Framework",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("slayer-config.yaml"),
        help="Path to configuration file",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm authorization to test (required)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "--modules",
        type=str,
        help="Comma-separated list of modules to run",
    )
    parser.add_argument(
        "--output-formats",
        type=str,
        help="Comma-separated: json,yaml,markdown,sarif",
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--taxonomy",
        action="store_true",
        help="Print taxonomy bridge table and exit",
    )

    args = parser.parse_args(argv)
    setup_logging(args.verbose)
    logger = logging.getLogger("slayer.cli")

    if args.taxonomy:
        _print_taxonomy()
        return 0

    if not args.config.exists():
        logger.error(f"Config file not found: {args.config}")
        return 1

    try:
        config = load_config(args.config)
    except Exception as e:
        logger.error(f"Configuration error: {e}")
        return 1

    if args.authorized:
        pass  # Already loaded from config
    if args.modules:
        config.enabled_modules = [m.strip() for m in args.modules.split(",")]
    if args.output_formats:
        config.output_formats = [f.strip() for f in args.output_formats.split(",")]
    if args.output_dir:
        config.output_dir = args.output_dir

    try:
        logger.info("=" * 60)
        logger.info("MCP-SLAYER v3.1 — OWASP MCP Security Assessment")
        logger.info("=" * 60)
        logger.info(f"Target: {config.gateway.base_url}")
        logger.info(f"Tools:  {len(config.tools)}")
        logger.info(f"Modules: {', '.join(config.enabled_modules)}")
        logger.info("=" * 60)

        findings = asyncio.run(run_assessment(config))

        logger.info("")
        logger.info("=" * 60)
        logger.info("ASSESSMENT COMPLETE")
        logger.info(f"Total Findings: {len(findings)}")
        for severity in reversed(list(Severity)):
            count = sum(1 for f in findings if f.severity == severity)
            if count > 0:
                logger.info(f"  {severity.value}: {count}")
        logger.info(f"Reports: {config.output_dir}")
        logger.info("=" * 60)

        critical_count = sum(
            1 for f in findings if f.severity == Severity.CRITICAL
        )
        return 1 if critical_count > 0 else 0

    except SlayerKillSwitchError:
        logger.critical("Assessment aborted via kill switch")
        return 130
    except KeyboardInterrupt:
        logger.warning("Assessment interrupted")
        return 130
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        return 1


def _print_taxonomy():
    """Print the taxonomy bridge table for reference."""
    from mcp_slayer.taxonomy import THREAT_METADATA, THREAT_TO_OWASP, PlaybookThreatID

    print("MCP-SLAYER Taxonomy Bridge: Playbook Threats → OWASP MCP Top 10")
    print("=" * 80)
    print(f"{'Threat ID':<12} {'Name':<38} {'OWASP':<18} {'Lane'}")
    print("-" * 80)
    for threat_id in PlaybookThreatID:
        meta = THREAT_METADATA.get(threat_id, {})
        owasp_cats = THREAT_TO_OWASP.get(threat_id, [])
        owasp_str = ",".join(c.value for c in owasp_cats)
        print(
            f"{threat_id.value:<12} "
            f"{meta.get('name', '?'):<38} "
            f"{owasp_str:<18} "
            f"{meta.get('red_team_lane', '?')}"
        )


if __name__ == "__main__":
    sys.exit(main())
