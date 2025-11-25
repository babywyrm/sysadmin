"""ADB helper utilities."""

import asyncio
import logging
import shlex
from typing import List, Optional

logger = logging.getLogger(__name__)


class ADBHelper:
    """Helper class for ADB operations."""

    def __init__(self, device_id: Optional[str] = None) -> None:
        self.device_id = device_id

    async def execute(self, command: str) -> Optional[str]:
        """Execute ADB command safely."""
        try:
            # Build command safely
            cmd_parts = ["adb"]
            
            if self.device_id:
                cmd_parts.extend(["-s", self.device_id])
            
            # Parse command safely
            cmd_parts.extend(shlex.split(command))

            proc = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.error(f"ADB command failed: {stderr.decode()}")
                return None

            return stdout.decode()

        except Exception as e:
            logger.error(f"Failed to execute ADB command: {e}")
            return None

    async def shell(self, command: str) -> Optional[str]:
        """Execute shell command on device."""
        # Escape command properly
        escaped_cmd = shlex.quote(command)
        return await self.execute(f"shell {escaped_cmd}")

    async def push(self, local: str, remote: str) -> bool:
        """Push file to device."""
        result = await self.execute(f"push {shlex.quote(local)} {shlex.quote(remote)}")
        return result is not None

    async def pull(self, remote: str, local: str) -> bool:
        """Pull file from device."""
        result = await self.execute(f"pull {shlex.quote(remote)} {shlex.quote(local)}")
        return result is not None

    async def get_property(self, prop: str) -> Optional[str]:
        """Get device property."""
        result = await self.shell(f"getprop {shlex.quote(prop)}")
        return result.strip() if result else None

    async def list_packages(self, filter_option: str = "") -> List[str]:
        """List installed packages."""
        result = await self.shell(f"pm list packages {filter_option}")
        
        if not result:
            return []

        packages = [
            line.split(":")[1].strip()
            for line in result.split("\n")
            if line.startswith("package:")
        ]

        return sorted(packages)
