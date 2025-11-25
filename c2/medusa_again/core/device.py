"""Device management."""

import asyncio
import logging
from typing import List, Optional

import frida

logger = logging.getLogger(__name__)


class DeviceManager:
    """Manages Android devices and ADB connections."""

    def __init__(self) -> None:
        self.device: Optional[frida.core.Device] = None
        self.device_id: Optional[str] = None

    async def enumerate_devices(self) -> List[frida.core.Device]:
        """Enumerate all connected devices."""
        try:
            devices = frida.enumerate_devices()
            logger.info(f"Found {len(devices)} device(s)")
            return devices
        except Exception as e:
            logger.error(f"Failed to enumerate devices: {e}")
            return []

    async def set_device(self, device: frida.core.Device) -> None:
        """Set the active device."""
        self.device = device
        self.device_id = device.id
        logger.info(f"Active device set to: {device.id}")

    async def list_packages(self, option: str = "") -> List[str]:
        """List installed packages."""
        if not self.device_id:
            logger.error("No device selected")
            return []

        try:
            cmd = f"adb -s {self.device_id} shell pm list packages {option}"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            packages = [
                line.split(":")[1].strip()
                for line in stdout.decode().strip().split("\n")
                if line
            ]
            return sorted(packages)

        except Exception as e:
            logger.error(f"Failed to list packages: {e}")
            return []

    async def get_package_info(self, package: str) -> dict:
        """Get detailed package information."""
        if not self.device_id:
            return {}

        try:
            cmd = f"adb -s {self.device_id} shell dumpsys package {package}"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            # Parse dumpsys output (simplified)
            info = {"package": package, "raw": stdout.decode()}
            return info

        except Exception as e:
            logger.error(f"Failed to get package info: {e}")
            return {}

    async def get_pid(self, package: str) -> Optional[int]:
        """Get process ID for a package."""
        if not self.device_id:
            return None

        try:
            cmd = f"adb -s {self.device_id} shell pidof {package}"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            pid_str = stdout.decode().strip()
            return int(pid_str) if pid_str else None

        except Exception as e:
            logger.error(f"Failed to get PID: {e}")
            return None
