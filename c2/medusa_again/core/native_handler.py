"""Native library operations."""

import logging
from typing import List, Dict, Any

import frida

logger = logging.getLogger(__name__)


class NativeHandler:
    """Handles native library operations."""

    def __init__(self, device: frida.core.Device) -> None:
        self.device = device

    async def enumerate_modules(
        self, package: str, spawn: bool = False
    ) -> List[str]:
        """Enumerate loaded native modules."""
        try:
            if spawn:
                pid = self.device.spawn([package])
                session = self.device.attach(pid)
                self.device.resume(pid)
            else:
                # Get PID
                pid = await self._get_pid(package)
                if not pid:
                    return []
                session = self.device.attach(pid)

            script_code = """
            rpc.exports = {
                enumerateModules: function() {
                    return Process.enumerateModules().map(m => m.path);
                }
            };
            """

            script = session.create_script(script_code)
            script.load()

            modules = script.exports_sync.enumerate_modules()
            script.unload()
            session.detach()

            return modules

        except Exception as e:
            logger.error(f"Failed to enumerate modules: {e}")
            return []

    async def load_library(self, package: str, library_path: str) -> bool:
        """Force load a native library."""
        try:
            pid = await self._get_pid(package)
            if not pid:
                return False

            session = self.device.attach(pid)

            script_code = f"""
            Java.perform(function() {{
                System.load("{library_path}");
            }});
            """

            script = session.create_script(script_code)
            script.load()

            logger.info(f"Loaded library: {library_path}")

            script.unload()
            session.detach()

            return True

        except Exception as e:
            logger.error(f"Failed to load library: {e}")
            return False

    async def _get_pid(self, package: str) -> Optional[int]:
        """Get process ID."""
        import asyncio

        try:
            cmd = f"adb -s {self.device.id} shell pidof {package}"
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
