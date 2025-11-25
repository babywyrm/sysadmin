"""Frida session management and script execution."""

import asyncio
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable

import frida

logger = logging.getLogger(__name__)


class FridaHandler:
    """Handles Frida operations and script management."""

    def __init__(self, device: frida.core.Device) -> None:
        self.device = device
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.message_handler: Optional[Callable] = None

    async def attach(self, package: str) -> Optional[frida.core.Session]:
        """Attach to a running process."""
        try:
            # Get PID
            pid = await self._get_pid(package)
            if not pid:
                logger.error(f"Process {package} not found")
                return None

            self.session = self.device.attach(pid)
            logger.info(f"Attached to {package} (PID: {pid})")
            return self.session

        except Exception as e:
            logger.error(f"Failed to attach: {e}")
            return None

    async def spawn(self, package: str) -> Optional[frida.core.Session]:
        """Spawn and attach to a process."""
        try:
            pid = self.device.spawn([package])
            self.session = self.device.attach(pid)
            logger.info(f"Spawned {package} (PID: {pid})")
            return self.session

        except Exception as e:
            logger.error(f"Failed to spawn: {e}")
            return None

    async def load_script(self, script_path: Path) -> bool:
        """Load and compile a Frida script."""
        if not self.session:
            logger.error("No active session")
            return False

        try:
            with open(script_path) as f:
                script_code = f.read()

            self.script = self.session.create_script(script_code)
            self.script.on("message", self._on_message)
            self.script.load()

            logger.info(f"Script loaded: {script_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to load script: {e}")
            return False

    async def run_session(
        self,
        package: str,
        script_path: Path,
        spawn: bool = False,
    ) -> None:
        """Run a Frida session with script."""
        # Attach or spawn
        if spawn:
            session = await self.spawn(package)
        else:
            session = await self.attach(package)

        if not session:
            return

        # Load script
        if not await self.load_script(script_path):
            return

        # Resume if spawned
        if spawn:
            self.device.resume(session._impl.pid)

        # Keep session alive
        logger.info("Session running. Press Ctrl+C to detach.")
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Detaching...")
            self.detach()

    def detach(self) -> None:
        """Detach from current session."""
        if self.script:
            self.script.unload()
            self.script = None

        if self.session:
            self.session.detach()
            self.session = None

        logger.info("Detached from session")

    async def enumerate_exports(
        self, package: str, library: str
    ) -> List[Dict[str, Any]]:
        """Enumerate native library exports."""
        if not await self.attach(package):
            return []

        try:
            script_code = f"""
            rpc.exports = {{
                enumerateExports: function(lib) {{
                    var module = Process.getModuleByName(lib);
                    return module.enumerateExports();
                }}
            }};
            """

            script = self.session.create_script(script_code)
            script.load()

            exports = script.exports_sync.enumerate_exports(library)
            script.unload()

            return exports

        except Exception as e:
            logger.error(f"Failed to enumerate exports: {e}")
            return []

    def _on_message(self, message: Dict[str, Any], data: Optional[bytes]) -> None:
        """Handle messages from Frida script."""
        if message["type"] == "send":
            payload = message.get("payload", {})
            logger.info(f"Script message: {payload}")
        elif message["type"] == "error":
            logger.error(f"Script error: {message['description']}")

    async def _get_pid(self, package: str) -> Optional[int]:
        """Get process ID for a package."""
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
