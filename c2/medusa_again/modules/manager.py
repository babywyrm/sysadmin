"""Module loading and management."""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Module:
    """Represents a Medusa module."""

    name: str
    category: str
    description: str
    code: str
    path: Path

    @classmethod
    def from_file(cls, path: Path) -> Optional["Module"]:
        """Load module from .med file."""
        try:
            with open(path) as f:
                data = json.load(f)

            return cls(
                name=data.get("name", path.stem),
                category=data.get("category", "uncategorized"),
                description=data.get("description", ""),
                code=data.get("code", ""),
                path=path,
            )

        except Exception as e:
            logger.error(f"Failed to load module {path}: {e}")
            return None


class ModuleManager:
    """Manages Medusa modules."""

    def __init__(self, modules_dir: Path) -> None:
        self.modules_dir = modules_dir
        self.available_modules: List[Module] = []
        self.staged_modules: List[Module] = []
        self.scratchpad: str = ""

    async def load_modules(self) -> int:
        """Load all available modules."""
        self.available_modules.clear()

        if not self.modules_dir.exists():
            logger.warning(f"Modules directory not found: {self.modules_dir}")
            return 0

        for module_file in self.modules_dir.rglob("*.med"):
            module = Module.from_file(module_file)
            if module:
                self.available_modules.append(module)

        logger.info(f"Loaded {len(self.available_modules)} modules")
        return len(self.available_modules)

    def get_available_modules(self) -> List[Module]:
        """Get list of available modules."""
        return self.available_modules

    def get_staged_modules(self) -> List[Module]:
        """Get list of staged modules."""
        return self.staged_modules

    def search_modules(self, keyword: str) -> List[Module]:
        """Search modules by keyword."""
        keyword = keyword.lower()
        return [
            mod
            for mod in self.available_modules
            if keyword in mod.name.lower()
            or keyword in mod.description.lower()
            or keyword in mod.category.lower()
        ]

    def stage_module(self, module_name: str) -> bool:
        """Stage a module for compilation."""
        # Find module
        module = next(
            (m for m in self.available_modules if m.name == module_name), None
        )

        if not module:
            logger.error(f"Module not found: {module_name}")
            return False

        # Check if already staged
        if module in self.staged_modules:
            logger.warning(f"Module already staged: {module_name}")
            return True

        self.staged_modules.append(module)
        logger.info(f"Staged module: {module_name}")
        return True

    def unstage_module(self, module_name: str) -> bool:
        """Remove a module from staging."""
        self.staged_modules = [
            m for m in self.staged_modules if m.name != module_name
        ]
        logger.info(f"Unstaged module: {module_name}")
        return True

    def clear_staged(self) -> None:
        """Clear all staged modules."""
        self.staged_modules.clear()
        logger.info("Cleared all staged modules")

    async def compile_script(self, output_path: Optional[Path] = None) -> Optional[Path]:
        """Compile staged modules into a single script."""
        if not self.staged_modules and not self.scratchpad:
            logger.warning("No modules staged")
            return None

        try:
            # Build script
            script_parts = []

            # Add header
            script_parts.append(self._get_header())

            # Add staged modules
            for module in self.staged_modules:
                script_parts.append(f"\n// Module: {module.name}\n")
                script_parts.append(module.code)

            # Add scratchpad
            if self.scratchpad:
                script_parts.append("\n// Scratchpad\n")
                script_parts.append(self.scratchpad)

            # Add footer
            script_parts.append(self._get_footer())

            # Write to file
            if output_path is None:
                from ..config import settings
                output_path = settings.base_dir / "agent.js"

            with open(output_path, "w") as f:
                f.write("\n".join(script_parts))

            logger.info(f"Compiled script: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to compile script: {e}")
            return None

    def add_to_scratchpad(self, code: str) -> None:
        """Add code to scratchpad."""
        self.scratchpad += "\n" + code
        logger.info("Added code to scratchpad")

    def clear_scratchpad(self) -> None:
        """Clear scratchpad."""
        self.scratchpad = ""
        logger.info("Cleared scratchpad")

    def _get_header(self) -> str:
        """Get script header."""
        return """
// Medusa Generated Script
// Auto-generated - Do not edit manually

Java.perform(function() {
    console.log('[*] Medusa script loaded');

    // Utility functions
    function colorLog(msg, color) {
        console.log(msg);
    }

    function displayAppInfo() {
        var context = Java.use('android.app.ActivityThread')
            .currentApplication()
            .getApplicationContext();
        
        var info = {
            packageName: context.getPackageName(),
            filesDir: context.getFilesDir().getAbsolutePath(),
            cacheDir: context.getCacheDir().getAbsolutePath()
        };
        
        console.log('[*] App Info:', JSON.stringify(info));
    }

    // Wait for app to initialize
    setTimeout(displayAppInfo, 500);
"""

    def _get_footer(self) -> str:
        """Get script footer."""
        return """
    console.log('[*] All hooks installed');
});
"""
