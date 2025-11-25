"""
Medusa - Modern Android Dynamic Analysis Framework
Version 2.0.0
"""

__version__ = "2.0.0"
__author__ = "Medusa Team"

from .config import Settings
from .core.device import DeviceManager
from .core.frida_handler import FridaHandler
from .modules.manager import ModuleManager

__all__ = [
    "Settings",
    "DeviceManager",
    "FridaHandler",
    "ModuleManager",
]
