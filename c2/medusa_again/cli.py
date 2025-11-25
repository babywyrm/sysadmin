"""Main CLI interface using Typer."""

import asyncio
import sys
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.table import Table

from .config import settings
from .core.device import DeviceManager
from .core.frida_handler import FridaHandler
from .modules.manager import ModuleManager
from .utils.adb import ADBHelper
from .utils.security import SecurityScanner

app = typer.Typer(
    name="medusa",
    help="Modern Android Dynamic Analysis Framework",
    add_completion=True,
)
console = Console()

# Global state
device_manager: Optional[DeviceManager] = None
frida_handler: Optional[FridaHandler] = None
module_manager: Optional[ModuleManager] = None


def print_banner() -> None:
    """Print the Medusa banner."""
    banner = """
    ███╗   ███╗███████╗██████╗ ██╗   ██╗███████╗ █████╗ 
    ████╗ ████║██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗    
    ██╔████╔██║█████╗  ██║  ██║██║   ██║███████╗███████║
    ██║╚██╔╝██║██╔══╝  ██║  ██║██║   ██║╚════██║██╔══██║
    ██║ ╚═╝ ██║███████╗██████╔╝╚██████╔╝███████║██║  ██║
    ╚═╝     ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
    
    Version 2.0.0 - Modern Android Dynamic Analysis
    """
    console.print(Panel(banner, style="bold cyan"))


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
) -> None:
    """Medusa - Modern Android Dynamic Analysis Framework."""
    if version:
        console.print(f"Medusa version 2.0.0")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        # Interactive mode
        asyncio.run(interactive_mode())


async def interactive_mode() -> None:
    """Run Medusa in interactive mode."""
    global device_manager, frida_handler, module_manager

    print_banner()

    # Initialize managers
    device_manager = DeviceManager()
    module_manager = ModuleManager(settings.modules_dir)
    
    console.print("\n[green]Initializing Medusa...[/green]")
    
    # Load device
    devices = await device_manager.enumerate_devices()
    if not devices:
        console.print("[red]No devices found![/red]")
        return

    # Device selection
    if len(devices) > 1:
        table = Table(title="Available Devices")
        table.add_column("Index", style="cyan")
        table.add_column("ID", style="green")
        table.add_column("Type", style="yellow")

        for idx, device in enumerate(devices):
            table.add_row(str(idx), device.id, device.type)

        console.print(table)
        device_idx = int(Prompt.ask("Select device", default="0"))
        device = devices[device_idx]
    else:
        device = devices[0]

    await device_manager.set_device(device)
    frida_handler = FridaHandler(device)

    console.print(
        f"[green]✓[/green] Connected to device: [cyan]{device.id}[/cyan]"
    )

    # Load modules
    module_count = await module_manager.load_modules()
    console.print(
        f"[green]✓[/green] Loaded {module_count} modules"
    )

    # Interactive shell
    await run_shell()


async def run_shell() -> None:
    """Run the interactive shell."""
    console.print("\n[yellow]Type 'help' for commands or 'exit' to quit[/yellow]\n")

    while True:
        try:
            command = Prompt.ask("[bold blue]medusa[/bold blue]")
            
            if not command.strip():
                continue

            parts = command.split()
            cmd = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []

            if cmd == "exit":
                if Confirm.ask("Are you sure you want to exit?"):
                    break
            elif cmd == "help":
                show_help()
            elif cmd == "list":
                await cmd_list(args)
            elif cmd == "modules":
                await cmd_modules(args)
            elif cmd == "use":
                await cmd_use(args)
            elif cmd == "compile":
                await cmd_compile(args)
            elif cmd == "run":
                await cmd_run(args)
            elif cmd == "hook":
                await cmd_hook(args)
            elif cmd == "enumerate":
                await cmd_enumerate(args)
            elif cmd == "scan":
                await cmd_scan(args)
            elif cmd == "clear":
                console.clear()
            else:
                console.print(f"[red]Unknown command: {cmd}[/red]")

        except KeyboardInterrupt:
            console.print("\n[yellow]Use 'exit' to quit[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


def show_help() -> None:
    """Show help information."""
    help_table = Table(title="Available Commands")
    help_table.add_column("Command", style="cyan")
    help_table.add_column("Description", style="white")

    commands = [
        ("list [options]", "List installed packages (-3 for 3rd party)"),
        ("modules [show|search]", "Manage modules"),
        ("use <module>", "Stage a module"),
        ("compile", "Compile staged modules"),
        ("run <package>", "Run Frida session"),
        ("hook <options>", "Hook methods"),
        ("enumerate <pkg> <lib>", "Enumerate native exports"),
        ("scan <package>", "Scan for secrets/C2"),
        ("clear", "Clear screen"),
        ("exit", "Exit Medusa"),
    ]

    for cmd, desc in commands:
        help_table.add_row(cmd, desc)

    console.print(help_table)


async def cmd_list(args: List[str]) -> None:
    """List packages."""
    if not device_manager:
        console.print("[red]No device connected[/red]")
        return

    option = args[0] if args else ""
    packages = await device_manager.list_packages(option)

    table = Table(title=f"Packages ({len(packages)})")
    table.add_column("Index", style="cyan")
    table.add_column("Package Name", style="green")

    for idx, pkg in enumerate(packages):
        table.add_row(str(idx), pkg)

    console.print(table)


async def cmd_modules(args: List[str]) -> None:
    """Module management."""
    if not module_manager:
        console.print("[red]Module manager not initialized[/red]")
        return

    if not args or args[0] == "show":
        modules = module_manager.get_available_modules()
        
        table = Table(title="Available Modules")
        table.add_column("Name", style="cyan")
        table.add_column("Category", style="yellow")
        table.add_column("Description", style="white")

        for mod in modules:
            table.add_row(mod.name, mod.category, mod.description)

        console.print(table)

    elif args[0] == "search" and len(args) > 1:
        keyword = args[1]
        results = module_manager.search_modules(keyword)
        
        if not results:
            console.print(f"[yellow]No modules found matching '{keyword}'[/yellow]")
        else:
            for mod in results:
                console.print(f"[green]•[/green] {mod.name} - {mod.description}")

    elif args[0] == "staged":
        staged = module_manager.get_staged_modules()
        
        if not staged:
            console.print("[yellow]No modules staged[/yellow]")
        else:
            table = Table(title="Staged Modules")
            table.add_column("Index", style="cyan")
            table.add_column("Name", style="green")

            for idx, mod in enumerate(staged):
                table.add_row(str(idx), mod.name)

            console.print(table)


async def cmd_use(args: List[str]) -> None:
    """Stage a module."""
    if not module_manager:
        console.print("[red]Module manager not initialized[/red]")
        return

    if not args:
        console.print("[red]Usage: use <module_name>[/red]")
        return

    module_name = args[0]
    if module_manager.stage_module(module_name):
        console.print(f"[green]✓[/green] Staged module: {module_name}")
    else:
        console.print(f"[red]Module not found: {module_name}[/red]")


async def cmd_compile(args: List[str]) -> None:
    """Compile staged modules."""
    if not module_manager:
        console.print("[red]Module manager not initialized[/red]")
        return

    with console.status("[bold green]Compiling modules..."):
        script_path = await module_manager.compile_script()

    if script_path:
        console.print(f"[green]✓[/green] Script compiled: {script_path}")
        
        # Show preview
        if Confirm.ask("Show compiled script?", default=False):
            with open(script_path) as f:
                syntax = Syntax(f.read(), "javascript", theme="monokai")
                console.print(syntax)
    else:
        console.print("[red]Compilation failed[/red]")


async def cmd_run(args: List[str]) -> None:
    """Run Frida session."""
    if not frida_handler:
        console.print("[red]Frida handler not initialized[/red]")
        return

    if not args:
        console.print("[red]Usage: run <package_name> [-f to spawn][/red]")
        return

    package = args[0]
    spawn = "-f" in args

    console.print(f"[green]Starting Frida session for {package}...[/green]")

    script_path = settings.base_dir / "agent.js"
    if not script_path.exists():
        console.print("[yellow]No compiled script found. Run 'compile' first.[/yellow]")
        return

    await frida_handler.run_session(package, script_path, spawn=spawn)


async def cmd_hook(args: List[str]) -> None:
    """Hook methods."""
    if not args:
        console.print("[red]Usage: hook -f (Java) | hook -n (Native)[/red]")
        return

    option = args[0]

    if option == "-f":
        # Java method hooking
        class_name = Prompt.ask("Enter class name")
        method_name = Prompt.ask("Enter method name")
        enable_backtrace = Confirm.ask("Enable backtrace?", default=False)

        code = generate_java_hook(class_name, method_name, enable_backtrace)
        
        # Add to scratchpad
        scratchpad = settings.base_dir / "scratchpad.js"
        with open(scratchpad, "a") as f:
            f.write(code)

        console.print("[green]✓[/green] Hook added to scratchpad")

    elif option == "-n":
        # Native method hooking
        library = Prompt.ask("Library name (e.g., libnative.so)")
        function = Prompt.ask("Function name or offset")
        num_args = int(Prompt.ask("Number of arguments", default="0"))

        code = generate_native_hook(library, function, num_args)
        
        scratchpad = settings.base_dir / "scratchpad.js"
        with open(scratchpad, "a") as f:
            f.write(code)

        console.print("[green]✓[/green] Hook added to scratchpad")


async def cmd_enumerate(args: List[str]) -> None:
    """Enumerate native library exports."""
    if not frida_handler:
        console.print("[red]Frida handler not initialized[/red]")
        return

    if len(args) < 2:
        console.print("[red]Usage: enumerate <package> <library>[/red]")
        return

    package = args[0]
    library = args[1]

    console.print(f"[green]Enumerating {library} in {package}...[/green]")

    exports = await frida_handler.enumerate_exports(package, library)

    if exports:
        table = Table(title=f"Exports from {library}")
        table.add_column("Name", style="cyan")
        table.add_column("Address", style="yellow")

        for export in exports:
            table.add_row(export["name"], export["address"])

        console.print(table)
    else:
        console.print("[yellow]No exports found[/yellow]")


async def cmd_scan(args: List[str]) -> None:
    """Scan for secrets and C2 addresses."""
    if not args:
        console.print("[red]Usage: scan <package> [-s secrets] [-c c2][/red]")
        return

    package = args[0]
    scan_secrets = "-s" in args or "-a" in args
    scan_c2 = "-c" in args or "-a" in args

    scanner = SecurityScanner(settings.vt_api_key)

    console.print(f"[green]Scanning {package}...[/green]")

    # Dump memory
    dump_dir = settings.base_dir / "dump" / package
    dump_dir.mkdir(parents=True, exist_ok=True)

    # Extract strings (simplified - would need actual implementation)
    strings = []  # Would extract from memory dump

    if scan_secrets:
        with console.status("[bold green]Scanning for secrets..."):
            findings = await scanner.scan_secrets(strings)
        
        if findings:
            console.print("[red]⚠ Secrets found:[/red]")
            for finding in findings:
                console.print(f"  [yellow]•[/yellow] {finding}")
        else:
            console.print("[green]✓[/green] No secrets found")

    if scan_c2:
        with console.status("[bold green]Scanning for C2 addresses..."):
            findings = await scanner.scan_c2(strings)
        
        if findings:
            console.print("[red]⚠ Suspicious domains found:[/red]")
            for finding in findings:
                console.print(f"  [yellow]•[/yellow] {finding}")
        else:
            console.print("[green]✓[/green] No suspicious domains found")


def generate_java_hook(
    class_name: str, method_name: str, backtrace: bool
) -> str:
    """Generate Java method hook code."""
    backtrace_code = """
        Java.perform(function() {
            var bt = Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new());
            console.log("Backtrace: " + bt);
        });
    """ if backtrace else ""

    return f"""
// Hook for {class_name}.{method_name}
Java.perform(function() {{
    var clazz = Java.use('{class_name}');
    clazz.{method_name}.implementation = function() {{
        console.log('[+] Hooked {method_name}');
        console.log('Arguments: ', arguments);
        {backtrace_code}
        var result = this.{method_name}.apply(this, arguments);
        console.log('Return value: ', result);
        return result;
    }};
}});
"""


def generate_native_hook(library: str, function: str, num_args: int) -> str:
    """Generate native function hook code."""
    arg_logging = "\n".join([
        f"        console.log('arg[{i}]:', args[{i}]);"
        for i in range(num_args)
    ])

    return f"""
// Hook for {function} in {library}
Interceptor.attach(Module.getExportByName('{library}', '{function}'), {{
    onEnter: function(args) {{
        console.log('[+] Entering {function}');
{arg_logging}
    }},
    onLeave: function(retval) {{
        console.log('[+] Leaving {function}');
        console.log('Return value:', retval);
    }}
}});
"""


# CLI Commands
@app.command()
def list_packages(
    device: Optional[str] = typer.Option(None, "--device", "-d"),
    third_party: bool = typer.Option(False, "--third-party", "-3"),
    system: bool = typer.Option(False, "--system", "-s"),
) -> None:
    """List installed packages."""
    asyncio.run(async_list_packages(device, third_party, system))


async def async_list_packages(
    device: Optional[str], third_party: bool, system: bool
) -> None:
    """Async implementation of list packages."""
    dm = DeviceManager()
    devices = await dm.enumerate_devices()
    
    if not devices:
        console.print("[red]No devices found[/red]")
        return

    dev = devices[0]
    await dm.set_device(dev)

    option = ""
    if third_party:
        option = "-3"
    elif system:
        option = "-s"

    packages = await dm.list_packages(option)
    
    for idx, pkg in enumerate(packages):
        console.print(f"[{idx}] {pkg}")


@app.command()
def modules(
    search: Optional[str] = typer.Option(None, "--search", "-s"),
) -> None:
    """Manage modules."""
    asyncio.run(async_modules(search))


async def async_modules(search: Optional[str]) -> None:
    """Async implementation of modules command."""
    mm = ModuleManager(settings.modules_dir)
    await mm.load_modules()

    if search:
        results = mm.search_modules(search)
        if results:
            for mod in results:
                console.print(f"[green]•[/green] {mod.name}")
        else:
            console.print(f"[yellow]No modules found for '{search}'[/yellow]")
    else:
        modules = mm.get_available_modules()
        console.print(f"[green]Available modules: {len(modules)}[/green]")


if __name__ == "__main__":
    app()
