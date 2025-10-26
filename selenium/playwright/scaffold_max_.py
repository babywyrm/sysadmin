# advanced_web_automation_scaffold.py
import asyncio
import time
import random
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Callable, Any
from pathlib import Path
from playwright.async_api import async_playwright, TimeoutError as PWTimeoutError, Page, BrowserContext
from contextlib import asynccontextmanager
import argparse

@dataclass
class ActionConfig:
    """Configuration for a single action"""
    action_type: str  # hover, click, focus, fill, select, custom
    selector: str
    value: Optional[str] = None  # for fill, select actions
    timeout: int = 2000
    retry_count: int = 2
    wait_state: str = "attached"  # attached, visible, hidden
    custom_handler: Optional[Callable] = None

@dataclass
class TargetConfig:
    """Configuration for target operations"""
    start_id: int = 1
    end_id: int = 10
    url_template: str = "/admin/entity/{target_id}"
    actions: List[ActionConfig] = field(default_factory=list)
    pre_actions: List[ActionConfig] = field(default_factory=list)  # actions before main actions
    post_actions: List[ActionConfig] = field(default_factory=list)  # actions after main actions

@dataclass
class AuthConfig:
    """Authentication configuration"""
    login_url: str = "/login"
    username: str = "admin"
    password: str = "password"
    username_selector: str = "#username"
    password_selector: str = "#password"
    submit_action: str = "Enter"  # key or selector
    success_indicator: Optional[str] = None  # selector that indicates successful login
    mfa_handler: Optional[Callable] = None

@dataclass
class BrowserConfig:
    """Browser configuration"""
    headless: bool = True
    viewport: Dict[str, int] = field(default_factory=lambda: {"width": 1920, "height": 1080})
    user_agent: Optional[str] = None
    extra_args: List[str] = field(default_factory=lambda: ["--disable-gpu", "--no-sandbox"])
    cookies_file: Optional[str] = None
    stealth_mode: bool = False

@dataclass
class PerformanceConfig:
    """Performance and timing configuration"""
    concurrency: int = 4
    nav_timeout: int = 10000
    selector_timeout: int = 5000
    login_timeout: int = 15000
    cycle_interval: int = 30
    max_retries: int = 3
    backoff_factor: float = 1.5

@dataclass
class AutomationConfig:
    """Main configuration class"""
    base_url: str = "http://localhost:8080"
    auth: AuthConfig = field(default_factory=AuthConfig)
    targets: TargetConfig = field(default_factory=TargetConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    session_name: str = "default"
    debug_mode: bool = False

class AutomationLogger:
    """Enhanced logging with different levels and session tracking"""
    
    def __init__(self, session_name: str, debug: bool = False):
        self.session_name = session_name
        self.logger = logging.getLogger(f"automation.{session_name}")
        
        level = logging.DEBUG if debug else logging.INFO
        self.logger.setLevel(level)
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                f'[%(asctime)s] [{session_name}] %(levelname)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def debug(self, msg: str): self.logger.debug(msg)
    def info(self, msg: str): self.logger.info(msg)
    def warning(self, msg: str): self.logger.warning(msg)
    def error(self, msg: str): self.logger.error(msg)

class SessionManager:
    """Manages browser sessions and context persistence"""
    
    def __init__(self, config: AutomationConfig, logger: AutomationLogger):
        self.config = config
        self.logger = logger
        self.context: Optional[BrowserContext] = None
        self.browser = None
        
    async def __aenter__(self):
        self.playwright = await async_playwright().__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.browser:
            await self.browser.close()
        await self.playwright.__aexit__(exc_type, exc_val, exc_tb)
    
    @asynccontextmanager
    async def get_context(self):
        """Get or create browser context with session persistence"""
        if not self.context:
            await self._create_browser_context()
        
        try:
            yield self.context
        except Exception as e:
            self.logger.error(f"Context error: {e}")
            # Recreate context on error
            if self.context:
                await self.context.close()
                self.context = None
            await self._create_browser_context()
            yield self.context
    
    async def _create_browser_context(self):
        """Create browser and context with full configuration"""
        browser_args = self.config.browser.extra_args.copy()
        
        if self.config.browser.stealth_mode:
            browser_args.extend([
                "--disable-blink-features=AutomationControlled",
                "--disable-features=VizDisplayCompositor"
            ])
        
        self.browser = await self.playwright.chromium.launch(
            headless=self.config.browser.headless,
            args=browser_args
        )
        
        context_options = {
            "viewport": self.config.browser.viewport,
            "user_agent": self.config.browser.user_agent,
        }
        
        # Load cookies if specified
        if self.config.browser.cookies_file:
            cookies_path = Path(self.config.browser.cookies_file)
            if cookies_path.exists():
                with open(cookies_path, 'r') as f:
                    cookies = json.load(f)
                context_options["storage_state"] = {"cookies": cookies}
        
        self.context = await self.browser.new_context(**{k: v for k, v in context_options.items() if v is not None})
        
        # Set timeouts
        self.context.set_default_navigation_timeout(self.config.performance.nav_timeout)
        self.context.set_default_timeout(self.config.performance.selector_timeout)
        
        if self.config.browser.stealth_mode:
            await self.context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined})
            """)

class ActionExecutor:
    """Handles execution of various page actions"""
    
    def __init__(self, page: Page, logger: AutomationLogger):
        self.page = page
        self.logger = logger
    
    async def execute_action(self, action: ActionConfig) -> bool:
        """Execute a single action with retry logic"""
        for attempt in range(1, action.retry_count + 1):
            try:
                # Wait for element
                element = await self.page.wait_for_selector(
                    action.selector,
                    state=action.wait_state,
                    timeout=action.timeout
                )
                
                if not element:
                    self.logger.warning(f"Element not found: {action.selector}")
                    continue
                
                # Execute action
                success = await self._perform_action(element, action)
                if success:
                    self.logger.debug(f"Action '{action.action_type}' succeeded on attempt {attempt}")
                    return True
                    
            except PWTimeoutError:
                self.logger.warning(f"Timeout waiting for {action.selector} (attempt {attempt})")
            except Exception as e:
                self.logger.warning(f"Action failed (attempt {attempt}): {e}")
        
        return False
    
    async def _perform_action(self, element, action: ActionConfig) -> bool:
        """Perform the actual action on the element"""
        action_type = action.action_type.lower()
        
        if action_type == "hover":
            await element.hover(timeout=action.timeout)
        elif action_type == "click":
            await element.click(timeout=action.timeout)
        elif action_type == "focus":
            await element.focus(timeout=action.timeout)
        elif action_type == "fill":
            await element.fill(action.value or "", timeout=action.timeout)
        elif action_type == "select":
            await element.select_option(value=action.value, timeout=action.timeout)
        elif action_type == "custom" and action.custom_handler:
            await action.custom_handler(element, self.page)
        else:
            self.logger.error(f"Unknown action type: {action_type}")
            return False
        
        return True

class WebAutomationFramework:
    """Main automation framework class"""
    
    def __init__(self, config: AutomationConfig):
        self.config = config
        self.logger = AutomationLogger(config.session_name, config.debug_mode)
        self.session_manager = None
        self.stats = {
            "cycles_completed": 0,
            "total_targets": 0,
            "successful_operations": 0,
            "failed_operations": 0
        }
    
    async def run(self):
        """Main execution method"""
        self.logger.info("Starting advanced web automation framework")
        
        async with SessionManager(self.config, self.logger) as session_manager:
            self.session_manager = session_manager
            
            while True:
                await self._execute_cycle()
                await self._wait_for_next_cycle()
    
    async def _execute_cycle(self):
        """Execute one automation cycle"""
        cycle_start = time.time()
        self.logger.info("Starting new automation cycle")
        
        try:
            async with self.session_manager.get_context() as context:
                # Authenticate if needed
                await self._authenticate(context)
                
                # Execute target operations concurrently
                await self._execute_target_operations(context)
                
        except Exception as e:
            self.logger.error(f"Cycle failed: {e}")
            self.stats["failed_operations"] += 1
        
        finally:
            cycle_duration = time.time() - cycle_start
            self.stats["cycles_completed"] += 1
            self.logger.info(f"Cycle completed in {cycle_duration:.2f}s")
            self._log_stats()
    
    async def _authenticate(self, context: BrowserContext):
        """Handle authentication flow"""
        page = await context.new_page()
        try:
            login_url = f"{self.config.base_url}{self.config.auth.login_url}"
            self.logger.info("Starting authentication")
            
            await page.goto(login_url, wait_until="domcontentloaded", timeout=self.config.performance.login_timeout)
            
            # Fill credentials
            await page.wait_for_selector(self.config.auth.username_selector, timeout=self.config.performance.login_timeout)
            await page.fill(self.config.auth.username_selector, self.config.auth.username)
            await page.fill(self.config.auth.password_selector, self.config.auth.password)
            
            # Submit
            if self.config.auth.submit_action.startswith("#") or self.config.auth.submit_action.startswith("."):
                await page.click(self.config.auth.submit_action)
            else:
                await page.press(self.config.auth.password_selector, self.config.auth.submit_action)
            
            # Handle MFA if configured
            if self.config.auth.mfa_handler:
                await self.config.auth.mfa_handler(page)
            
            # Wait for success indicator
            if self.config.auth.success_indicator:
                await page.wait_for_selector(self.config.auth.success_indicator, timeout=self.config.performance.login_timeout)
            else:
                await page.wait_for_load_state("networkidle", timeout=self.config.performance.login_timeout)
            
            self.logger.info("Authentication successful")
            
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            raise
        finally:
            await page.close()
    
    async def _execute_target_operations(self, context: BrowserContext):
        """Execute operations on all targets concurrently"""
        semaphore = asyncio.Semaphore(self.config.performance.concurrency)
        tasks = []
        
        for target_id in range(self.config.targets.start_id, self.config.targets.end_id):
            task = asyncio.create_task(self._process_target(context, target_id, semaphore))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        successes = sum(1 for r in results if r is True)
        failures = len(results) - successes
        
        self.stats["total_targets"] += len(results)
        self.stats["successful_operations"] += successes
        self.stats["failed_operations"] += failures
        
        self.logger.info(f"Target operations: {successes} succeeded, {failures} failed")
    
    async def _process_target(self, context: BrowserContext, target_id: int, semaphore: asyncio.Semaphore) -> bool:
        """Process a single target with all configured actions"""
        async with semaphore:
            page = await context.new_page()
            executor = ActionExecutor(page, self.logger)
            
            try:
                # Navigate to target
                target_url = f"{self.config.base_url}{self.config.targets.url_template.format(target_id=target_id, random_cb=random.randint(100000, 999999))}"
                await page.goto(target_url, wait_until="domcontentloaded", timeout=self.config.performance.nav_timeout)
                
                # Execute pre-actions
                for action in self.config.targets.pre_actions:
                    await executor.execute_action(action)
                
                # Execute main actions
                success = True
                for action in self.config.targets.actions:
                    if not await executor.execute_action(action):
                        success = False
                
                # Execute post-actions
                for action in self.config.targets.post_actions:
                    await executor.execute_action(action)
                
                if success:
                    self.logger.debug(f"Target {target_id} processed successfully")
                return success
                
            except Exception as e:
                self.logger.error(f"Target {target_id} failed: {e}")
                return False
            finally:
                await page.close()
    
    async def _wait_for_next_cycle(self):
        """Wait for the next cycle with exponential backoff on failures"""
        base_interval = self.config.performance.cycle_interval
        
        # Implement exponential backoff based on recent failures
        recent_failure_rate = self.stats["failed_operations"] / max(1, self.stats["total_targets"])
        if recent_failure_rate > 0.5:  # More than 50% failures
            backoff_multiplier = self.config.performance.backoff_factor
            actual_interval = base_interval * backoff_multiplier
            self.logger.warning(f"High failure rate detected, using backoff: {actual_interval:.1f}s")
        else:
            actual_interval = base_interval
        
        self.logger.info(f"Waiting {actual_interval:.1f}s for next cycle")
        await asyncio.sleep(actual_interval)
    
    def _log_stats(self):
        """Log current statistics"""
        if self.stats["total_targets"] > 0:
            success_rate = (self.stats["successful_operations"] / self.stats["total_targets"]) * 100
            self.logger.info(f"Stats: {self.stats['cycles_completed']} cycles, {success_rate:.1f}% success rate")

def load_config_from_file(config_file: str) -> AutomationConfig:
    """Load configuration from JSON file"""
    with open(config_file, 'r') as f:
        config_dict = json.load(f)
    
    # Convert nested dicts to dataclass instances
    # This is a simplified version - you'd want more robust parsing in production
    return AutomationConfig(**config_dict)

def create_sample_config() -> AutomationConfig:
    """Create a sample configuration"""
    return AutomationConfig(
        base_url="http://localhost:8080",
        auth=AuthConfig(
            login_url="/admin/login",
            username="admin",
            password="password123"
        ),
        targets=TargetConfig(
            start_id=1,
            end_id=10,
            url_template="/admin/users/{target_id}?cb={random_cb}",
            actions=[
                ActionConfig("hover", "[name='email']"),
                ActionConfig("click", ".save-btn", retry_count=3)
            ]
        ),
        performance=PerformanceConfig(
            concurrency=6,
            cycle_interval=45
        ),
        browser=BrowserConfig(
            stealth_mode=True,
            viewport={"width": 1366, "height": 768}
        )
    )

async def main():
    """Main entry point with CLI argument parsing"""
    parser = argparse.ArgumentParser(description="Advanced Web Automation Framework")
    parser.add_argument("--config", "-c", help="Configuration file path")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug mode")
    parser.add_argument("--session", "-s", default="default", help="Session name")
    parser.add_argument("--generate-config", action="store_true", help="Generate sample config file")
    
    args = parser.parse_args()
    
    if args.generate_config:
        config = create_sample_config()
        with open("automation_config.json", "w") as f:
            json.dump(config.__dict__, f, indent=2, default=str)
        print("Sample config generated: automation_config.json")
        return
    
    # Load configuration
    if args.config:
        config = load_config_from_file(args.config)
    else:
        config = create_sample_config()
    
    if args.debug:
        config.debug_mode = True
    if args.session:
        config.session_name = args.session
    
    # Run automation
    framework = WebAutomationFramework(config)
    await framework.run()

if __name__ == "__main__":
    asyncio.run(main())
