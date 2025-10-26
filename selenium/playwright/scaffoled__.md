# Advanced Web Automation Framework

A powerful, feature-rich web automation framework built on Playwright with support for concurrent operations, session persistence, stealth mode, and extensive configuration options.

## 🚀 Features

- **Concurrent Operations**: Execute multiple targets simultaneously with configurable concurrency limits
- **Session Persistence**: Maintain browser contexts and cookies across cycles
- **Stealth Mode**: Anti-detection features to avoid bot detection
- **Multi-Action Support**: Pre/main/post actions with hover, click, fill, select, and custom handlers
- **Smart Retry Logic**: Exponential backoff and intelligent failure handling
- **MFA Support**: Configurable multi-factor authentication handling
- **Statistics Tracking**: Real-time success rates and performance metrics
- **CLI Interface**: Command-line argument parsing with config file support
- **Debug Mode**: Comprehensive logging for troubleshooting

## 📦 Installation ..someday..

```bash
# Clone the repository
git clone https://github.com/yourusername/advanced-web-automation.git
cd advanced-web-automation

# Install dependencies
pip install playwright asyncio

# Install Playwright browsers
playwright install chromium
```

## 🛠️ Quick Start

### 1. Generate Sample Configuration

```bash
python advanced_automation.py --generate-config
```

This creates `automation_config.json` with all available options.

### 2. Basic Usage

```bash
# Run with default configuration
python advanced_automation.py

# Run with custom config file
python advanced_automation.py --config my_config.json

# Run with debug mode enabled
python advanced_automation.py --config my_config.json --debug

# Run with custom session name
python advanced_automation.py --session "my_bot" --debug
```

## 📋 Configuration

The framework uses a JSON configuration file with the following structure:

### Basic Configuration Example

```json
{
  "base_url": "http://localhost:8080",
  "session_name": "my_automation",
  "debug_mode": false,
  
  "auth": {
    "login_url": "/admin/login",
    "username": "admin",
    "password": "password123",
    "username_selector": "#username",
    "password_selector": "#password",
    "submit_action": "Enter",
    "success_indicator": ".dashboard"
  },
  
  "targets": {
    "start_id": 1,
    "end_id": 10,
    "url_template": "/admin/users/{target_id}?cb={random_cb}",
    "actions": [
      {
        "action_type": "hover",
        "selector": "[name='email']",
        "timeout": 3000,
        "retry_count": 2
      }
    ]
  },
  
  "performance": {
    "concurrency": 4,
    "cycle_interval": 30
  },
  
  "browser": {
    "headless": true,
    "stealth_mode": false
  }
}
```

### Configuration Sections

#### Authentication (`auth`)
```json
{
  "login_url": "/login",
  "username": "admin",
  "password": "password123",
  "username_selector": "#user_login",
  "password_selector": "#user_pass", 
  "submit_action": "Enter",
  "success_indicator": ".wp-admin",
  "mfa_handler": null
}
```

#### Target Configuration (`targets`)
```json
{
  "start_id": 1,
  "end_id": 50,
  "url_template": "/admin/entity-edit?id={target_id}&cb={random_cb}",
  "pre_actions": [],
  "actions": [
    {
      "action_type": "hover",
      "selector": "[name='target_field']",
      "timeout": 2000,
      "retry_count": 2,
      "wait_state": "attached"
    }
  ],
  "post_actions": []
}
```

#### Browser Configuration (`browser`)
```json
{
  "headless": true,
  "viewport": {"width": 1920, "height": 1080},
  "user_agent": "Mozilla/5.0...",
  "extra_args": ["--disable-gpu", "--no-sandbox"],
  "cookies_file": "cookies.json",
  "stealth_mode": true
}
```

#### Performance Configuration (`performance`)
```json
{
  "concurrency": 6,
  "nav_timeout": 10000,
  "selector_timeout": 5000,
  "login_timeout": 15000,
  "cycle_interval": 45,
  "max_retries": 3,
  "backoff_factor": 1.5
}
```

## 🎯 Action Types

The framework supports multiple action types:

### Basic Actions
- `hover` - Hover over element
- `click` - Click element
- `focus` - Focus on element
- `fill` - Fill input field (requires `value`)
- `select` - Select dropdown option (requires `value`)

### Action Configuration
```json
{
  "action_type": "fill",
  "selector": "#email",
  "value": "test@example.com",
  "timeout": 3000,
  "retry_count": 2,
  "wait_state": "visible"
}
```

### Custom Actions
For complex operations, implement custom handlers:

```python
async def custom_handler(element, page):
    # Your custom logic here
    await element.scroll_into_view_if_needed()
    await page.wait_for_timeout(1000)
    await element.click()

# In your config
action = ActionConfig(
    action_type="custom",
    selector=".complex-element",
    custom_handler=custom_handler
)
```

## 🔄 Execution Flow

1. **Initialize Session**: Create browser context with configured options
2. **Authenticate**: Login using provided credentials
3. **Target Processing**: 
   - Execute pre-actions (setup)
   - Execute main actions (core automation)
   - Execute post-actions (cleanup)
4. **Statistics**: Track success/failure rates
5. **Wait**: Sleep until next cycle with intelligent backoff
6. **Repeat**: Continue until stopped

## 📊 Monitoring & Statistics

The framework provides real-time statistics:

```
[2024-10-25 20:00:15] [my_bot] INFO: Target operations: 8 succeeded, 2 failed
[2024-10-25 20:00:15] [my_bot] INFO: Stats: 5 cycles, 80.0% success rate
[2024-10-25 20:00:15] [my_bot] INFO: Waiting 30.0s for next cycle
```

## 🛡️ Stealth Mode Features

Enable stealth mode to avoid detection:

```json
{
  "browser": {
    "stealth_mode": true,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "extra_args": [
      "--disable-blink-features=AutomationControlled",
      "--disable-features=VizDisplayCompositor"
    ]
  }
}
```

Features included:
- Removes `navigator.webdriver` property
- Custom user agents
- Specialized browser arguments
- Cookie persistence

## 🎛️ Advanced Usage Examples

### CTF/Security Testing
```json
{
  "base_url": "http://target-site.com",
  "targets": {
    "url_template": "/admin/user-edit.php?user_id={target_id}&cb={random_cb}",
    "actions": [
      {
        "action_type": "hover", 
        "selector": "[name='vulnerable_field']"
      }
    ]
  },
  "performance": {
    "concurrency": 8,
    "cycle_interval": 60
  },
  "browser": {
    "stealth_mode": true
  }
}
```

### Form Automation
```json
{
  "targets": {
    "actions": [
      {
        "action_type": "fill",
        "selector": "#name",
        "value": "Test User"
      },
      {
        "action_type": "select", 
        "selector": "#country",
        "value": "US"
      },
      {
        "action_type": "click",
        "selector": ".submit-btn"
      }
    ]
  }
}
```

### Multi-Factor Authentication
```python
async def handle_mfa(page):
    # Wait for MFA prompt
    await page.wait_for_selector("#mfa-code")
    
    # Get MFA code from your source (SMS, app, etc.)
    mfa_code = get_mfa_code()  # Your implementation
    
    # Fill and submit
    await page.fill("#mfa-code", mfa_code)
    await page.click("#mfa-submit")

# Configure in AuthConfig
config.auth.mfa_handler = handle_mfa
```

## 🔧 CLI Reference

```bash
python advanced_automation.py [OPTIONS]

Options:
  -c, --config FILE     Configuration file path
  -d, --debug          Enable debug mode
  -s, --session NAME   Session name for logging
  --generate-config    Generate sample configuration file
  -h, --help          Show help message
```

## 🐛 Troubleshooting

### Common Issues

1. **Timeouts**: Increase `nav_timeout` and `selector_timeout` values
2. **Element Not Found**: Check selectors and add `wait_state: "visible"`
3. **Login Failures**: Verify selectors and add `success_indicator`
4. **High Memory Usage**: Reduce `concurrency` value
5. **Detection Issues**: Enable `stealth_mode` and customize `user_agent`

### Debug Mode

Enable debug mode for detailed logging:

```bash
python advanced_automation.py --debug
```

This provides:
- Detailed action execution logs
- Element selection attempts
- Timing information
- Error stack traces

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. 
Users are responsible for complying with applicable laws and website terms of service. The authors are not responsible for any misuse or damage caused by this software.

## 🔗 Dependencies

- Python 3.7+
- Playwright
- asyncio (built-in)
- dataclasses (built-in)
- json (built-in)
- logging (built-in)

## 📚 Additional Resources

- [Playwright Documentation](https://playwright.dev/python/)
- [Async/Await in Python](https://docs.python.org/3/library/asyncio.html)
- [Web Automation Best Practices](https://playwright.dev/python/docs/best-practices)
