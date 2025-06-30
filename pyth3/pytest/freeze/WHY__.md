
##
#
https://pytest-with-eric.com/plugins/python-freezegun/
#
https://betterstack.com/community/guides/testing/freezegun-unit-testing/
#
##

# Freezegun + pytest: Complete Guide (Scaffolding, Examples) 

A comprehensive guide for using Freezegun to write deterministic, time-aware pytest tests with clear examples and best practices.

## Table of Contents

1. [Installation & Setup](#installation--setup)
2. [Basic Usage Patterns](#basic-usage-patterns)
3. [Advanced Techniques](#advanced-techniques)
4. [Real-World Examples](#real-world-examples)
5. [Best Practices](#best-practices)
6. [Common Gotchas](#common-gotchas)

## Installation & Setup

### Dependencies

```bash
pip install pytest freezegun pytest-freezegun pytz requests
```

### Project Structure

```
your_project/
├── src/
│   ├── time_utils.py
│   ├── auth.py
│   └── scheduler.py
├── tests/
│   ├── conftest.py
│   ├── test_time_utils.py
│   ├── test_auth.py
│   └── test_scheduler.py
└── requirements.txt
```

## Basic Usage Patterns

### 1. Decorator Pattern

```python
# src/time_utils.py
from datetime import datetime, date

def get_greeting():
    """Return greeting based on current hour."""
    hour = datetime.now().hour
    if hour < 12:
        return "Good morning!"
    elif hour < 18:
        return "Good afternoon!"
    else:
        return "Good evening!"

def is_weekend():
    """Check if today is weekend."""
    return date.today().weekday() >= 5
```

```python
# tests/test_time_utils.py
import pytest
from freezegun import freeze_time
from datetime import datetime, date

from src.time_utils import get_greeting, is_weekend

@freeze_time("2025-06-30 09:00:00")  # Monday morning
def test_morning_greeting():
    assert get_greeting() == "Good morning!"

@freeze_time("2025-06-30 14:30:00")  # Monday afternoon
def test_afternoon_greeting():
    assert get_greeting() == "Good afternoon!"

@freeze_time("2025-06-30 20:00:00")  # Monday evening
def test_evening_greeting():
    assert get_greeting() == "Good evening!"

@freeze_time("2025-06-28")  # Saturday
def test_weekend_detection():
    assert is_weekend() is True

@freeze_time("2025-06-30")  # Monday
def test_weekday_detection():
    assert is_weekend() is False
```

### 2. Context Manager Pattern

```python
# src/scheduler.py
from datetime import datetime, timedelta

class TaskScheduler:
    def __init__(self):
        self.tasks = []
    
    def schedule_task(self, name, delay_minutes=30):
        """Schedule a task to run after delay_minutes."""
        run_at = datetime.now() + timedelta(minutes=delay_minutes)
        task = {"name": name, "run_at": run_at}
        self.tasks.append(task)
        return task
    
    def get_ready_tasks(self):
        """Get tasks ready to run now."""
        now = datetime.now()
        return [task for task in self.tasks if task["run_at"] <= now]
```

```python
# tests/test_scheduler.py
import pytest
from freezegun import freeze_time
from datetime import datetime

from src.scheduler import TaskScheduler

def test_task_scheduling():
    scheduler = TaskScheduler()
    
    # Start at a specific time
    with freeze_time("2025-06-30 10:00:00") as frozen_time:
        # Schedule a task
        task = scheduler.schedule_task("backup", delay_minutes=30)
        
        # No tasks ready initially
        assert len(scheduler.get_ready_tasks()) == 0
        
        # Move time forward by 29 minutes - still not ready
        frozen_time.move_to("2025-06-30 10:29:00")
        assert len(scheduler.get_ready_tasks()) == 0
        
        # Move time forward by 1 more minute - now ready
        frozen_time.move_to("2025-06-30 10:30:00")
        ready_tasks = scheduler.get_ready_tasks()
        assert len(ready_tasks) == 1
        assert ready_tasks[0]["name"] == "backup"
```

### 3. Plugin Fixture Pattern

```python
# tests/conftest.py
import pytest
from freezegun import freeze_time

@pytest.fixture
def scheduler():
    """Provide a clean TaskScheduler instance."""
    from src.scheduler import TaskScheduler
    return TaskScheduler()
```

```python
# Alternative test using pytest-freezegun plugin
def test_with_freezer_fixture(freezer, scheduler):
    """Test using the freezer fixture from pytest-freezegun."""
    # Set initial time
    freezer.move_to("2025-06-30 15:00:00")
    
    # Schedule task
    task = scheduler.schedule_task("email_report", delay_minutes=60)
    assert len(scheduler.get_ready_tasks()) == 0
    
    # Move forward 60 minutes
    freezer.move_to("2025-06-30 16:00:00")
    assert len(scheduler.get_ready_tasks()) == 1
```

## Advanced Techniques

### 1. Parametrized Time Tests

```python
# src/auth.py
from datetime import datetime, timedelta
import secrets

class TokenManager:
    def __init__(self, expiry_minutes=30):
        self.expiry_minutes = expiry_minutes
        self.tokens = {}
    
    def create_token(self, user_id):
        """Create a new token for user."""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(minutes=self.expiry_minutes)
        self.tokens[token] = {
            "user_id": user_id,
            "expires_at": expires_at,
            "created_at": datetime.now()
        }
        return token
    
    def is_valid(self, token):
        """Check if token is valid and not expired."""
        if token not in self.tokens:
            return False
        return datetime.now() < self.tokens[token]["expires_at"]
```

```python
# tests/test_auth.py
import pytest
from freezegun import freeze_time
from datetime import datetime

from src.auth import TokenManager

@pytest.mark.parametrize("minutes_passed,expected_valid", [
    (15, True),   # 15 minutes - should be valid
    (29, True),   # 29 minutes - should be valid
    (30, False),  # 30 minutes - should be expired
    (45, False),  # 45 minutes - should be expired
])
@freeze_time("2025-06-30 10:00:00")
def test_token_expiry(minutes_passed, expected_valid):
    token_manager = TokenManager(expiry_minutes=30)
    
    # Create token at frozen time
    token = token_manager.create_token("user123")
    assert token_manager.is_valid(token) is True
    
    # Move time forward
    with freeze_time(f"2025-06-30 10:{minutes_passed:02d}:00"):
        assert token_manager.is_valid(token) is expected_valid
```

### 2. Auto-tick for Continuous Time

```python
# src/performance.py
from datetime import datetime
import time

class PerformanceTimer:
    def __init__(self):
        self.start_time = datetime.now()
        self.checkpoints = []
    
    def checkpoint(self, name):
        """Record a checkpoint with current time."""
        now = datetime.now()
        elapsed = (now - self.start_time).total_seconds()
        self.checkpoints.append({"name": name, "elapsed": elapsed})
        return elapsed
    
    def get_total_elapsed(self):
        """Get total elapsed time since creation."""
        return (datetime.now() - self.start_time).total_seconds()
```

```python
# tests/test_performance.py
import pytest
from freezegun import freeze_time
import time

from src.performance import PerformanceTimer

def test_performance_timer_with_auto_tick():
    """Test timer with automatic time progression."""
    with freeze_time("2025-06-30 10:00:00", auto_tick_seconds=1):
        timer = PerformanceTimer()
        
        # Each call advances time by 1 second due to auto_tick_seconds=1
        assert timer.checkpoint("start") == 1.0
        assert timer.checkpoint("middle") == 2.0
        assert timer.checkpoint("end") == 3.0
        
        # Total elapsed should be 4 seconds (started + 3 checkpoints)
        assert timer.get_total_elapsed() == 4.0
```

### 3. Timezone Testing

```python
# src/timezone_utils.py
from datetime import datetime
import pytz

def get_business_hours_status(timezone_name="UTC"):
    """Check if current time is within business hours (9-17) for given timezone."""
    tz = pytz.timezone(timezone_name)
    local_time = datetime.now(tz)
    return 9 <= local_time.hour < 17

def convert_utc_to_timezone(utc_dt, timezone_name):
    """Convert UTC datetime to specified timezone."""
    utc_tz = pytz.UTC
    target_tz = pytz.timezone(timezone_name)
    
    if utc_dt.tzinfo is None:
        utc_dt = utc_tz.localize(utc_dt)
    
    return utc_dt.astimezone(target_tz)
```

```python
# tests/test_timezone_utils.py
import pytest
from freezegun import freeze_time
from datetime import datetime
import pytz

from src.timezone_utils import get_business_hours_status, convert_utc_to_timezone

@pytest.mark.parametrize("utc_hour,timezone,expected", [
    (14, "UTC", True),      # 2 PM UTC - business hours
    (18, "UTC", False),     # 6 PM UTC - after hours
    (1, "Asia/Tokyo", False),   # 10 AM JST (1 AM UTC) - business hours
    (8, "Asia/Tokyo", True),    # 5 PM JST (8 AM UTC) - after hours
])
def test_business_hours_by_timezone(utc_hour, timezone, expected):
    with freeze_time(f"2025-06-30 {utc_hour:02d}:00:00", tz_offset=0):
        assert get_business_hours_status(timezone) == expected

@freeze_time("2025-06-30 12:00:00", tz_offset=0)  # Noon UTC
def test_timezone_conversion():
    utc_time = datetime(2025, 6, 30, 12, 0, 0)
    
    # Convert to Tokyo (UTC+9)
    tokyo_time = convert_utc_to_timezone(utc_time, "Asia/Tokyo")
    assert tokyo_time.hour == 21  # 9 PM JST
    
    # Convert to New York (UTC-4 in summer)
    ny_time = convert_utc_to_timezone(utc_time, "America/New_York")
    assert ny_time.hour == 8   # 8 AM EDT
```

## Real-World Examples

### 1. Certificate Expiry Monitoring

```python
# src/cert_monitor.py
from datetime import datetime, timedelta
import ssl
import socket

class CertificateMonitor:
    def __init__(self, hostname, port=443, warning_days=30):
        self.hostname = hostname
        self.port = port
        self.warning_days = warning_days
    
    def get_cert_expiry(self):
        """Get certificate expiry date (mocked for testing)."""
        # In real implementation, this would connect to the server
        # For testing, we'll return a fixed future date
        return datetime.now() + timedelta(days=45)
    
    def check_expiry_status(self):
        """Check certificate expiry status."""
        expiry_date = self.get_cert_expiry()
        now = datetime.now()
        days_until_expiry = (expiry_date - now).days
        
        return {
            "hostname": self.hostname,
            "expiry_date": expiry_date,
            "days_until_expiry": days_until_expiry,
            "expires_soon": days_until_expiry <= self.warning_days,
            "expired": expiry_date <= now
        }
```

```python
# tests/test_cert_monitor.py
import pytest
from freezegun import freeze_time
from datetime import datetime, timedelta
from unittest.mock import patch

from src.cert_monitor import CertificateMonitor

class TestCertificateMonitor:
    
    @freeze_time("2025-06-30")
    def test_certificate_expires_soon(self):
        monitor = CertificateMonitor("example.com", warning_days=30)
        
        # Mock cert expiry to be 20 days from now
        future_date = datetime.now() + timedelta(days=20)
        
        with patch.object(monitor, 'get_cert_expiry', return_value=future_date):
            status = monitor.check_expiry_status()
            
            assert status["expires_soon"] is True
            assert status["expired"] is False
            assert status["days_until_expiry"] == 20
    
    @freeze_time("2025-06-30")
    def test_certificate_expired(self):
        monitor = CertificateMonitor("example.com")
        
        # Mock cert expiry to be 5 days ago
        past_date = datetime.now() - timedelta(days=5)
        
        with patch.object(monitor, 'get_cert_expiry', return_value=past_date):
            status = monitor.check_expiry_status()
            
            assert status["expired"] is True
            assert status["expires_soon"] is True
            assert status["days_until_expiry"] == -5

    @freeze_time("2025-06-30")
    def test_certificate_healthy(self):
        monitor = CertificateMonitor("example.com", warning_days=30)
        
        # Mock cert expiry to be 60 days from now
        future_date = datetime.now() + timedelta(days=60)
        
        with patch.object(monitor, 'get_cert_expiry', return_value=future_date):
            status = monitor.check_expiry_status()
            
            assert status["expired"] is False
            assert status["expires_soon"] is False
            assert status["days_until_expiry"] == 60
```

### 2. Session Management

```python
# src/session.py
from datetime import datetime, timedelta
import uuid

class SessionManager:
    def __init__(self, session_timeout_minutes=30):
        self.sessions = {}
        self.timeout_minutes = session_timeout_minutes
    
    def create_session(self, user_id):
        """Create a new session for user."""
        session_id = str(uuid.uuid4())
        now = datetime.now()
        
        self.sessions[session_id] = {
            "user_id": user_id,
            "created_at": now,
            "last_accessed": now,
            "expires_at": now + timedelta(minutes=self.timeout_minutes)
        }
        
        return session_id
    
    def refresh_session(self, session_id):
        """Refresh session expiry time."""
        if session_id in self.sessions:
            now = datetime.now()
            self.sessions[session_id]["last_accessed"] = now
            self.sessions[session_id]["expires_at"] = now + timedelta(
                minutes=self.timeout_minutes
            )
            return True
        return False
    
    def is_session_valid(self, session_id):
        """Check if session exists and hasn't expired."""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        return datetime.now() < session["expires_at"]
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions."""
        now = datetime.now()
        expired_sessions = [
            sid for sid, session in self.sessions.items()
            if session["expires_at"] <= now
        ]
        
        for sid in expired_sessions:
            del self.sessions[sid]
        
        return len(expired_sessions)
```

```python
# tests/test_session.py
import pytest
from freezegun import freeze_time
from datetime import datetime

from src.session import SessionManager

class TestSessionManager:
    
    @freeze_time("2025-06-30 10:00:00")
    def test_session_creation_and_validation(self):
        manager = SessionManager(session_timeout_minutes=30)
        
        # Create session
        session_id = manager.create_session("user123")
        assert manager.is_session_valid(session_id) is True
        
        # Move forward 29 minutes - should still be valid
        with freeze_time("2025-06-30 10:29:00"):
            assert manager.is_session_valid(session_id) is True
        
        # Move forward 31 minutes - should be expired
        with freeze_time("2025-06-30 10:31:00"):
            assert manager.is_session_valid(session_id) is False
    
    def test_session_refresh_extends_expiry(self):
        with freeze_time("2025-06-30 10:00:00") as frozen_time:
            manager = SessionManager(session_timeout_minutes=30)
            session_id = manager.create_session("user123")
            
            # Move forward 25 minutes and refresh
            frozen_time.move_to("2025-06-30 10:25:00")
            assert manager.refresh_session(session_id) is True
            
            # Move forward another 25 minutes (50 total, 25 since refresh)
            frozen_time.move_to("2025-06-30 10:50:00")
            assert manager.is_session_valid(session_id) is True
            
            # Move forward 5 more minutes (30 since refresh)
            frozen_time.move_to("2025-06-30 10:55:00")
            assert manager.is_session_valid(session_id) is True
            
            # Move forward 1 more minute (31 since refresh)
            frozen_time.move_to("2025-06-30 10:56:00")
            assert manager.is_session_valid(session_id) is False
    
    def test_cleanup_expired_sessions(self):
        with freeze_time("2025-06-30 10:00:00") as frozen_time:
            manager = SessionManager(session_timeout_minutes=30)
            
            # Create multiple sessions
            session1 = manager.create_session("user1")
            session2 = manager.create_session("user2")
            session3 = manager.create_session("user3")
            
            assert len(manager.sessions) == 3
            
            # Move forward 31 minutes - all should expire
            frozen_time.move_to("2025-06-30 10:31:00")
            
            # Cleanup expired sessions
            cleaned_count = manager.cleanup_expired_sessions()
            
            assert cleaned_count == 3
            assert len(manager.sessions) == 0
```

## Best Practices

### 1. Use Fixtures for Common Time Scenarios

```python
# tests/conftest.py
import pytest
from freezegun import freeze_time

@pytest.fixture
def monday_morning():
    """Provide a Monday morning timestamp."""
    with freeze_time("2025-06-30 09:00:00"):  # Monday
        yield

@pytest.fixture
def friday_evening():
    """Provide a Friday evening timestamp."""
    with freeze_time("2025-07-04 18:00:00"):  # Friday
        yield

@pytest.fixture
def weekend():
    """Provide a weekend timestamp."""
    with freeze_time("2025-07-05 14:00:00"):  # Saturday
        yield
```

### 2. Document Time Dependencies Clearly

```python
@freeze_time("2025-06-30 10:00:00")
def test_daily_report_generation():
    """
    Test daily report generation.
    
    Frozen at: Monday, June 30, 2025 at 10:00 AM
    This ensures the report includes the previous day's data
    and runs during business hours.
    """
    # Test implementation
    pass
```

### 3. Use Descriptive Time Values

```python
# Good: Clear what time represents
@freeze_time("2025-12-25 00:00:00")  # Christmas Day
def test_holiday_pricing():
    pass

# Better: Use constants
CHRISTMAS_2025 = "2025-12-25 00:00:00"
NEW_YEARS_2026 = "2026-01-01 00:00:00"

@freeze_time(CHRISTMAS_2025)
def test_holiday_pricing():
    pass
```

## Common Gotchas

### 1. Time Zone Awareness

```python
# Problematic: Assumes local timezone
@freeze_time("2025-06-30 10:00:00")
def test_timezone_problem():
    # This might behave differently on different machines
    pass

# Better: Explicit timezone
@freeze_time("2025-06-30 10:00:00", tz_offset=0)  # UTC
def test_timezone_explicit():
    pass

# Best: Use timezone-aware datetime
from datetime import datetime, timezone

utc_time = datetime(2025, 6, 30, 10, 0, 0, tzinfo=timezone.utc)

@freeze_time(utc_time)
def test_timezone_aware():
    pass
```

### 2. Nested Freezing Behavior

```python
def test_nested_freeze_understanding():
    """Demonstrate how nested freezing works."""
    
    with freeze_time("2025-06-30 10:00:00") as outer:
        assert datetime.now().hour == 10
        
        # Inner freeze overrides outer
        with freeze_time("2025-06-30 15:00:00"):
            assert datetime.now().hour == 15
        
        # Back to outer freeze
        assert datetime.now().hour == 10
        
        # Moving outer freeze
        outer.move_to("2025-06-30 12:00:00")
        assert datetime.now().hour == 12
```

### 3. Auto-tick Precision

```python
def test_auto_tick_precision():
    """Auto-tick might not be precise for very small intervals."""
    
    # This works well
    with freeze_time("2025-06-30 10:00:00", auto_tick_seconds=1):
        start = datetime.now()
        # Each operation advances by 1 second
        end = datetime.now()
        assert (end - start).total_seconds() == 1.0
    
    # This might be less reliable
    with freeze_time("2025-06-30 10:00:00", auto_tick_seconds=0.001):
        # Very small auto-tick intervals can be unpredictable
        pass
```

### 4. Mock Integration

```python
from unittest.mock import patch
from freezegun import freeze_time

# Good: Freeze time, then mock specific methods
@freeze_time("2025-06-30 10:00:00")
def test_with_mocks():
    with patch('src.module.external_api_call') as mock_api:
        mock_api.return_value = {"status": "success"}
        # Test implementation using frozen time and mocked API
        pass

# Avoid: Complex interactions between freezegun and mocks
# Can lead to unexpected behavior
```
