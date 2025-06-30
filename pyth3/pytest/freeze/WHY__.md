
##
#
https://pytest-with-eric.com/plugins/python-freezegun/
#
https://betterstack.com/community/guides/testing/freezegun-unit-testing/
#
##


# Freezegun + pytest: Consolidated Guide

This guide brings together core concepts, examples, and best practices for using Freezegun to write deterministic, time-aware pytest tests.

It’s organized into logical sections for easy reference.

---

## Contents

1. Prerequisites  
2. Installation & Project Setup  
3. Basic Usage  
   - Decorator  
   - Context Manager  
   - Plugin Fixture  
4. Freezing in Fixtures  
5. Parametrized and Nested Freezes  
6. Simulating Passage of Time  
   - Manual `move_to`  
   - Auto-tick  
7. Time-Zone Testing  
8. Example: Greeting Function  
9. Example: Age & Token Expiry  
10. Example: Simple Timer with Auto-tick  
11. Example: HSTS Header Test (integration)  
12. Best Practices & Gotchas  
13. Further Reading  

---

## 1. Prerequisites

- Python 3.11+ (3.13+ recommended for newer features)  
- Basic familiarity with pytest and fixtures  
- Optional: `pytz` for timezone examples  

---

## 2. Installation & Project Setup

1. **Create a virtual environment**  
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
````

2. **Install dependencies**

   ```bash
   pip install pytest freezegun pytest-freezegun requests cryptography
   ```

3. **Add to `requirements.txt`**

   ```
   pytest
   freezegun
   pytest-freezegun
   requests
   cryptography
   ```

4. **Directory structure**

   ```
   your_project/
   ├── site_monitor.py
   ├── test_site_monitoring.py
   ├── conftest.py
   ├── time_functions.py
   ├── time_travel.py
   ├── timer.py
   ├── timezone_functions.py
   └── requirements.txt
   ```

---

## 3. Basic Usage

### 3.1 Decorator

```python
from freezegun import freeze_time
from datetime import datetime

@freeze_time("2025-06-27 21:27:12")
def test_timestamp():
    assert datetime.now().isoformat().startswith("2025-06-27T21:27:12")
```

### 3.2 Context Manager

```python
def test_partial_freeze():
    # non-time-dependent code
    with freeze_time("2025-01-01"):
        assert date.today() == date(2025, 1, 1)
```

### 3.3 Plugin Fixture

```python
def test_with_plugin(freezer):
    freezer.move_to("2025-12-25")
    assert datetime.now().month == 12
```

---

## 4. Freezing in Fixtures

```python
# conftest.py
import pytest
from freezegun import freeze_time

@pytest.fixture(scope="session", autouse=True)
def freeze_all():
    with freeze_time("2025-06-27 00:00:00"):
        yield
```

All tests see the same frozen “now”.

---

## 5. Parametrized & Nested Freezes

```python
@freeze_time("2025-06-27")
@pytest.mark.parametrize("days,expect", [(10, True), (40, False)])
def test_expires_soon(days, expect, monitor):
    cert = monitor._load_cert()
    info = monitor._analyze_certificate(cert)
    assert info["expires_soon"] == expect
```

Nested:

```python
def test_nested_freeze():
    with freeze_time("2025-06-27"):
        data = fn()
        with freeze_time("2025-07-01"):
            assert fn2() > data
```

---

## 6. Simulating Passage of Time

### 6.1 Manual `move_to`

```python
with freeze_time("2023-05-15") as frozen:
    frozen.move_to("2023-06-15")
    assert fn()  # now sees June 15
```

### 6.2 Auto-tick

```python
with freeze_time("2023-05-15 10:00:00", auto_tick_seconds=2):
    timer = SimpleTimer()
    assert timer.elapsed_seconds() == 2.0
    assert timer.elapsed_seconds() == 4.0
```

---

## 7. Time-Zone Testing

```python
@freeze_time("2023-05-15 12:00:00", tz_offset=0)
def test_timezones():
    assert get_current_time_in_timezone("UTC").hour == 12
    assert get_current_time_in_timezone("Asia/Tokyo").hour == 21
```

---

## 8. Example: Greeting Function

```python
# time_functions.py
from datetime import datetime
def get_greeting():
    h = datetime.now().hour
    if h < 12: return "Good morning!"
    if h < 18: return "Good afternoon!"
    return "Good evening!"

# tests/test_greeting.py
from freezegun import freeze_time
@freeze_time("2025-01-01 09:00:00")
def test_morning(): assert get_greeting() == "Good morning!"
```

---

## 9. Example: Age & Token Expiry

```python
# time_travel.py
def calculate_age(birth):
    today = datetime.now()
    # ...
def is_token_expired(ts, expiry_minutes=30):
    return datetime.now() > ts + timedelta(minutes=expiry_minutes)

# tests/test_time_travel.py
def test_age_and_token():
    with freeze_time("2023-05-15") as fr:
        assert calculate_age(date(2000,5,16)) == 22
        fr.move_to("2023-05-16")
        assert calculate_age(date(2000,5,16)) == 23

    with freeze_time("2023-05-15 10:00"):
        ts = datetime.now()
        assert not is_token_expired(ts)
        fr.move_to("2023-05-15 10:31")
        assert is_token_expired(ts)
```

---

## 10. Example: Simple Timer with Auto-tick

```python
# timer.py
class SimpleTimer:
    def __init__(self): self.start = datetime.now()
    def elapsed_seconds(self): return (datetime.now() - self.start).total_seconds()

# tests/test_auto_tick.py
with freeze_time("2023-05-15 10:00", auto_tick_seconds=2):
    timer = SimpleTimer()
    assert timer.elapsed_seconds() == 2
```

---

## 11. Example: HSTS Header Test

```python
def test_hsts_header_present(cli_url, custom_monitor):
    import requests
    if not cli_url: pytest.skip("requires --url")
    m = custom_monitor(cli_url)
    if m.parsed_url.scheme!="https": pytest.skip("only HTTPS")
    resp = requests.head(cli_url, timeout=m.timeout, allow_redirects=True)
    hsts = resp.headers.get("Strict-Transport-Security")
    assert hsts, "Missing HSTS header"
    parts = dict(p.partition("=")[::2] for p in hsts.split(";"))
    assert int(parts.get("max-age",0)) >= 15768000
```

---

## 12. Best Practices & Gotchas

* **Freeze only where needed** to avoid hidden dependencies.
* **Use high-resolution timers** (`perf_counter_ns`) for elapsed-time tests.
* **Clean up**: always stop manual freezes (use context managers/fixtures).
* **Document** each freeze with a clear reason.
* **Avoid over-freezing**: if many tests need time injection, consider passing a clock dependency instead.

---

## 13. Further Reading

* [Freezegun on PyPI](https://pypi.org/project/freezegun/)
* [pytest-freezegun Plugin](https://pypi.org/project/pytest-freezegun/)
* Freezegun GitHub: [https://github.com/spulec/freezegun](https://github.com/spulec/freezegun)

##
##
