## How to Add a New Test Case  :D :D 

Follow these steps to add a clear, maintainable test to this suite:

1. Identify the behavior or scenario  
   - Choose the method or logic you want to verify (e.g. a specific cipher edge case, retry back-off, certificate expiry).  
   - Give your test a descriptive name that begins with `test_`.

2. Select or create fixtures  
   - To target a specific URL, rely on the existing `cli_url` fixture (from `--url`) or add a new parametrized fixture in `test_site_monitoring.py`.  
   - For time-dependent logic, apply `@freeze_time("YYYY-MM-DD HH:MM:SS")` to freeze `datetime.now()`.

3. Write the test function  
   ```python
   def test_example_cipher_edge_case(custom_monitor):
       # Arrange
       url = "https://example-edge-cipher.test"
       monitor = custom_monitor(url, timeout=5, retries=1)

       # Act
       result = monitor.check_tls_ciphers()

       # Assert
       assert result["tls_version"] in ("TLSv1.2", "TLSv1.3")
       assert result["has_weak_cipher"] is False

4. Use parametrization or markers for multiple inputs

```python
@pytest.mark.parametrize("cipher_string,expected", [
    ("TLS_AES_256_GCM_SHA384", True),
    ("RC4-SHA", False),
])
def test__is_modern_cipher_param(monitor, cipher_string, expected):
    info = (cipher_string, None, None)
    assert monitor._is_modern_cipher(info, "TLSv1.3") == expected
```

5. Capture logs for retry/back-off tests

```python
def test_retry_backoff_logging(caplog, custom_monitor):
    caplog.set_level(logging.WARNING, logger="site_monitor")
    bad = custom_monitor("https://nonexistent.test", retries=2)
    bad.check_uptime()
    assert "Attempt 1 failed" in caplog.text
    assert "Attempt 2 failed" in caplog.text
```

```
pytest -q
```

# Ensure your new test passes and does not break existing ones.

# If you add any new dependencies (e.g. requests-mock), update requirements.txt accordingly.
