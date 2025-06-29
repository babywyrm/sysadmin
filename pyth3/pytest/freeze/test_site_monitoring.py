import pytest
import time
from freezegun import freeze_time
from datetime import datetime, timedelta
from site_monitor import SiteMonitor

@pytest.fixture(params=[
    "https://google.com",
    "https://github.com",
    "https://httpbin.org/get"
])
def default_urls(request):
    """
    Original list of test URLs.
    """
    return request.param

@pytest.fixture
def test_url(default_urls, cli_url):
    """
    If --url is provided, use that; otherwise use one of the defaults.
    """
    return cli_url or default_urls

@pytest.fixture
def monitor(test_url):
    """
    Create a SiteMonitor for whichever URL we’re testing.
    """
    return SiteMonitor(test_url, timeout=15, retries=2)

@pytest.fixture
def custom_monitor():
    """
    Factory for custom monitors.
    """
    def _create_monitor(url, **kwargs):
        return SiteMonitor(url, **kwargs)
    return _create_monitor


class TestSiteMonitoring:

    def test_uptime_check_success(self, monitor):
        """Test successful uptime checking"""
        result = monitor.check_uptime()
        assert result["status"] == "up"
        assert 200 <= result["status_code"] < 400
        assert result["response_time"] > 0
        assert result["response_time"] < 30
        assert "timestamp" in result
        assert "final_url" in result

    def test_uptime_check_with_retries(self, custom_monitor):
        """Test retry logic with a non-existent domain"""
        bad = custom_monitor("https://no-domain-12345.test", retries=2)
        result = bad.check_uptime()
        assert result["status"] == "down"
        assert "error" in result
        assert result["attempts"] == 3

    def test_tls_cipher_check_success(self, monitor):
        """Test TLS cipher checking on good sites"""
        # Skip if non-HTTPS
        if not monitor.parsed_url.scheme == "https":
            pytest.skip("Not HTTPS, skipping TLS tests")
        result = monitor.check_tls_ciphers()
        assert "error" not in result
        assert result["tls_version"] in ["TLSv1.2", "TLSv1.3"]
        assert result["cipher_suite"] is not None
        assert result["security_score"] >= 50
        assert "certificate" in result

    def test_modern_cipher_validation(self, monitor):
        """Test that modern cipher validation works"""
        if monitor.parsed_url.scheme != "https":
            pytest.skip("Not HTTPS, skipping cipher tests")
        result = monitor.check_tls_ciphers()
        if "error" not in result:
            assert result["is_modern_cipher"] is True
            assert result["has_weak_cipher"] is False

    def test_certificate_analysis(self, monitor):
        """Test certificate analysis features"""
        if monitor.parsed_url.scheme != "https":
            pytest.skip("Not HTTPS, skipping cert tests")
        result = monitor.check_tls_ciphers()
        if "certificate" in result:
            cert = result["certificate"]
            assert "subject" in cert
            assert "issuer" in cert
            assert cert["is_expired"] is False
            assert cert["days_until_expiry"] > 0

    def test_security_score_calculation(self, monitor):
        """Test security score calculation"""
        if monitor.parsed_url.scheme != "https":
            pytest.skip("Not HTTPS, skipping score tests")
        result = monitor.check_tls_ciphers()
        if "security_score" in result:
            score = result["security_score"]
            assert 0 <= score <= 100
            if result["tls_version"] == "TLSv1.3":
                assert score >= 70
            elif result["tls_version"] == "TLSv1.2" and result["is_modern_cipher"]:
                assert score >= 60

    def test_non_https_url(self, custom_monitor):
        """Test handling of non-HTTPS URLs"""
        http_only = custom_monitor("http://example.com")
        result = http_only.check_tls_ciphers()
        assert "error" in result
        assert "Not an HTTPS URL" in result["error"]

    def test_invalid_url(self, custom_monitor):
        """Test handling of invalid URLs"""
        with pytest.raises(ValueError):
            custom_monitor("not-a-url")

    @freeze_time("2025-06-27 21:27:12")
    def test_uptime_with_frozen_time(self, monitor):
        """Test uptime checking with frozen time"""
        now = datetime.now()
        result = monitor.check_uptime()
        assert result["status"] == "up"
        assert result["response_time"] > 0
        assert result["timestamp"].startswith(now.isoformat())

    @freeze_time("2025-06-27 21:27:12")
    def test_certificate_expiry_with_frozen_time(self, monitor):
        """Test certificate expiry calculation with frozen time"""
        with freeze_time("2025-12-25 00:00:00"):
            if monitor.parsed_url.scheme != "https":
                pytest.skip("Not HTTPS, skipping cert expiry test")
            result = monitor.check_tls_ciphers()
            cert = result.get("certificate", {})
            assert "days_until_expiry" in cert

    def test_full_check_integration(self, monitor):
        """Test the full check integration"""
        result = monitor.full_check()
        assert "url" in result
        assert "uptime" in result
        assert "tls" in result
        assert "overall_timestamp" in result
        if result["uptime"]["status"] == "up":
            assert not (result["tls"].get("skipped") and "https" in result["tls"].get("skipped", "").lower())

    def test_multiple_sites_batch(self, custom_monitor):
        """Test monitoring multiple sites"""
        urls = [
            "https://google.com",
            "https://github.com",
            "https://stackoverflow.com"
        ]
        results = [custom_monitor(u).full_check() for u in urls]
        assert len(results) == 3
        up_count = sum(1 for r in results if r["uptime"]["status"] == "up")
        assert up_count >= 1

    @pytest.mark.parametrize("timeout,retries", [(5,1), (10,2), (15,3)])
    def test_timeout_and_retry_configurations(self, custom_monitor, timeout, retries):
        """Test different timeout and retry configurations"""
        monitor = custom_monitor("https://httpbin.org/delay/1", timeout=timeout, retries=retries)
        result = monitor.check_uptime()
        if timeout >= 5:
            assert result["status"] == "up"

    def test_ssl_error_handling(self, custom_monitor):
        """Test SSL error handling with bad certificates"""
        bad = custom_monitor("https://self-signed.badssl.com")
        result = bad.check_tls_ciphers()
        assert "error" in result
        assert result["type"] == "ssl_error"
##
##
