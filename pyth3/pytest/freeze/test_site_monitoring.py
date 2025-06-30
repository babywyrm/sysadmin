import pytest
import logging
import requests
from freezegun import freeze_time
from datetime import datetime
from site_monitor import SiteMonitor

@pytest.fixture(params=[
    "https://google.com",
    "https://github.com",
    "https://httpbin.org/get"
])
def default_urls(request):
    """Original list of test URLs."""
    return request.param

@pytest.fixture
def cli_url(request):
    """URL override via --url."""
    return request.config.getoption("--url")

@pytest.fixture
def test_url(default_urls, cli_url):
    """Use CLI URL if provided, otherwise one of the defaults."""
    return cli_url or default_urls

@pytest.fixture
def monitor(test_url):
    """Create a SiteMonitor for the test URL."""
    return SiteMonitor(test_url, timeout=15, retries=2)

@pytest.fixture
def custom_monitor():
    """Factory for custom monitors."""
    def _create(url, **kwargs):
        return SiteMonitor(url, **kwargs)
    return _create

class TestSiteMonitoring:

    def test_uptime_check_success(self, monitor):
        result = monitor.check_uptime()
        assert result["status"] == "up"
        assert 200 <= result["status_code"] < 400
        assert result["response_time"] > 0
        assert result["response_time"] < 30
        assert "timestamp" in result
        assert "final_url" in result

    def test_uptime_check_with_retries(self, custom_monitor):
        bad = custom_monitor("https://no-domain-12345.test", retries=2)
        result = bad.check_uptime()
        assert result["status"] == "down"
        assert "error" in result
        assert result["attempts"] == 3

    def test_tls_cipher_check_success(self, monitor):
        if monitor.parsed_url.scheme.lower() != "https":
            pytest.skip("Not HTTPS, skipping TLS tests")
        result = monitor.check_tls_ciphers()
        assert "error" not in result
        assert result["tls_version"] in ["TLSv1.2", "TLSv1.3"]
        assert result["cipher_suite"] is not None
        assert result["security_score"] >= 50
        assert "certificate" in result

    def test_modern_cipher_validation(self, monitor):
        if monitor.parsed_url.scheme.lower() != "https":
            pytest.skip("Not HTTPS, skipping cipher tests")
        result = monitor.check_tls_ciphers()
        if "error" not in result:
            assert result["is_modern_cipher"] is True
            assert result["has_weak_cipher"] is False

    def test_certificate_analysis(self, monitor):
        if monitor.parsed_url.scheme.lower() != "https":
            pytest.skip("Not HTTPS, skipping cert tests")
        result = monitor.check_tls_ciphers()
        cert = result.get("certificate")
        assert cert is not None
        assert "subject" in cert
        assert "issuer" in cert
        assert cert["is_expired"] is False
        assert cert["days_until_expiry"] > 0

    def test_security_score_calculation(self, monitor):
        if monitor.parsed_url.scheme.lower() != "https":
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
        http_only = custom_monitor("http://example.com")
        result = http_only.check_tls_ciphers()
        assert "error" in result
        assert "Not an HTTPS URL" in result["error"]

    def test_invalid_url(self, custom_monitor):
        with pytest.raises(ValueError):
            custom_monitor("not-a-url")

    @freeze_time("2025-06-27 21:27:12")
    def test_uptime_with_frozen_time(self, monitor):
        now = datetime.now()
        result = monitor.check_uptime()
        assert result["status"] == "up"
        assert result["response_time"] > 0
        assert result["timestamp"].startswith(now.isoformat())

    @freeze_time("2025-06-27 21:27:12")
    def test_certificate_expiry_with_frozen_time(self, monitor):
        if monitor.parsed_url.scheme.lower() != "https":
            pytest.skip("Not HTTPS, skipping cert expiry test")
        with freeze_time("2025-12-25 00:00:00"):
            result = monitor.check_tls_ciphers()
            cert = result.get("certificate", {})
            assert "days_until_expiry" in cert

    def test_full_check_integration(self, monitor):
        result = monitor.full_check()
        assert "url" in result
        assert "uptime" in result
        assert "tls" in result
        assert "overall_timestamp" in result
        if result["uptime"]["status"] == "up":
            assert not (result["tls"].get("skipped") and "https" in result["tls"]["skipped"].lower())

    def test_multiple_sites_batch(self, custom_monitor):
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
        monitor = custom_monitor("https://httpbin.org/delay/1", timeout=timeout, retries=retries)
        result = monitor.check_uptime()
        if timeout >= 5:
            assert result["status"] == "up"

    def test_ssl_error_handling(self, custom_monitor):
        bad = custom_monitor("https://self-signed.badssl.com")
        result = bad.check_tls_ciphers()
        assert "error" in result
        assert result["type"] == "ssl_error"

    def test_hsts_header_present(self, cli_url, custom_monitor):
        """
        Ensure the server sends a Strict-Transport-Security header
        with at least 6 months (15768000 seconds) max-age.
        """
        if not cli_url:
            pytest.skip("HSTS test requires --url override")
        url = cli_url
        monitor = custom_monitor(url)
        if monitor.parsed_url.scheme.lower() != "https":
            pytest.skip("HSTS applies only to HTTPS")

        response = requests.head(
            url,
            timeout=monitor.timeout,
            allow_redirects=True,
            verify=True
        )
        hsts = response.headers.get("Strict-Transport-Security")
        assert hsts is not None, "Missing Strict-Transport-Security header"

        parts = {k.strip(): v for k, _, v in (p.partition("=") for p in hsts.split(";"))}
        max_age = int(parts.get("max-age", 0))
        assert max_age >= 15768000, f"Expected max-age ≥ 15768000, got {max_age}"
