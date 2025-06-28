import pytest
import time
from freezegun import freeze_time
from datetime import datetime, timedelta
from site_monitor import SiteMonitor


class TestSiteMonitoring:
    
    @pytest.fixture(params=[
        'https://google.com',
        'https://github.com', 
        'https://httpbin.org/get'
    ])
    def test_urls(self, request):
        """Parameterized fixture for multiple test URLs"""
        return request.param
    
    @pytest.fixture
    def monitor(self, test_urls):
        """Create monitor instance for test URLs"""
        return SiteMonitor(test_urls, timeout=15, retries=2)
    
    @pytest.fixture
    def custom_monitor(self):
        """Factory for custom monitors"""
        def _create_monitor(url, **kwargs):
            return SiteMonitor(url, **kwargs)
        return _create_monitor

    def test_uptime_check_success(self, monitor):
        """Test successful uptime checking"""
        result = monitor.check_uptime()
        
        assert result['status'] == 'up'
        assert 200 <= result['status_code'] < 400
        assert result['response_time'] > 0
        assert result['response_time'] < 30  # Reasonable timeout
        assert 'timestamp' in result
        assert 'final_url' in result

    def test_uptime_check_with_retries(self, custom_monitor):
        """Test retry logic with a non-existent domain"""
        monitor = custom_monitor('https://this-domain-should-not-exist-12345.com', retries=2)
        result = monitor.check_uptime()
        
        assert result['status'] == 'down'
        assert 'error' in result
        assert result['attempts'] == 3  # 1 initial + 2 retries

    def test_tls_cipher_check_success(self, monitor):
        """Test TLS cipher checking on good sites"""
        result = monitor.check_tls_ciphers()
        
        assert 'error' not in result
        assert result['tls_version'] in ['TLSv1.2', 'TLSv1.3']
        assert result['cipher_suite'] is not None
        assert result['security_score'] >= 50  # Reasonable security threshold
        assert 'certificate' in result

    def test_modern_cipher_validation(self, monitor):
        """Test that modern cipher validation works"""
        result = monitor.check_tls_ciphers()
        
        if 'error' not in result:
            # Most major sites should have modern ciphers
            assert result['is_modern_cipher'] is True
            assert result['has_weak_cipher'] is False

    def test_certificate_analysis(self, monitor):
        """Test certificate analysis features"""
        result = monitor.check_tls_ciphers()
        
        if 'error' not in result and 'certificate' in result:
            cert = result['certificate']
            
            assert 'subject' in cert
            assert 'issuer' in cert
            assert 'days_until_expiry' in cert
            assert 'is_expired' in cert
            assert cert['is_expired'] is False  # Should not be expired
            assert cert['days_until_expiry'] > 0

    def test_security_score_calculation(self, monitor):
        """Test security score calculation"""
        result = monitor.check_tls_ciphers()
        
        if 'error' not in result:
            score = result['security_score']
            assert 0 <= score <= 100
            
            # Good sites should have decent scores
            if result['tls_version'] == 'TLSv1.3':
                assert score >= 70
            elif result['tls_version'] == 'TLSv1.2' and result['is_modern_cipher']:
                assert score >= 60

    def test_non_https_url(self, custom_monitor):
        """Test handling of non-HTTPS URLs"""
        monitor = custom_monitor('http://httpbin.org/get')
        result = monitor.check_tls_ciphers()
        
        assert 'error' in result
        assert 'Not an HTTPS URL' in result['error']

    def test_invalid_url(self, custom_monitor):
        """Test handling of invalid URLs"""
        with pytest.raises(ValueError):
            custom_monitor('not-a-url')

    @freeze_time("2025-06-27 21:27:12")
    def test_uptime_with_frozen_time(self, monitor):
        """Test uptime checking with frozen time for reproducible tests"""
        frozen_time = datetime.now()
        result = monitor.check_uptime()
        
        assert result['status'] == 'up'
        # Response time should still be measured accurately
        assert result['response_time'] > 0
        assert frozen_time.isoformat() in result['timestamp']

    @freeze_time("2025-06-27 21:27:12")
    def test_certificate_expiry_with_frozen_time(self, monitor):
        """Test certificate expiry calculation with frozen time"""
        with freeze_time("2025-12-25 00:00:00"):  # Christmas 2025
            result = monitor.check_tls_ciphers()
            
            if 'error' not in result and 'certificate' in result:
                # The days calculation should be based on frozen time
                cert = result['certificate']
                assert 'days_until_expiry' in cert

    def test_full_check_integration(self, monitor):
        """Test the full check integration"""
        result = monitor.full_check()
        
        assert 'url' in result
        assert 'uptime' in result
        assert 'tls' in result
        assert 'overall_timestamp' in result
        
        # If uptime check succeeds, TLS should be checked too
        if result['uptime']['status'] == 'up':
            assert 'skipped' not in result['tls'] or 'error' in result['tls']

    def test_multiple_sites_batch(self, custom_monitor):
        """Test monitoring multiple sites"""
        urls = [
            'https://google.com',
            'https://github.com',
            'https://stackoverflow.com'
        ]
        
        results = []
        for url in urls:
            monitor = custom_monitor(url)
            results.append(monitor.full_check())
        
        assert len(results) == 3
        
        # At least some should be up (assuming internet connectivity)
        up_count = sum(1 for r in results if r['uptime']['status'] == 'up')
        assert up_count >= 1

    @pytest.mark.parametrize("timeout,retries", [
        (5, 1),
        (10, 2), 
        (15, 3)
    ])
    def test_timeout_and_retry_configurations(self, custom_monitor, timeout, retries):
        """Test different timeout and retry configurations"""
        monitor = custom_monitor('https://httpbin.org/delay/1', timeout=timeout, retries=retries)
        result = monitor.check_uptime()
        
        # Should succeed with reasonable timeouts
        if timeout >= 5:
            assert result['status'] == 'up'

    def test_ssl_error_handling(self, custom_monitor):
        """Test SSL error handling with bad certificates"""
        # Using a site known for SSL issues (self-signed, expired, etc.)
        monitor = custom_monitor('https://self-signed.badssl.com')
        result = monitor.check_tls_ciphers()
        
        # Should gracefully handle SSL errors
        assert 'error' in result
        assert result['type'] == 'ssl_error'


if __name__ == '__main__':
    # Example usage
    monitor = SiteMonitor('https://google.com')
    result = monitor.full_check()
    print(f"Results for {result['url']}:")
    print(f"Uptime: {result['uptime']['status']}")
    if 'security_score' in result['tls']:
        print(f"Security Score: {result['tls']['security_score']}/100")
