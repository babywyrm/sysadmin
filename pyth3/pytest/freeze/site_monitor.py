import ssl
import socket
import requests
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import time


class SiteMonitor:
    # Modern cipher suites we consider secure
    MODERN_CIPHERS = {
        'TLSv1.3': [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
        ],
        'TLSv1.2': [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
        ]
    }
    
    # Weak/deprecated ciphers to flag
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT', 'ADH', 'AECDH'
    ]

    def __init__(self, url: str, timeout: int = 10, retries: int = 3):
        self.url = url
        self.timeout = timeout
        self.retries = retries
        self.parsed_url = urlparse(url)
        self.logger = logging.getLogger(__name__)
        
        if not self.parsed_url.scheme:
            raise ValueError(f"Invalid URL: {url}")

    def check_uptime(self) -> Dict:
        """Check site uptime with retry logic"""
        last_error = None
        
        for attempt in range(self.retries + 1):
            try:
                start_time = time.time()
                response = requests.get(
                    self.url, 
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=True  # Verify SSL certificates
                )
                response_time = time.time() - start_time
                
                return {
                    'status': 'up',
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'final_url': response.url,
                    'attempt': attempt + 1,
                    'headers': dict(response.headers),
                    'timestamp': datetime.now().isoformat()
                }
                
            except requests.exceptions.RequestException as e:
                last_error = e
                self.logger.warning(f"Attempt {attempt + 1} failed: {str(e)}")
                if attempt < self.retries:
                    time.sleep(2 ** attempt)  # Exponential backoff
        
        return {
            'status': 'down',
            'error': str(last_error),
            'attempts': self.retries + 1,
            'timestamp': datetime.now().isoformat()
        }

    def check_tls_ciphers(self) -> Dict:
        """Comprehensive TLS cipher and security check"""
        if self.parsed_url.scheme != 'https':
            return {'error': 'Not an HTTPS URL', 'url': self.url}
        
        hostname = self.parsed_url.hostname
        port = self.parsed_url.port or 443
        
        try:
            # Create SSL context with secure defaults
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher_info = ssock.cipher()
                    tls_version = ssock.version()
                    peer_cert_der = ssock.getpeercert_chain()[0]
                    peer_cert = ssock.getpeercert()
                    
                    # Parse certificate with cryptography
                    cert = x509.load_der_x509_certificate(peer_cert_der, default_backend())
                    
                    return {
                        'tls_version': tls_version,
                        'cipher_suite': cipher_info[0] if cipher_info else None,
                        'cipher_strength': cipher_info[2] if cipher_info else None,
                        'is_modern_cipher': self._is_modern_cipher(cipher_info, tls_version),
                        'has_weak_cipher': self._has_weak_cipher(cipher_info),
                        'certificate': self._analyze_certificate(cert, peer_cert),
                        'security_score': self._calculate_security_score(tls_version, cipher_info, cert),
                        'timestamp': datetime.now().isoformat()
                    }
                    
        except ssl.SSLError as e:
            return {
                'error': f'SSL Error: {str(e)}',
                'type': 'ssl_error',
                'timestamp': datetime.now().isoformat()
            }
        except socket.error as e:
            return {
                'error': f'Connection Error: {str(e)}',
                'type': 'connection_error', 
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'error': f'Unexpected error: {str(e)}',
                'type': 'unknown_error',
                'timestamp': datetime.now().isoformat()
            }

    def _is_modern_cipher(self, cipher_info: Tuple, tls_version: str) -> bool:
        """Check if cipher suite is considered modern"""
        if not cipher_info or not tls_version:
            return False
            
        cipher_name = cipher_info[0]
        
        # TLS 1.3 ciphers are inherently modern
        if tls_version == 'TLSv1.3':
            return True
            
        # Check TLS 1.2 modern ciphers
        if tls_version == 'TLSv1.2':
            return any(modern in cipher_name for modern in self.MODERN_CIPHERS['TLSv1.2'])
            
        # TLS 1.1 and below are not modern
        return False

    def _has_weak_cipher(self, cipher_info: Tuple) -> bool:
        """Check for weak/deprecated cipher components"""
        if not cipher_info:
            return True
            
        cipher_name = cipher_info[0].upper()
        return any(weak in cipher_name for weak in self.WEAK_CIPHERS)

    def _analyze_certificate(self, cert: x509.Certificate, peer_cert: Dict) -> Dict:
        """Analyze SSL certificate details"""
        now = datetime.now()
        
        # Extract certificate details
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        days_until_expiry = (not_after - now).days
        
        # Get subject and issuer
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        
        # Check for SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            san_names = []
        
        return {
            'subject': subject,
            'issuer': issuer,
            'serial_number': str(cert.serial_number),
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'days_until_expiry': days_until_expiry,
            'is_expired': now > not_after,
            'expires_soon': days_until_expiry <= 30,
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'san_names': san_names,
            'key_size': cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else None
        }

    def _calculate_security_score(self, tls_version: str, cipher_info: Tuple, cert: x509.Certificate) -> int:
        """Calculate a security score from 0-100"""
        score = 0
        
        # TLS Version scoring (40 points max)
        if tls_version == 'TLSv1.3':
            score += 40
        elif tls_version == 'TLSv1.2':
            score += 30
        elif tls_version == 'TLSv1.1':
            score += 10
        # TLSv1.0 and below get 0 points
        
        # Cipher scoring (30 points max)
        if self._is_modern_cipher(cipher_info, tls_version):
            score += 30
        elif not self._has_weak_cipher(cipher_info):
            score += 15
        
        # Certificate scoring (30 points max)
        now = datetime.now()
        days_until_expiry = (cert.not_valid_after - now).days
        
        if days_until_expiry > 90:
            score += 15
        elif days_until_expiry > 30:
            score += 10
        elif days_until_expiry > 0:
            score += 5
        
        # Key size bonus
        try:
            key_size = cert.public_key().key_size
            if key_size >= 4096:
                score += 15
            elif key_size >= 2048:
                score += 10
            elif key_size >= 1024:
                score += 5
        except:
            pass
        
        return min(score, 100)

    def full_check(self) -> Dict:
        """Perform both uptime and TLS checks"""
        uptime_result = self.check_uptime()
        
        if uptime_result['status'] == 'up' and self.parsed_url.scheme == 'https':
            tls_result = self.check_tls_ciphers()
        else:
            tls_result = {'skipped': 'Site down or not HTTPS'}
        
        return {
            'url': self.url,
            'uptime': uptime_result,
            'tls': tls_result,
            'overall_timestamp': datetime.now().isoformat()
        }
