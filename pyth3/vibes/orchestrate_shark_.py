#!/usr/bin/env python3
"""
Real-Time PTR Traffic Analyzer
Captures traffic WHILE triggering queries simultaneously
"""

import pyshark
import subprocess
import threading
import time
import json
from collections import defaultdict
import queue

class RealTimePTRAnalyzer:
    def __init__(self):
        self.traffic_queue = queue.Queue()
        self.dns_traffic = []
        self.mdns_traffic = []
        self.running = False
        
        # Your known IPs
        self.target_ips = [
            '192.168.1.65', '192.168.1.83', '192.168.1.102', '192.168.1.113',
            '192.168.1.150', '192.168.1.154', '192.168.1.160', '192.168.1.169',
            '192.168.1.180', '192.168.1.182', '192.168.1.190', '192.168.1.199',
            '192.168.1.213', '192.168.1.218', '192.168.1.223', '192.168.1.233',
            '192.168.1.247', '192.168.1.248', '192.168.1.250', '192.168.1.254'
        ]
    
    def start_live_capture(self):
        """Start live packet capture"""
        print("🎯 Starting live capture...")
        
        try:
            # Simplified capture - focus on DNS/mDNS
            capture = pyshark.LiveCapture(
                interface='en0',
                bpf_filter='port 53 or port 5353',
                display_filter='dns or mdns'
            )
            
            self.running = True
            
            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                
                # Process packet immediately
                self.process_packet_realtime(packet)
                
        except Exception as e:
            print(f"❌ Capture failed: {e}")
    
    def process_packet_realtime(self, packet):
        """Process packets in real-time with better parsing"""
        try:
            timestamp = str(packet.sniff_time)
            
            # Debug: Show raw packet info
            if hasattr(packet, 'ip'):
                src = packet.ip.src
                dst = packet.ip.dst
                
                # DNS Processing
                if hasattr(packet, 'dns'):
                    self.process_dns_realtime(packet, timestamp, src, dst)
                
                # mDNS Processing
                elif hasattr(packet, 'mdns'):
                    self.process_mdns_realtime(packet, timestamp, src, dst)
            
        except Exception as e:
            # Debug: print parsing errors
            print(f"⚠️  Packet parsing error: {e}")
    
    def process_dns_realtime(self, packet, timestamp, src, dst):
        """Process DNS packets with detailed parsing"""
        try:
            dns = packet.dns
            
            # Check if it's a query or response using flags
            is_response = False
            if hasattr(dns, 'flags'):
                # DNS flags: QR bit (position 15) indicates query (0) or response (1)
                flags = int(dns.flags, 16) if isinstance(dns.flags, str) else int(dns.flags)
                is_response = bool(flags & 0x8000)  # Check QR bit
            
            if is_response:
                # This is a DNS Response
                self.handle_dns_response(dns, timestamp, src, dst)
            else:
                # This is a DNS Query
                self.handle_dns_query(dns, timestamp, src, dst)
                
        except Exception as e:
            print(f"⚠️  DNS processing error: {e}")
    
    def handle_dns_query(self, dns, timestamp, src, dst):
        """Handle DNS queries"""
        try:
            # Get query name
            query_name = None
            if hasattr(dns, 'qry_name'):
                query_name = dns.qry_name
            elif hasattr(dns, 'query_name'):
                query_name = dns.query_name
            
            if query_name:
                query_info = {
                    'timestamp': timestamp,
                    'src': src, 'dst': dst,
                    'type': 'DNS_QUERY',
                    'query_name': query_name
                }
                
                if '.in-addr.arpa' in query_name:
                    reverse_ip = self.extract_ip_from_arpa(query_name)
                    query_info['reverse_ip'] = reverse_ip
                    print(f"🔍 DNS Query: {src}→{dst} | PTR for {reverse_ip}")
                else:
                    print(f"🔍 DNS Query: {src}→{dst} | {query_name}")
                
                self.dns_traffic.append(query_info)
        
        except Exception as e:
            pass
    
    def handle_dns_response(self, dns, timestamp, src, dst):
        """Handle DNS responses"""
        try:
            response_info = {
                'timestamp': timestamp,
                'src': src, 'dst': dst,
                'type': 'DNS_RESPONSE'
            }
            
            # Look for PTR records in response
            found_ptr = False
            
            # Check all available attributes for PTR data
            for attr in dir(dns):
                attr_value = getattr(dns, attr, None)
                
                if 'ptr' in attr.lower() and attr_value:
                    response_info['ptr_record'] = attr_value
                    print(f"✅ DNS Response: {src}→{dst} | PTR: {attr_value}")
                    found_ptr = True
                
                elif attr == 'ans_name' and attr_value and '.in-addr.arpa' in str(attr_value):
                    reverse_ip = self.extract_ip_from_arpa(str(attr_value))
                    response_info['reverse_ip'] = reverse_ip
                    
                elif 'rdata' in attr.lower() and attr_value and not found_ptr:
                    # Sometimes PTR data is in rdata fields
                    if '.' in str(attr_value) and not str(attr_value).replace('.', '').isdigit():
                        response_info['hostname'] = attr_value
                        print(f"✅ DNS Response: {src}→{dst} | Hostname: {attr_value}")
                        found_ptr = True
            
            if not found_ptr:
                # Generic response
                print(f"📨 DNS Response: {src}→{dst} | (generic)")
            
            self.dns_traffic.append(response_info)
            
        except Exception as e:
            pass
    
    def process_mdns_realtime(self, packet, timestamp, src, dst):
        """Process mDNS packets"""
        try:
            mdns = packet.mdns
            
            mdns_info = {
                'timestamp': timestamp,
                'src': src,
                'type': 'mDNS'
            }
            
            # Check for .local domains
            for attr in dir(mdns):
                attr_value = getattr(mdns, attr, None)
                if attr_value and '.local' in str(attr_value):
                    mdns_info['local_name'] = attr_value
                    print(f"📡 mDNS: {src} | {attr_value}")
                    break
            
            self.mdns_traffic.append(mdns_info)
            
        except Exception as e:
            pass
    
    def extract_ip_from_arpa(self, arpa_name):
        """Extract IP from .in-addr.arpa"""
        if '.in-addr.arpa' in arpa_name:
            parts = arpa_name.replace('.in-addr.arpa', '').split('.')
            return '.'.join(reversed(parts))
        return arpa_name
    
    def continuous_query_trigger(self):
        """Continuously trigger queries while capture is running"""
        print("🚀 Starting continuous query trigger...")
        
        query_count = 0
        while self.running and query_count < 3:  # 3 rounds of queries
            query_count += 1
            print(f"\n🔄 Query Round {query_count}/3")
            
            for i, ip in enumerate(self.target_ips):
                if not self.running:
                    break
                
                print(f"⚡ Querying {ip} ({i+1}/{len(self.target_ips)})")
                
                try:
                    # Fire multiple query types
                    subprocess.run(['dig', '-x', ip, '+time=1'], 
                                 capture_output=True, timeout=2)
                    
                    time.sleep(0.2)  # Very short pause
                    
                    # Also try nslookup
                    subprocess.run(['nslookup', ip], 
                                 capture_output=True, timeout=2)
                    
                    time.sleep(0.3)
                    
                except:
                    continue
            
            print(f"✅ Completed query round {query_count}")
            time.sleep(2)  # Pause between rounds
        
        print("🏁 Query triggering complete")
    
    def run_realtime_analysis(self, duration=30):
        """Run real-time analysis"""
        print("🎬 Starting Real-Time PTR Analysis")
        print("=" * 60)
        
        # Start packet capture in background
        capture_thread = threading.Thread(target=self.start_live_capture)
        capture_thread.daemon = True
        capture_thread.start()
        
        time.sleep(2)  # Let capture initialize
        
        # Start query trigger in background
        query_thread = threading.Thread(target=self.continuous_query_trigger)
        query_thread.daemon = True
        query_thread.start()
        
        # Let it run
        print(f"⏱️  Running for {duration} seconds...")
        
        start_time = time.time()
        while (time.time() - start_time) < duration:
            # Show live stats
            dns_count = len(self.dns_traffic)
            mdns_count = len(self.mdns_traffic)
            elapsed = int(time.time() - start_time)
            
            print(f"\r⏳ {elapsed}s | DNS: {dns_count} | mDNS: {mdns_count}", end='', flush=True)
            time.sleep(1)
        
        # Stop everything
        self.running = False
        print(f"\n🛑 Stopping capture...")
        
        time.sleep(2)  # Let threads finish
        
        # Results
        self.print_realtime_results()
    
    def print_realtime_results(self):
        """Print comprehensive results"""
        print("\n" + "=" * 60)
        print("📊 REAL-TIME ANALYSIS RESULTS")
        print("=" * 60)
        
        dns_queries = [t for t in self.dns_traffic if t['type'] == 'DNS_QUERY']
        dns_responses = [t for t in self.dns_traffic if t['type'] == 'DNS_RESPONSE']
        ptr_responses = [t for t in dns_responses if 'ptr_record' in t or 'hostname' in t]
        
        print(f"\n🔍 DNS Traffic Summary:")
        print(f"   • Total packets: {len(self.dns_traffic)}")
        print(f"   • Queries: {len(dns_queries)}")
        print(f"   • Responses: {len(dns_responses)}")
        print(f"   • PTR Responses: {len(ptr_responses)}")
        
        print(f"\n🎯 PTR Resolutions Found:")
        for ptr in ptr_responses:
            hostname = ptr.get('ptr_record') or ptr.get('hostname', 'unknown')
            reverse_ip = ptr.get('reverse_ip', 'unknown')
            print(f"   {reverse_ip} → {hostname}")
        
        print(f"\n📡 mDNS Traffic: {len(self.mdns_traffic)} packets")
        local_names = [m for m in self.mdns_traffic if 'local_name' in m]
        for mdns in local_names:
            print(f"   {mdns['src']} → {mdns['local_name']}")
        
        # Save results
        results = {
            'dns_traffic': self.dns_traffic,
            'mdns_traffic': self.mdns_traffic,
            'summary': {
                'total_dns': len(self.dns_traffic),
                'dns_queries': len(dns_queries),
                'dns_responses': len(dns_responses),
                'ptr_responses': len(ptr_responses),
                'mdns_packets': len(self.mdns_traffic)
            }
        }
        
        with open('realtime_ptr_analysis.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Results saved to: realtime_ptr_analysis.json")

def main():
    analyzer = RealTimePTRAnalyzer()
    
    try:
        analyzer.run_realtime_analysis(duration=45)
    except KeyboardInterrupt:
        analyzer.running = False
        print("\n👋 Analysis stopped")

if __name__ == "__main__":
    main()
