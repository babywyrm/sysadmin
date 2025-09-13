#!/usr/bin/env python3
"""
Enhanced Subnet PTR Traffic Analyzer ..beta..demo..
Captures all DNS/mDNS traffic and triggers comprehensive queries
"""

import pyshark
import subprocess
import threading
import time
import json
import ipaddress
from collections import defaultdict

class EnhancedSubnetPTRAnalyzer:
    def __init__(self):
        self.dns_traffic = []
        self.mdns_traffic = []
        self.dhcp_traffic = []
        self.running = False
        self.capture = None
        
        # IPs that had PTR records from your previous scan
        self.target_ips = [
            '192.168.1.65', '192.168.1.83', '192.168.1.102', '192.168.1.113',
            '192.168.1.150', '192.168.1.154', '192.168.1.160', '192.168.1.169',
            '192.168.1.180', '192.168.1.182', '192.168.1.190', '192.168.1.199',
            '192.168.1.213', '192.168.1.218', '192.168.1.223', '192.168.1.233',
            '192.168.1.247', '192.168.1.248', '192.168.1.250', '192.168.1.254'
        ]
    
    def start_comprehensive_capture(self):
        """Enhanced capture with better filtering"""
        print("🎯 Starting comprehensive network capture...")
        
        try:
            # More comprehensive capture - all DNS-related traffic
            self.capture = pyshark.LiveCapture(
                interface='en0',  # Your main interface
                bpf_filter='port 53 or port 5353 or port 67 or port 68 or port 137',
                include_raw=True,
                use_json=True
            )
            
            self.running = True
            
            # Also capture multicast traffic for mDNS
            for packet in self.capture.sniff_continuously():
                if not self.running:
                    break
                    
                self.analyze_enhanced_packet(packet)
                
        except Exception as e:
            print(f"Enhanced capture failed: {e}")
            # Fallback to simpler capture
            self.fallback_capture()
    
    def fallback_capture(self):
        """Fallback capture method"""
        print("📡 Using fallback capture method...")
        try:
            self.capture = pyshark.LiveCapture(interface='en0')
            self.running = True
            
            for packet in self.capture.sniff_continuously():
                if not self.running:
                    break
                self.analyze_enhanced_packet(packet)
        except Exception as e:
            print(f"Fallback capture failed: {e}")
    
    def analyze_enhanced_packet(self, packet):
        """Enhanced packet analysis"""
        timestamp = packet.sniff_time
        
        try:
            # DNS Traffic (Port 53)
            if hasattr(packet, 'dns') and hasattr(packet, 'ip'):
                self.process_dns_traffic(packet, timestamp)
            
            # mDNS Traffic (Port 5353) 
            if hasattr(packet, 'mdns') and hasattr(packet, 'ip'):
                self.process_mdns_traffic(packet, timestamp)
                
            # DHCP Traffic (Ports 67/68)
            if hasattr(packet, 'dhcp'):
                self.process_dhcp_traffic(packet, timestamp)
                
            # NetBIOS Name Service (Port 137)
            if hasattr(packet, 'nbns'):
                self.process_netbios_traffic(packet, timestamp)
                
        except Exception as e:
            # Skip problematic packets
            pass
    
    def process_dns_traffic(self, packet, timestamp):
        """Process all DNS traffic"""
        dns = packet.dns
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        
        dns_info = {
            'timestamp': str(timestamp),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'packet_type': 'DNS'
        }
        
        # DNS Queries
        if hasattr(dns, 'flags_response') and dns.flags_response == '0':
            if hasattr(dns, 'qry_name'):
                dns_info.update({
                    'type': 'QUERY',
                    'query_name': dns.qry_name,
                    'query_type': getattr(dns, 'qry_type', 'unknown')
                })
                
                if '.in-addr.arpa' in dns.qry_name:
                    # Extract IP from reverse query
                    reverse_ip = self.extract_ip_from_arpa(dns.qry_name)
                    dns_info['reverse_ip'] = reverse_ip
                    print(f"🔍 PTR Query: {src_ip} → {dst_ip} | {reverse_ip} ({dns.qry_name})")
        
        # DNS Responses  
        elif hasattr(dns, 'flags_response') and dns.flags_response == '1':
            if hasattr(dns, 'resp_name'):
                dns_info.update({
                    'type': 'RESPONSE',
                    'response_name': getattr(dns, 'resp_name', ''),
                })
                
                # PTR Response
                if hasattr(dns, 'ptr_domain_name'):
                    dns_info['ptr_domain'] = dns.ptr_domain_name
                    reverse_ip = self.extract_ip_from_arpa(dns.resp_name) if hasattr(dns, 'resp_name') else 'unknown'
                    print(f"✅ PTR Response: {src_ip} → {dst_ip} | {reverse_ip} → {dns.ptr_domain_name}")
                
                # A Record Response
                if hasattr(dns, 'a'):
                    dns_info['a_record'] = dns.a
                    print(f"🌐 A Response: {src_ip} → {dst_ip} | {getattr(dns, 'resp_name', 'unknown')} → {dns.a}")
        
        self.dns_traffic.append(dns_info)
    
    def process_mdns_traffic(self, packet, timestamp):
        """Process mDNS traffic"""
        try:
            mdns = packet.mdns
            src_ip = packet.ip.src
            
            mdns_info = {
                'timestamp': str(timestamp),
                'src_ip': src_ip,
                'packet_type': 'mDNS'
            }
            
            if hasattr(mdns, 'qry_name') and '.local' in mdns.qry_name:
                mdns_info.update({
                    'type': 'QUERY',
                    'query_name': mdns.qry_name
                })
                print(f"📡 mDNS Query: {src_ip} | {mdns.qry_name}")
            
            if hasattr(mdns, 'resp_name') and '.local' in mdns.resp_name:
                mdns_info.update({
                    'type': 'RESPONSE', 
                    'response_name': mdns.resp_name
                })
                if hasattr(mdns, 'a'):
                    mdns_info['ip_address'] = mdns.a
                    print(f"🎯 mDNS Response: {src_ip} | {mdns.resp_name} → {mdns.a}")
                else:
                    print(f"🎯 mDNS Response: {src_ip} | {mdns.resp_name}")
            
            self.mdns_traffic.append(mdns_info)
            
        except Exception as e:
            pass
    
    def process_dhcp_traffic(self, packet, timestamp):
        """Process DHCP traffic for hostnames"""
        try:
            dhcp = packet.dhcp
            
            dhcp_info = {
                'timestamp': str(timestamp),
                'packet_type': 'DHCP'
            }
            
            if hasattr(packet, 'bootp'):
                dhcp_info['client_ip'] = getattr(packet.bootp, 'ip_client', 'unknown')
            
            if hasattr(dhcp, 'option_hostname'):
                dhcp_info['hostname'] = dhcp.option_hostname
                print(f"🏠 DHCP: {dhcp_info.get('client_ip', 'unknown')} | {dhcp.option_hostname}")
            
            self.dhcp_traffic.append(dhcp_info)
            
        except Exception as e:
            pass
    
    def process_netbios_traffic(self, packet, timestamp):
        """Process NetBIOS name service traffic"""
        try:
            if hasattr(packet, 'nbns'):
                nbns_info = {
                    'timestamp': str(timestamp),
                    'src_ip': packet.ip.src,
                    'packet_type': 'NetBIOS'
                }
                print(f"🪟 NetBIOS: {packet.ip.src} | NetBIOS traffic detected")
                self.dns_traffic.append(nbns_info)  # Add to DNS traffic for now
        except:
            pass
    
    def extract_ip_from_arpa(self, arpa_name):
        """Extract IP from .in-addr.arpa format"""
        if '.in-addr.arpa' in arpa_name:
            parts = arpa_name.replace('.in-addr.arpa', '').split('.')
            return '.'.join(reversed(parts))
        return arpa_name
    
    def trigger_comprehensive_queries(self):
        """Trigger queries for all known IPs"""
        print(f"🚀 Triggering PTR queries for {len(self.target_ips)} known hosts...")
        
        for i, ip in enumerate(self.target_ips):
            try:
                # Multiple query methods
                print(f"⏳ Querying {ip} ({i+1}/{len(self.target_ips)})")
                
                # Standard dig
                subprocess.run(['dig', '-x', ip, '+time=2'], 
                             capture_output=True, timeout=3)
                
                # Try nslookup too
                subprocess.run(['nslookup', ip], 
                             capture_output=True, timeout=3)
                
                time.sleep(0.5)  # Brief pause between queries
                
            except Exception as e:
                continue
        
        print("✅ Finished triggering queries")
    
    def listen_for_natural_traffic(self, duration=60):
        """Just listen for natural network traffic"""
        print(f"👂 Listening for natural network traffic for {duration} seconds...")
        print("   (This will catch devices announcing themselves)")
        
        # Trigger some network activity to generate responses
        threading.Thread(target=self.generate_network_activity, daemon=True).start()
        
        time.sleep(duration)
    
    def generate_network_activity(self):
        """Generate network activity to trigger responses"""
        activities = [
            # Ping broadcast to trigger ARP and potentially mDNS
            ['ping', '-c', '3', '192.168.1.255'],
            # Browse for services (triggers mDNS)
            ['dns-sd', '-B', '_http._tcp'],
        ]
        
        for activity in activities:
            try:
                subprocess.run(activity, capture_output=True, timeout=10)
                time.sleep(5)
            except:
                continue
    
    def run_comprehensive_analysis(self, duration=90):
        """Run comprehensive traffic analysis"""
        print("🎬 Starting Comprehensive Subnet PTR Analysis")
        print("=" * 70)
        
        # Start capture
        capture_thread = threading.Thread(target=self.start_comprehensive_capture)
        capture_thread.daemon = True
        capture_thread.start()
        
        time.sleep(3)  # Let capture start
        
        # Phase 1: Trigger specific queries
        query_thread = threading.Thread(target=self.trigger_comprehensive_queries)
        query_thread.start()
        query_thread.join()
        
        time.sleep(2)
        
        # Phase 2: Listen for natural traffic
        self.listen_for_natural_traffic(duration - 15)
        
        # Stop capture
        self.running = False
        if self.capture:
            self.capture.close()
        
        # Results
        self.print_comprehensive_results()
    
    def print_comprehensive_results(self):
        """Print comprehensive results"""
        print("\n" + "=" * 80)
        print("📊 COMPREHENSIVE TRAFFIC ANALYSIS")
        print("=" * 80)
        
        print(f"\n🔍 DNS Traffic: {len(self.dns_traffic)} packets")
        
        # Group by type
        dns_queries = [d for d in self.dns_traffic if d.get('type') == 'QUERY']
        dns_responses = [d for d in self.dns_traffic if d.get('type') == 'RESPONSE']
        ptr_responses = [d for d in dns_responses if 'ptr_domain' in d]
        
        print(f"   • Queries: {len(dns_queries)}")
        print(f"   • Responses: {len(dns_responses)}")
        print(f"   • PTR Responses: {len(ptr_responses)}")
        
        print(f"\n🎯 PTR Resolutions Found:")
        for ptr in ptr_responses:
            reverse_ip = ptr.get('reverse_ip', 'unknown')
            hostname = ptr.get('ptr_domain', 'unknown')
            print(f"   {reverse_ip} → {hostname}")
        
        print(f"\n📡 mDNS Traffic: {len(self.mdns_traffic)} packets")
        mdns_responses = [m for m in self.mdns_traffic if m.get('type') == 'RESPONSE']
        for mdns in mdns_responses[-5:]:  # Last 5
            hostname = mdns.get('response_name', 'unknown')
            ip = mdns.get('ip_address', '')
            print(f"   {mdns['src_ip']} → {hostname} {ip}")
        
        print(f"\n🏠 DHCP Traffic: {len(self.dhcp_traffic)} packets")
        
        # Save results
        results = {
            'dns_traffic': self.dns_traffic,
            'mdns_traffic': self.mdns_traffic, 
            'dhcp_traffic': self.dhcp_traffic
        }
        
        with open('comprehensive_ptr_analysis.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Results saved to: comprehensive_ptr_analysis.json")

def main():
    analyzer = EnhancedSubnetPTRAnalyzer()
    
    try:
        analyzer.run_comprehensive_analysis(duration=60)
    except KeyboardInterrupt:
        print("\n👋 Analysis stopped")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
