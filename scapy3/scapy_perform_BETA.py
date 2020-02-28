#!/usr/bin/env python
##
##
#
##   _craft_packtes_and_benchmark_scapy__
##   _pretty_certain_the_print_statements_are_pyth3_broken__
##
#################
#################################
#################
# Guillaume Valadon <guillaume@valadon.net>

# Scapy performance examples

import argparse, time, os
from scapy.all import *
conf.verbose = 0 # ask Scapy to be quiet

functions_table = {}


# Simple packet building
def building_1(dummy):
 return str(IP(dst="8.8.8.8", src="10.28.7.80")/UDP()/DNS(rd=1, qd=DNSQR(qname="miscmag.com", qtype="A")))
functions_table["building_1"] = building_1 # register the function


# Cache built packets
cached = None
def building_2(dummy):
 global cached
 if not cached:
   cached = str(IP(dst="8.8.8.8", src="10.28.7.80")/UDP()/DNS(rd=1, qd=DNSQR(qname="miscmag.com", qtype="A")))
 return cached
functions_table["building_2"] = building_2 # register the function


# Use Scapy internals to modify a cached packet
packet = IP(dst="8.8.8.8", src="10.28.7.80", chksum=0)/UDP(chksum=0)/DNS(rd=1, qd=DNSQR(qname="miscmag.com", qtype="A"))
# Note that the checksums fields must be manually set to zero as later on as the checksums computations that will be
# performed later requires that these fields are zeroed.
cached_packet= str(packet)

def patch_qid(dns_packet_str, value, offset=0):
    # Encode value as an unsigned short in network ordering and append the rest of the DNS packet,
    # and make sure that it wont't be bigger than 65535
    # The offset parameter is used to ease patching long string
    return dns_packet_str[:offset] + struct.pack("!H", value % 65535) + dns_packet_str[offset+2:]

def building_3(qid):
  # Modify the DNS query ID
  patched_dns_packet = patch_qid(cached_packet[28:], qid)

  # Modify the UDP checksum
  del(packet[UDP].chksum) # Force Scapy to recompute the checksum
  patched_udp_packet = packet[UDP].post_build(cached_packet[20:28], patched_dns_packet) # UDP header

  # Modify the IP checksum
  del(packet[IP].chksum) # Force Scapy to recompute the checksum
  patched_ip_packet  = packet[IP].post_build(cached_packet[:20], patched_udp_packet) # Up to the UDP header
   
  return patched_ip_packet
functions_table["building_3"] = building_3 # register the function


# Modify the packet manually

def pseudo_header(ip_dst, ip_src, ip_proto, length):
    # Prepare the binary representation of the pseudo header
    return struct.pack("!4s4sHH", inet_aton(ip_dst), inet_aton(ip_src), ip_proto, length)

def patch_udp_checksum(udp_packet, pseudo_header):
    # Compute the checksum and replace its value
    return udp_packet[:6] + struct.pack("!H", checksum(pseudo_header+udp_packet)) + udp_packet[8:]

def patch_ip_checksum(ip_packet):
    # Compute the checksum and replace its value
    return ip_packet[:10] + struct.pack("!H", checksum(ip_packet)) + ip_packet[12:]

# Split the packet into "static" part
cached_udp_packet = cached_packet[20:]
cached_ip_packet = cached_packet[:20]
phdr = pseudo_header("8.8.8.8", "10.28.7.80", socket.IPPROTO_UDP, len(cached_udp_packet))

def building_4(qid):
  # Modify the DNS query ID
  patched_dns_packet = patch_qid(cached_udp_packet[8:], qid)
  patched_udp_packet = cached_udp_packet[:8] + patched_dns_packet

  # Modify the UDP checksum
  patched_udp_packet = patch_udp_checksum(patched_udp_packet, phdr)
 
  # Modify the IP checksum
  patched_ip_packet = patch_ip_checksum(cached_ip_packet) + patched_udp_packet
  return patched_ip_packet
functions_table["building_4"] = building_4 # register the function


# Simple packet injection
cached_ether = str(Ether(dst="ff:ff:ff:ff:ff:ff", type=0x800))
def injection_1(qid):
  global cached_ether
  sendp(cached_ether + building_3(qid), verbose=conf.verbose)
functions_table["injection_1"] = injection_1 # register the function


# Keep the socket opened
l2socket = None
def injection_2(qid):
 global l2socket, cached_ether
 l2socket.send(cached_ether + building_3(qid))
functions_table["injection_2"] = injection_2 # register the function


# Access the sendto() method direclty
l2socket = None
def injection_3(qid):
 global l2socket, cached_ether
 l2socket.outs.sendto(cached_ether + building_3(qid))
functions_table["injection_3"] = injection_2 # register the function


if __name__ == "__main__":

  # Parse command line options
  parser = argparse.ArgumentParser(description="Scapy performance examples")

  # Building examples
  subparsers = parser.add_subparsers(help="sub-commands help", dest="command")
  parser_building = subparsers.add_parser("building", help="Packets building examples")
  parser_building.add_argument("id", type=int, choices=range(1,5), help="Example ID (between 1 and 4)")

  parser_injection = subparsers.add_parser("injection", help="Packets injection  examples")
  parser_injection.add_argument("interface", help="Network interface")
  parser_injection.add_argument("id", type=int, choices=range(1,4), help="Example ID (between 1 and 3)")

  args = parser.parse_args()

  # Ease the display
  verbs = { "building": "built", "injection": "injected" }

  # Set the interface if injecting and check if examples are launched as root
  if args.command == "injection":
    if not os.geteuid() == 0:
      print >> sys.stderr, "Launch these examples as root !"
      sys.exit()
    if not args.interface in get_if_list():
      print >> sys.stderr, "The interface '%s'does not exist !"
      sys.exit()
    conf.iface = args.interface
    l2socket = L2Socket(conf.iface)

  # Call & bench the function
  function_name = "%s_%d" % (args.command, args.id)
  start_time = time.time()
  for i in xrange(1000):
    functions_table.get(function_name, lambda x: None)(i)

  # Display the results  
  print "1000 packets %s in %.5fs" % (verbs.get(args.command, "NOT_DEFINED"), time.time() - start_time )
  
  #####################
  ###############################
  
