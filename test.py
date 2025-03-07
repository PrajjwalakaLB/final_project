import socket
import time
import random
import threading
import sys
import logging
from scapy.all import *
from scapy.layers.dns import DNSQR
from scapy.layers.inet import UDP
from scapy.layers.inet import TCP
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP

# Set up logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_normal_traffic():
    """Generate normal HTTP traffic"""
    try:
        # Create legitimate HTTP GET requests
        for _ in range(3):
            packet = IP(dst="8.8.8.8")/TCP(dport=80)/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            send(packet, verbose=False)
            logger.info("Sent normal HTTP traffic")
            time.sleep(1)
    except Exception as e:
        logger.error(f"Error generating normal traffic: {str(e)}")

def generate_suspicious_traffic():
    """Generate suspicious traffic patterns"""
    try:
        # Generate unusually long DNS query (potential DNS tunneling)
        suspicious_domain = "very.long.suspicious." + "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=50)) + ".com"
        dns_packet = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(
            rd=1,
            qd=DNSQR(qname=suspicious_domain)
        )
        send(dns_packet, verbose=False)
        logger.info("Sent suspicious DNS query")

        # Generate rapid SYN packets (potential SYN flood)
        for _ in range(5):
            syn_packet = IP(dst="192.168.1.1")/TCP(dport=80, flags="S")
            send(syn_packet, verbose=False)
        logger.info("Sent suspicious SYN packets")

        time.sleep(1)
    except Exception as e:
        logger.error(f"Error generating suspicious traffic: {str(e)}")

def generate_malicious_traffic():
    """Generate malicious traffic patterns"""
    try:
        # Simulate command injection attempt
        malicious_payload = "eval(document.cookie)"
        packet = IP(dst="192.168.1.1")/TCP(dport=80)/Raw(load=malicious_payload)
        send(packet, verbose=False)
        logger.info("Sent malicious command injection packet")

        # Simulate connection to known malicious port
        malicious_ports = [4444, 666, 1337]  # Common malware ports
        for port in malicious_ports:
            packet = IP(dst="192.168.1.1")/TCP(dport=port)
            send(packet, verbose=False)
            logger.info(f"Sent malicious connection attempt to port {port}")

        # Simulate potential ARP spoofing
        arp_packet = ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.2", hwsrc="12:34:56:78:9A:BC")
        send(arp_packet, verbose=False)
        logger.info("Sent malicious ARP packet")

        time.sleep(1)
    except Exception as e:
        logger.error(f"Error generating malicious traffic: {str(e)}")

def continuous_traffic_generation():
    """Generate a mix of traffic patterns continuously"""
    logger.info("Starting traffic generation...")
    
    try:
        while True:
            # Generate normal traffic
            generate_normal_traffic()
            time.sleep(2)

            # Generate suspicious traffic
            generate_suspicious_traffic()
            time.sleep(2)

            # Generate malicious traffic
            generate_malicious_traffic()
            time.sleep(2)

    except KeyboardInterrupt:
        logger.info("Traffic generation stopped by user")
    except Exception as e:
        logger.error(f"Error in traffic generation: {str(e)}")

if __name__ == "__main__":
    # Check for root privileges
    if sys.platform != "win32" and os.geteuid() != 0:

        logger.error("This script requires root privileges to generate network packets")
        logger.error("Please run with sudo")
        sys.exit(1)

    logger.info("Network Traffic Generator")
    logger.info("Press Ctrl+C to stop")
    
    try:
        # Start continuous traffic generation
        continuous_traffic_generation()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")