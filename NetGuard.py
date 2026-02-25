from scapy.all import IP, TCP, sr1
import socket

def audit_target(Target_IP):
#Common ports to check for security vulnerabilities
# 22(SSH), 80(HTTP), 443(HTTPS), 445 (SMB - common for ransomeware)
    vuln_ports = [22, 80, 443, 445, 3389] # Added RDP port for potential vulnerabilities

    print (f"--- Staring Secutrity Audit for {Target_IP} ---")
    for port in vuln_ports:
    # Craft a SYN packet (The "Hello" packet)
     syn_packet = IP(dst=Target_IP)/TCP(dport=port, flags='S')
    # Send the packet and wait for a response
     response = sr1(syn_packet, timeout=1, verbose=0)
    
     if response is None:
         print(f"Port {port}: Filtered (Likely Blocked by a firewall)")
     elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12: # SYN-ACK
            print(f"Port {port}: Open (Potential Entry Point)")
            # Send RST to close the connection
            sr1(IP(dst=Target_IP)/TCP(dport=port, flags='R'), timeout=1, verbose=0)
        elif response.getlayer(TCP).flags == 0x14: # RST-ACK
            print(f"Port {port}: Closed")

audit_target("192.168.1.1")            