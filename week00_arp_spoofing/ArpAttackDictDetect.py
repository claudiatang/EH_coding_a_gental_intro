import scapy.all as scapy
import time

ARPTABLE = {}

def rcv_packet_ip_mac(packet):
    rcv_sndr_ip = packet[scapy.ARP].psrc
    rcv_sndr_mac = packet[scapy.ARP].hwsrc
    return rcv_sndr_ip, rcv_sndr_mac
    


def get_authentic_mac(queried_ip):
    local_mac = scapy.Ether().src
    #print(f"queried ip: {queried_ip}")
    #print(f"local mac: {local_mac}")
    arp_req_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=queried_ip, hwsrc=local_mac)
    rcvd = scapy.srp(arp_req_packet, timeout=2, verbose=0)
    #print(rcvd[0][0])
    auth_mac = rcvd[0][0][1].hwsrc
    print(f"queried ip: {queried_ip} <-> auth mac: {auth_mac}")
    return auth_mac


def update_arp_table(ip, mac):
    if ip in ARPTABLE:
        if mac != ARPTABLE[ip]:
            print(f"arp attack detected!!record ip--mac: {ip}--{ARPTABLE[ip]} | suspect mac: {mac}")
    else:
        authentic_mac = get_authentic_mac(ip)
        ARPTABLE[ip] = authentic_mac
        if mac != authentic_mac:
            print(f"arp attack detected!!new acquired ip--mac: {ip}--{ARPTABLE[ip]} | suspect mac: {mac}")

def process_packet(packet):
    if packet[scapy.ARP].op == 2:
        rcv_arp = rcv_packet_ip_mac(packet)
        if rcv_arp:
            update_arp_table(rcv_arp[0],rcv_arp[1])
    else:
        return


print("start ...")
sniffer = scapy.AsyncSniffer(prn=process_packet, filter="arp", store=False)
sniffer.start()
time.sleep(30)
sniffer.stop()












