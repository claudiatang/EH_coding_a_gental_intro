import scapy.all as scapy
import time

def main():
    print("start detect...")
    sniffer = scapy.AsyncSniffer(prn=examin_rcv_packet, filter="arp", store=False, )
    sniffer.start()
    time.sleep(30)
    sniffer.stop()

def rcv_packet_ip_mac(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        rcv_sndr_ip = packet[scapy.ARP].psrc
        rcv_sndr_mac = packet[scapy.ARP].hwsrc
        return rcv_sndr_ip, rcv_sndr_mac
    else:
        return


def get_authentic_mac(queried_ip):
    local_mac = scapy.Ether().src
    #print(f"queried ip: {queried_ip}")
    #print(f"local mac: {local_mac}")
    arp_req_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=queried_ip, hwsrc=local_mac)
    rcvd = scapy.srp(arp_req_packet, timeout=2, verbose=0)
    #print(rcvd[0][0])
    return rcvd[0][0][1].hwsrc


def examin_rcv_packet(packet):
    rcv_sndr_ip_mac = rcv_packet_ip_mac(packet)
    if rcv_sndr_ip_mac:
        #print(rcv_sndr_ip_mac[0])
        queried_ip = rcv_sndr_ip_mac[0]
        authentic_mac = get_authentic_mac(queried_ip)
        if authentic_mac:
            #print(f"mac of {queried_ip} is {authentic_mac}")
            if authentic_mac != rcv_sndr_ip_mac[1]:
                print(f"arp attack detected!!ip {queried_ip} has clasing mac addr: {rcv_sndr_ip_mac[1]} >*< {authentic_mac}")



if __name__=='__main__':
    main()




