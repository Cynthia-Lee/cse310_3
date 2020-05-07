import dpkt
import sys
import struct

# analyzes the pcap trace for the ARP packet

# byte-level programming to read each byte and
# convert it to the ARP header element
# the sender MAC address, target MAC address, protocol type

# ARP message structure in book, determine elements of 
# ARP message

# process ARP packets, for each packet, 
# determine if it is an ARP packet
# if it is an ARP packet then process it furhter

# (i) count the number of ARP messages in your captured pcap

# (i) print the entire ARP request and response for one ARP packet exchange

arp_requests = []
arp_replies = []
arp_exchange = []

class arp:
    def __init__(self):
        self.destination = 0
        self.source = 0
        self.hardware_type = 0
        self.protocol_type = 0
        self.hardware_size = 0
        self.protocol_size = 0
        self.opcode = 0
        self.sender_mac_addr = 0
        self.sender_ip_addr = 0
        self.target_mac_addr = 0
        self.target_ip_addr = 0

def analyze_arp(filename):
    # open pcap file        
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)
    global arp_requests
    global arp_replies
    global arp_exchange
    count = 0
    # access each packet
    for timestamp, buf in pcap:
        # buf is <class 'bytes'>
        # packet, read byte by byte
        if (int.from_bytes(buf[12:14], "big") == 0x0806):
            count = count + 1
            curr = arp()
            curr.destination = buf[0:6] # destination = 0-5
            curr.source = buf[6:12] # source = 6-11
            curr.hardware_type = buf[14:16] # hardware type = 14-15
            curr.protocol_type = buf[16:18] # protocol type = 16-17
            curr.hardware_size = buf[18] # hardware size = 18
            curr.protocol_size = buf[19] # protocol size = 19
            curr.opcode = buf[20:22] # opcode = 20-21
            curr.sender_mac_addr = buf[22:28] # sender mac address = 22-27
            curr.sender_ip_addr = buf[28:32] # sender ip address = 28-31
            curr.target_mac_addr = buf[32:38] # target mac address = 32-37
            curr.target_ip_addr = buf[38:42] # target ip address = 38-41
            if (curr.destination != b'\xff\xff\xff\xff\xff\xff'):
                if (int.from_bytes(curr.opcode, "big") == 1): # request
                    arp_requests.append(curr)
                if (int.from_bytes(curr.opcode, "big") == 2): # reply
                    arp_replies.append(curr)
    # first exchange, the one with the first reply with corresponding request
    i = 0
    found = 0
    while(i < len(arp_replies) and (found == 0)):
        reply = arp_replies[i]
        for curr in arp_requests:
            # check source and destination
            if ((reply.destination == curr.source) and (reply.source == curr.destination)):
                arp_exchange.append(curr)
                arp_exchange.append(reply)
                found = 1
                break
        i = i + 1
    return count

class analysis_pcap_arp:
    if (len(sys.argv) == 2):
        filename = sys.argv[1]
        global arp_exchange
        num = analyze_arp(filename)
        print("Total ARP packets:", num, "\n")
        print("One ARP packet exchange:\n")
        for x in range(0,2):
            curr = arp_exchange[x]
            if (int.from_bytes(curr.opcode, "big") == 1):
                print("ARP Request")
            elif (int.from_bytes(curr.opcode, "big") == 2):
                print("\nARP Reply")
            
            print("Destination:", "%x:%x:%x:%x:%x:%x" % struct.unpack(">BBBBBB", curr.destination))
            print("Source:", "%x:%x:%x:%x:%x:%x" % struct.unpack(">BBBBBB", curr.source))
            print("Hardware type:", int.from_bytes(curr.hardware_type, "big"))
            print("Protocol type:", hex(int.from_bytes(curr.protocol_type, "big")))
            print("Hardware size:", curr.hardware_size)
            print("Protocol size:", curr.protocol_size)
            print("Opcode:", int.from_bytes(curr.opcode, "big"))
            print("Sender MAC address:", "%x:%x:%x:%x:%x:%x" % struct.unpack(">BBBBBB", curr.sender_mac_addr))
            print("Sender IP address:", '.'.join(map(str, struct.unpack(">BBBB", curr.sender_ip_addr))))
            print("Target MAC address:", "%x:%x:%x:%x:%x:%x" % struct.unpack(">BBBBBB", curr.target_mac_addr))
            print("Target IP address", '.'.join(map(str, struct.unpack(">BBBB", curr.target_ip_addr))))
            # "%x:%x:%x:%x:%x:%x" % struct.unpack(">BBBBBB", source[:])
    else:
        print("Wrong arguments. Need to specify pcap filename.")