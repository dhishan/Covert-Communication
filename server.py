from scapy.all import *
import random
import time
from Crypto.Cipher import AES

bin4 = lambda(n): ''.join(str(1 & int(n) >> i ) for i in range(4)[::-1]) # python < 2.6

# DNS response packet
def constructpkt(char,ip_ident,dns_ident,dport,query):
    RA_c = ord(char) % 2
    RD_c = (ord(char) >> 1) % 2
    TC_c = (ord(char) >> 2) % 2
    AA_c = (ord(char) >> 3) % 2
    op_c = (ord(char) >> 4) % 16
    pkt = IP(src="10.10.111.103", dst="10.10.111.104", id=ip_ident)/UDP(sport=53, dport=dport)
    pkt /= DNS(id=dns_ident, qr=1, opcode=op_c,ra=RA_c,rd=RD_c,tc=TC_c,aa=AA_c,qd=query,an=DNSRR(rrname=getattr(query,"qname"),rdata=str(RandIP())))
    return pkt

#extracts the character from the packet
def deconstruct(a):
    RA_c = a[0][DNS].ra
    RD_c = a[0][DNS].rd
    TC_c = a[0][DNS].tc
    AA_c = a[0][DNS].aa
    op_c = a[0][DNS].opcode
    bin_s = bin4(op_c) + str(AA_c) + str(TC_c) + str(RD_c) + str(RA_c)
    char = chr(int(bin_s,2))
    return char

## Initiate Message
lfil = lambda(r): UDP in r and DNS in r and (r[DNS].id == r[UDP].sport + 7) and (r[DNS].opcode == 7)
a=sniff(count=1,filter="src host 10.10.111.104",lfilter = lfil)

print deconstruct(a)
ip_id = random.randint(1000,60000)
udp_dport = a[0][UDP].sport
prev_query = a[0][DNS].qd
dns_id_prev = a[0][DNS].id

# Message Encryption
encryption_suit = AES.new('netsec  favorite',AES.MODE_CBC,'vector8 vector10')
message = encryption_suit.encrypt("This is a secret message dhishan")
message += "~";

#sending the message
for c in message:
    ip_id = random.randint(1000,60000)
    pkt = constructpkt(c,ip_id,dns_id_prev,udp_dport,prev_query)
    time.sleep(5)
    flag = 1
    while(flag):
        send(pkt)
        lfila = lambda(r): UDP in r and DNS in r and (r[DNS].id == r[UDP].sport + 7) and (r[IP].id == ip_id + 1)
        rcv=sniff(count=1,filter="src host 10.10.111.104",lfilter = lfila,timeout=10)
        if(len(rcv)!=0):
            flag=0
            udp_dport = rcv[0][UDP].sport
            prev_query = rcv[0][DNS].qd
            dns_id_prev = rcv[0][DNS].id
            print deconstruct(rcv)
