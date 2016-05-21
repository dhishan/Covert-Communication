from scapy.all import *
import string, random
import time
from Crypto.Cipher import AES

top =[ ".com", ".net" , ".com", ".edu" , ".ch", ".de", ".li", ".jp", ".ru", ".tv",".nl",".fr" ]

# converts int into 4 bit bin value
bin4 = lambda(n): ''.join(str(1 & int(n) >> i ) for i in range(4)[::-1]) # python < 2.6
#"{0:b}".format(op_c).zfill(4) #Python > 2.6

def constructpkt(char,ip_ident,dns_ident,sport,query):
    RA_c = ord(char) % 2
    RD_c = (ord(char) >> 1) % 2
    TC_c = (ord(char) >> 2) % 2
    AA_c = (ord(char) >> 3) % 2
    op_c = (ord(char) >> 4) % 16
    pkt = IP(src="10.10.111.104",dst="10.10.111.103",id=ip_ident)/UDP(sport=sport,dport=53)
    pkt /= DNS(id=dns_ident,qr=0,opcode=op_c,ra=RA_c,rd=RD_c,tc=TC_c,aa=AA_c,qd=DNSQR(qname=query))
    return pkt

def constructquery(char,ip_id):
    sport = random.randint(10000,60000)
    dns_id = sport + 7
    query = "www."
    query += ''.join(random.choice(string.ascii_lowercase) for x in range(12))
    query += top[random.randrange(len(top))]
    return dns_id,constructpkt(char,ip_id,dns_id,sport,query)

def deconstruct(a):
    RA_c = a[0][DNS].ra
    RD_c = a[0][DNS].rd
    TC_c = a[0][DNS].tc
    AA_c = a[0][DNS].aa
    op_c = a[0][DNS].opcode
    bin_s = bin4(op_c) + str(AA_c) + str(TC_c)+ str(RD_c) + str(RA_c)
    char = chr(int(bin_s,2))
    return char


dns_id , pkt = constructquery('s',random.randint(1,60000))
send(pkt)
print getattr(pkt[DNS].qd,"qname")

c = ""
flag = 1
while(flag):
    lfil = lambda(r): UDP in r and DNS in r and (r[DNS].id == dns_id)
    rcv=sniff(count=1,filter="src host 10.10.111.103",lfilter = lfil)
    if(len(rcv)!=0):
        rchar = deconstruct(rcv)
        if(rchar == '~'):
            flag = 0
        c += rchar
        dns_id, ack = constructquery(rchar,rcv[0][IP].id +1)
        time.sleep(5)
        send(ack)

c = c[:-1]
print c
decrypt_suite = AES.new('netsec  favorite',AES.MODE_CBC,'vector8 vector10')
message = decrypt_suite.decrypt(c)
print message
