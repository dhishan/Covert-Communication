from scapy.all import *
from Crypto.Cipher import AES
lfil = lambda(r): IP in r and r[IP].proto == 150
a=sniff(count=1,filter="src host 10.10.111.104",lfilter = lfil)
print a[0][IP].frag
encryption_suit = AES.new('netsec  favorite',AES.MODE_CBC,'vector8 vector10')
message = encryption_suit.encrypt("This is a secret message dhishan")
message += "~";
print message
ident = a[0][IP].id
if(ident != 20):
	print "Error!"
for c in message:
	rcv = 1
	val=ord(c)
	pkt = IP(dst="10.10.111.104",id=ident+1,proto=150,frag=val)
	while(rcv):
		send(pkt)
		p = sniff(count=1,filter="src host 10.10.111.104",lfilter = lfil,timeout = 10)
		if(len(p) != 0 and p[0][IP].id == ident+1):
			ident +=1
			rcv = 0
