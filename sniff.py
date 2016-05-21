from scapy.all import *
from Crypto.Cipher import AES
import time
ident = 20
send(IP(dst="10.10.111.103",id=ident,proto=150,frag=0xFE))
lfil  = lambda(r): IP in r and r[IP].proto == 150
flag = 1
str=""
char1=0
while(flag):
	p = sniff(count=1,filter = "src host 10.10.111.103",lfilter = lfil)
	if(p[0][IP].id == ident + 1):
		ident +=1
		str +=chr(p[0][IP].frag)
	time.sleep(5)
	send(IP(dst="10.10.111.103",id=ident,proto=150,frag=p[0][IP].frag))
	if p[0][IP].frag == 126:
		flag = 0
str = str[:-1]
decrypt_suite = AES.new('netsec  favorite',AES.MODE_CBC,'vector8 vector10')
message = decrypt_suite.decrypt(str)
print message
