import sys, os, argparse
import socket
from numpy import average,std

# from math import log as LOG
from scapy.all import *
from time import *

iteraciones= 3
timeout = 2
maximottl=50
hostDestino=socket.gethostbyname("iot.absolutmobile.net")
distancias =[]
distanciaAlHost=(0,0)

def agregar(ipOrigen,ipDestino,rtt):
	if ipOrigen=="*" or ipDestino=="*":
		return
	for x in range(0,len(distancias)):
		if (distancias[x][0]==ipOrigen and distancias[x][1]==ipDestino) or (distancias[x][0]==ipDestino and distancias[x][1]==ipOrigen):
			distancias[x] = (distancias[x][0],distancias[x][1],distancias[x][2]+rtt,distancias[x][3]+1)
			return
	distancias.append((ipOrigen,ipDestino,rtt,1))

for i in range(0,iteraciones):
	ultimaIp=""
	rtt="*"
	ttl = 1
	responses = {}
	while ttl<maximottl:
		probe = IP(dst=hostDestino, ttl=ttl) / ICMP()
		t_i = time()
		# Envia un paquete, y devuelve la respuesta (si la hubo)
		ans = sr1(probe, verbose=False, timeout=timeout)
		t_f = time()
		if ttl not in responses: responses[ttl] = []
		if ans is not None:
			rtt = (ans.time - probe.sent_time)*1000
			ultimaIp=ans.src
   		else:
			ultimaIp="*"
			rtt=0            
        #os.system('clear')
		responses[ttl].append((ultimaIp, rtt))
		print("%s, ttl %d" %(hostDestino, ttl))
		print("Ip respuesta %s" %(ultimaIp))
		print("rtt %.2f" %(rtt))
        #print_route( responses )
        # Tipo 0: echo-reply
		print("- - - - - -")
		if ttl==1:
			agregar(probe.src,ultimaIp,rtt)
		else:
			agregar(responses[ttl-1][0][0],ultimaIp,rtt-responses[ttl-1][0][1])
		ttl+=1
		if ultimaIp==hostDestino:
			distanciaAlHost=(distanciaAlHost[0]+rtt,distanciaAlHost[1]+1)
			break
	print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
	
for x in range(0,len(distancias)):
	distancias[x]=(distancias[x][0],distancias[x][1],distancias[x][2]/distancias[x][3],distancias[x][3])
print(distancias)
distanciaAlHost=(distanciaAlHost[0]/distanciaAlHost[1],distanciaAlHost[1])
print(distanciaAlHost)