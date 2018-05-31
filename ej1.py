import sys, os, argparse
import socket
import math
from numpy import average,std
from scipy import stats

# from math import log as LOG
from scapy.all import *
from time import *

iteraciones= 20
timeout = 1
maximottl=50
hostDestino=socket.gethostbyname("iot.absolutmobile.net")
distancias =[]
distanciaAlHost=(0,0)
responses=[]
ipLocal=""
def agregar(ipOrigen,ipDestino,rtt):
	if ipOrigen=="*" or ipDestino=="*":
		return
	for x in range(0,len(distancias)):
		if (distancias[x][0]==ipOrigen and distancias[x][1]==ipDestino) or (distancias[x][0]==ipDestino and distancias[x][1]==ipOrigen):
			distancias[x] = (distancias[x][0],distancias[x][1],distancias[x][2]+rtt,distancias[x][3]+1)
			return
	distancias.append((ipOrigen,ipDestino,rtt,1))

def calcularTau(vector):
	tStudent=abs(stats.t.ppf(0.05/2,len(vector)-2))
	tau= tStudent*(len(vector)-1)/(math.sqrt(len(vector))*math.sqrt(len(vector)-2+tStudent**2))
	return tau


def dameElPromedio(ipOrigen,ipDestino):
	for x in range(0,len(distancias)):
		if (distancias[x][0]==ipOrigen and distancias[x][1]==ipDestino) or (distancias[x][0]==ipDestino and distancias[x][1]==ipOrigen):
			return distancias[x][2]

def findOutliers(indice):
	outliers=[]
	ruta=responses[indice]
	vector=[] #Vector es un arreglo de tuplas (ipOrigen,ipdestino,promedio RTT entre las ip de la rutas,desvio estandar)

	for x in range(1,len(ruta)+1):
		if x==1:			
			if ruta[x][0][0]!="*":
				vector.append((ipLocal,ruta[x][0][0],dameElPromedio(ipLocal,ruta[x][0][0]),0))
		else:
			if ruta[x][0][0]!="*" and ruta[x-1][0][0]!="*":
				vector.append((ruta[x-1][0][0],ruta[x][0][0],dameElPromedio(ruta[x-1][0][0],ruta[x][0][0]),0))
	
	hayMasOutliers=True
	print("Vector:")
	print(vector)
	while hayMasOutliers:
		promedio=reduce(lambda x, y: x + y, [x[2] for x in vector]) / len(vector)
		#Calculo el desvio estandar de la muestra
		sumatoria=0
		for x in range(0,len(vector)):
		    sumatoria += ((vector[x][2]-promedio)**2)
		desvioEstandar= math.sqrt((sumatoria/(len(vector)-1)))

		#calculo el desvio estandar absoluto de cada valor
		for x in range(0,len(vector)):
			vector[x]=(vector[x][0],vector[x][1],vector[x][2],abs(vector[x][2]-promedio))
		#Ahora buscamos el sospechoso
		indiceSospechoso=0
		for x in range(0,len(vector)):
			
			if vector[indiceSospechoso][3]<vector[x][3]:
				indiceSospechoso=x
		tau=calcularTau(vector) 
		
		#Me fijo si el sospechoso es outlier
		if vector[indiceSospechoso][3]>tau*desvioEstandar:
			outliers.append(vector[indiceSospechoso])
			del(vector[indiceSospechoso])
		else:
			hayMasOutliers=False
	return outliers




print("IP destino: %s\n"%(hostDestino))
for i in range(0,iteraciones):
	print("Iteracion %d"%(i+1))
	ultimaIp="*"
	rtt="*"
	ttl = 1
	responses.append({})
	while ttl<maximottl:
		timeExceeded=0
		ultimaIp="*"
		while timeExceeded<=1 and ultimaIp=="*":
			probe = IP(dst=hostDestino, ttl=ttl) / ICMP()
			t_i = time()
			# Envia un paquete, y devuelve la respuesta (si la hubo)
			ans = sr1(probe, verbose=False, timeout=timeout)
			t_f = time()
			if ttl not in responses[i]: responses[i][ttl] = []
			if ans is not None:
				rtt = (ans.time - probe.sent_time)*1000
				ultimaIp=ans.src
			else:
				ultimaIp="*"
				rtt=0
				timeExceeded+=1
	
		responses[i][ttl].append((ultimaIp, rtt))
		if ultimaIp!="*":
			print("ttl %d : %s (%.2f ms)" %(ttl,ultimaIp,rtt))
		else:
			print("ttl %d : * (*)" %(ttl))
        #print_route( responses )
        # Tipo 0: echo-reply
		if ttl==1:
			agregar(probe.src,ultimaIp,rtt)
			ipLocal=probe.src
		else:
			agregar(responses[i][ttl-1][0][0],ultimaIp,rtt-responses[i][ttl-1][0][1])
		ttl+=1
		if ultimaIp==hostDestino:
			distanciaAlHost=(distanciaAlHost[0]+rtt,distanciaAlHost[1]+1)
			break
	print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
	


for x in range(0,len(distancias)):
	distancias[x]=(distancias[x][0],distancias[x][1],distancias[x][2]/distancias[x][3],distancias[x][3])

distanciaAlHost=(distanciaAlHost[0]/distanciaAlHost[1],distanciaAlHost[1])

print("OUTLIERS:")
for x in range(0,iteraciones):
	print(findOutliers(x))

