#!/usr/bin/python

# requerimientos: python3, scapy, numpy
import sys, os, argparse
from numpy import average,std

# from math import log as LOG
from scapy.all import *
from time import *

# Manejo de argumentos
parser = argparse.ArgumentParser(description='Implementacion en scapy de traceroute')
parser.add_argument('--destination-host', '-d', dest='host', default='google.com', help='host al cual se quiere hacer el traceroute (default: google.com)')
parser.add_argument('--ttl', '-t', dest='ttl',  type=int, default=30, help='ttl de los paquetes (default: 30)')
parser.add_argument('--queries', '-q', dest='queries',  type=int, default=1, help='numero de paquetes que se le envia a cada hop (default: 1)')
parser.add_argument('--timeout', '-o', dest='timeout', default=1, help='timeout del envio de cada paquete (default: 1s)')
parser.add_argument('--verbose', '-v', action='store_true', help='agregar si se desea verbosidad de la herramienta (default: no)')
args = parser.parse_args()

# Diccionario que para cada ttl, guarda una lista con tuplas (host, rtt)
responses = {}

ttl_range = range(1, args.ttl+1)

def print_route(rs):
    table = {}
    last_rtt = 0
    for ttl in ttl_range:
        if ttl not in rs: continue

        # r = (src, rtt)
        ips = ",".join(list(set([ r[0] for r in rs[ttl] ])))
        avg_rtt = average( [ r[1] for r in rs[ttl] ] )
        std_rtt = std( [ r[1] for r in rs[ttl] ] )

        if avg_rtt-last_rtt<0.0:
            table[ttl] = (avg_rtt, std_rtt, 0, ips)
        else:
            table[ttl] = (avg_rtt, std_rtt, avg_rtt-last_rtt, ips)
            last_rtt = avg_rtt
    
    print("ttl\tavg_rtt\tstd_rtt\td_rtt\tips")
    for ttl in ttl_range:
        if ttl not in table:
            print(ttl, "\t*\t*\t*\t*")
        else:
            # table[ttl] = (avg_rtt, std_rtt, delta_rtt, ips)
            print("%d\t" % (ttl) + "%.2f\t%.2f\t%.2f\t%s" % table[ttl])


# Recordar que se pueden invertir los siguientes ciclos.
for i in range(args.queries):
    for ttl in ttl_range:
        probe = IP(dst=args.host, ttl=ttl) / ICMP()

        t_i = time()
        # Envia un paquete, y devuelve la respuesta (si la hubo)
        ans = sr1(probe, verbose=False, timeout=args.timeout)
        t_f = time()

        if ans is not None:
            rtt = (t_f - t_i)*1000
            # Otra manera: el paquete enviado tiene su timestamp en sent_time, y el recibido en time. 
            #rtt = (ans.time - probe.sent_time)*1000

            if ttl not in responses: responses[ttl] = []
            responses[ttl].append((ans.src, rtt))

        os.system('clear')
        print("%s, iteracion %d" %(args.host, i+1))
        print_route( responses )

        # Tipo 0: echo-reply
        if ans is not None and ans.type==0: break
            


