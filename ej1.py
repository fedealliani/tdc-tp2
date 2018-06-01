import sys, os, argparse
import socket
import math
from numpy import average,std
from scipy import stats
from scapy.all import *
from time import *

# Cantidad de iteraciones que se van a hacer. Cada iteracion es un traceroute completo
# iteraciones = 20

# Cantidad maxima de TTL hasta llegar al host destino
maximoTTL = 0 # Se setea por parametro

# Cantidad de respuestas Time Exceeded que quiero recibir para el TTL actual
respuestasTimeExceededDeseadas = 0 # Se setea por parametro

# Host destino
hostDestino = "" # Se setea por parametro

# Lista de Tupla<IP1, IP2, RTT, cantidad>, que representa
# la distancia RTT promedio entre IP1 e IP2.
# Tambien se cuenta la cantidad de veces que se paso
# por esas dos IP en el campo cantidad.
distancias = [] # Se inicializa como una lista vacia

# Lista<RTT>.
# La lista contiene cada distancia RTT medida (no promedio) entre la IP local y el host destino,
# teniendo en cuenta que se pide 30 respuestas (variable respuestasTimeExceededDeseadas)
distanciasAlHost = []

# Diccionario<clave=TTL, valor=Lista<<Tupla<IP, RTT>>>.
# Para cada clave TTL (mayor o igual a 1) el diccionario contiene
# una Lista de Tupla<IP, RTT>. La lista va a contener cada respuesta
# (de la 1 a la 30, que es la cantidad de respuestas que pide el TP) con el
# RTT medido (no promedio) entre nuestra IP local y la IP de la tupla
respuestasRTT = {} # Se inicializa como un diccionario vacio

# Variable en la cual se va a guardar nuestra IP local.
# La sacamos del paquete creado por scapy
ipLocal = "*" # Por ahora es un dummy

# Variable que guarda todos los outliers
outliers = []

# Agrega la distancia entre ip1 e ip2 a la lista distancias
def guardarDistancia(ip1, ip2, distancia):
	# Si alguna de las dos IP es basura, no agregamos nada
	if (ip1 == "*" or ip2 == "*"):
		return

	# Vemos primero si ya existe una entrada en el vector distancias para estas dos IP
	for x in range(0, len(distancias)):
		if (distancias[x][0] == ip1 and distancias[x][1] == ip2) or (distancias[x][0] == ip2 and distancias[x][1] == ip1):
			# Encontramos un elemento que ya tiene informacion sobre estas dos IP

			# Le agregamos la distancia que nos pasaron como parametro e incrementamos en uno el contador de cantidad de mediciones
			# Nota: Luego de llenar todo el vector de distancias calcularemos el promedio.
			# Es decir, por ahora, el tercer campo de la tupla tiene todas las distancias acumuladas, y luego
			# se van a reemplazar con el valor promedio, dividiendo por la cantidad de mediciones hechas sobre esas dos IP

			# Nota: la unica forma de modificar una tupla es creando una tupla nueva usando los valores anteriores
			distancias[x] = (distancias[x][0], distancias[x][1], distancias[x][2] + distancia, distancias[x][3] + 1)

			# Como ya hicimos lo que teniamos que hacer, salimos
			return

	# No encontramos ninguna entrada en el vector distancias para estas dos IP,
	# asi que creamos una entrada nueva con la distancia que nos pasaron como parametro
	# y seteamos el contador de cantidad de mediciones en 1
	distancias.append((ip1, ip2, distancia, 1))

def calcularTau(vector):
	tStudent = abs(stats.t.ppf(0.05/2,len(vector)-2))
	tau = tStudent*(len(vector)-1)/(math.sqrt(len(vector))*math.sqrt(len(vector)-2+tStudent**2))
	return tau

def dameElPromedio(ipOrigen,ipDestino):
	for x in range(0,len(distancias)):
		if (distancias[x][0]==ipOrigen and distancias[x][1]==ipDestino) or (distancias[x][0]==ipDestino and distancias[x][1]==ipOrigen):
			return distancias[x][2]

def esOutlier(x):
	for i in range(0, len(outliers)):
		if (distancias[x][0] == outliers[i][0] and distancias[x][1] == outliers[i][1]) or (distancias[x][0] == outliers[i][1] and distancias[x][1] == outliers[i][0]):
			# Encontramos esta entrada en la lista de outliers, entonces es un outlier
			return True
	return False

def findOutliers():	
	# Vector es Tupla<ip1, ip2, RTT promedio, desvio estandar>
	vector = []

	# Copiamos los datos del vector distancias a vector
	for x in range(0, len(distancias)):
		vector.append((distancias[x][0], distancias[x][1], distancias[x][2], 0))

	hayMasOutliers = True
	while hayMasOutliers:
		# Calculo la media de todas las distancias
		media = reduce(lambda x, y: x + y, [ x[2] for x in vector ]) / len(vector)
		
		# Calculo el desvio estandar de la muestra
		sumatoria = 0
		for x in range(0, len(vector)):
		    sumatoria += ((vector[x][2] - media)**2)
		
		desvioEstandar = math.sqrt((sumatoria/(len(vector)-1)))

		# Calculo el desvio estandar absoluto de cada valor y lo agrego al cuarto elemento de la tupla
		for x in range(0, len(vector)):
			vector[x] = (vector[x][0], vector[x][1], vector[x][2], abs(vector[x][2] - media))
		
		# Ahora buscamos el sospechoso
		indiceSospechoso = 0
		for x in range(0, len(vector)):
			
			if vector[indiceSospechoso][3] < vector[x][3]:
				indiceSospechoso = x
		tau = calcularTau(vector) 
		
		# Me fijo si el sospechoso es outlier
		if vector[indiceSospechoso][3] > tau*desvioEstandar:
			outliers.append(vector[indiceSospechoso])
			del(vector[indiceSospechoso])
		else:
			hayMasOutliers=False
	return outliers


# Aca empieza el main

# Manejo de argumentos
parser = argparse.ArgumentParser(description='Traceroute')
parser.add_argument('--destination-host', '-d', dest='host', default='iot.absolutmobile.net', help='host al cual se quiere hacer el traceroute (default: "iot.absolutmobile.net")')
parser.add_argument('--ttl', '-t', dest='ttl',  type=int, default=30, help='maximo ttl de los paquetes (default: 30)')
parser.add_argument('--queries', '-q', dest='queries',  type=int, default=15, help='numero de paquetes que se le envia a cada hop (default: 15)')
parser.add_argument('--cant-time-exceeded', '-x', dest='timeexceeded',  type=int, default=30, help='cantidad de respuestas Time Exceeded que queremos tener por cada hop (default: 30)')
parser.add_argument('--timeout', '-o', dest='timeout', default=1, help='timeout del envio de cada paquete (default: 1s)')
parser.add_argument('--verbose', '-v', action='store_true', help='agregar si se desea mayor verbosidad de la herramienta (default: no)')
args = parser.parse_args()


hostDestino = args.host
maximoTTL = args.ttl
respuestasTimeExceededDeseadas = args.timeexceeded

# Resolvemos la IP del host destino y la mostramos en pantalla

hostDestino = socket.gethostbyname(hostDestino)
print("------------------------------")
print("IP destino: %s"%(hostDestino))
print("------------------------------")
print("")

# Seteamos el TTL inicial
actualTTL = 1

while actualTTL < maximoTTL:
	# Imprimimos el TTL actual
	if args.verbose:
		print (("TTL: %d" %(actualTTL)).rjust(2))
	else:
		print (("%d" %(actualTTL)).rjust(2), end=' ')

	# Reseteamos las variables para este TTL
	ultimaIP = "*"
	ultimoRTT = "*"

	# Creamos una nueva lista donde guardaremos las 30 respuestas para el TTL actual
	if actualTTL not in respuestasRTT: respuestasRTT[actualTTL] = []

	# Vamos a contar la cantidad de Time Exceeded, ya que necesitamos que respondan al menos 30 veces dicho mensaje.
	# Si no hay respuesta luego de 30 intentos entonces proseguimos
	# con el siguiente TTL
	cantidadTimeExceeded = 0
	
	# Vamos a copiar la variable original para no perder el numero original
	# Nota: leer los comentarios del else (timeout) para entender por que se hace esto
	minimoTimeExceededRequeridos = respuestasTimeExceededDeseadas

	while cantidadTimeExceeded < minimoTimeExceededRequeridos:
		next_ttl = False

		#t_i = []
		#t_f = []
		respuestas = []
		probe = []

		# Mandamos queries simultaneas
		if args.verbose:
			print ("| Enviando %d queries con TTL=%d a %s..." %(args.queries, actualTTL, hostDestino))

		for x in range(0, args.queries):
			# Creamos el paquete a enviar con el TTL actual
			probe.append(IP(dst=hostDestino, ttl=actualTTL) / ICMP())
			#t_i.append(time())
			# Envia un paquete, y devuelve la respuesta (si la hubo)
			respuestas.append(sr1(probe[x], verbose=False, timeout=args.timeout))
			#t_f.append(time())

		# Nos guardamos nuestra IP local para usarla mas adelante
		ipLocal = probe[0].src

		if args.verbose:
			print ("| %d queries enviadas. Recibidas %d respuestas." %(args.queries, sum(x is not None for x in respuestas)))

		# Ejemplo practico con queries=15 y respuestasTimeExceededDeseadas=30
		# Salen las dos rafagas iniciales de 15 paquetes cada una.
		# Entre las dos rafagas, hay 29 respuestas del tipo Time Exceeded, y un timeout
		# Como cantidadTimeExceeded = 29 < minimoTimeExceededRequeridos = 30, vamos a enviar otra rafaga mas de 15 paquetes.
		# De esta nueva rafaga se obtienen 30 respuestas del tipo Time Exceeded.
		# Con lo cual vamos a obtener informacion equivalente a 29+30 = 59 mediciones

		for x in range(0, len(respuestas)):
			ans = respuestas[x]
			if ans is not None:
				# Pruebas de mediciones.
				#print(" t_i = %f" %(t_i[x]))
				#print(" t_f = %f" %(t_f[x]))
				#print(" t_f - t_i = %f ms" %((t_f[x] - t_i[x])*1000))
				#print(" ans.time = %f" %(ans.time))
				#print(" probe[x].sent_time = %f" %(probe[x].sent_time))
				#print(" ans.time - probe[x].sent_time = %f ms" %((ans.time - probe[x].sent_time)*1000))
				
				# Volvemos a setear minimoTimeExceededRequeridos a su valor inicial
				# Nota: leer los comentarios del else (timeout) para entender por que se hace esto
				minimoTimeExceededRequeridos = respuestasTimeExceededDeseadas

				# Hubo una respuesta del tipo Time Exceeded!
				cantidadTimeExceeded += 1

				# Imprimimos la IP si es que obtuvimos una nueva
				if not args.verbose:
					if (ans.src != ultimaIP):
						print ("(%s)" %(ans.src), end=' ')
						

				ultimaIP = ans.src
				ultimoRTT = (ans.time - probe[x].sent_time) * 1000 # (ans.time - probe.sent_time)*1000

				# Imprimimos el RTT
				if args.verbose:
					print ("|", end=' ')
					print (("%d" %(x+1)).rjust(2), end=' ')
					print ("(OK):", end=' ')
					print ("Respuesta de %s (%s) en %.2f ms" %(ans.src, "time-exceeded" if ans.type == 11 else ("echo-reply" if ans.type == 0 else ans.type), ultimoRTT))
				else:
					print (" %.2f ms" %(ultimoRTT), end=' ')

				# Guardamos los datos en nuestro diccionario para la clave actualTTL
				respuestasRTT[actualTTL].append((ultimaIP, ultimoRTT))

				# Guardamos la distancia entre salto y salto
				if (actualTTL == 1):
					# Si el TTL actual es 1, lo que queremos es guardar la distancia entre nuestra IP local y el primer salto (IP que acabamos de recibir).
					# Dicha distancia es simplemente el RTT medido en este caso.
					guardarDistancia(ipLocal, ultimaIP, ultimoRTT)					
				else:
					# Si no estamos en TTL 1, calculamos la distancia entre la IP
					# recien recibida y TODAS las IP recibidas en el anterior TTL
					# Nota: Esta bien conceptualmente? Que otra solucion podria haber?
					for ipSaltoAnterior in respuestasRTT[actualTTL-1]:
						guardarDistancia(ipSaltoAnterior[0], ultimaIP, ultimoRTT - ipSaltoAnterior[1])

				# Si ya llegamos al host destino nos guardamos la distancia total
				# (distancia entre nuestra IP local y el host destino), por si la necesitamos para algo
				# Aunque hayamos llegado al host destino, igual repetimos esto 30 veces (igual que cuando un salto
				# nos responde con Time Exceeded), asi hacemos promedio sobre el host destino tambien
				if (ultimaIP == hostDestino):
					distanciasAlHost.append(ultimoRTT)

			else:
				# Salto el timeout!
				# Que hacemos? Puede pasar que un salto decida no responder
				# con un Time Exceeded el 100% de las veces. En ese caso,
				# cuanto tiempo tenemos que esperar para proseguir con el proximo TTL?
				if args.verbose:
					print ("|", end=' ')
					print (("%d" %(x+1)).rjust(2), end=' ')
					print ("(ERROR): *")
				else:
					print ("*", end=' ')

				# Vamos a hacer un truquillo, que consiste en decrementar en 1, temporalmente,
				# la variable minimoTimeExceededRequeridos (variable que indica la cantidad minima de Time Exceeded a esperar)
				
				# De esta forma, cada vez que salte un timeout vamos acercando la variable cantidadTimeExceeded a minimoTimeExceededRequeridos,
				# sin tocar el contador actual de Time Exceeded

				# Si por algun milagro divino recibimos alguna respuesta Time Exceeded mas adelante, volvemos a setear minimoTimeExceededRequeridos en 30,
				# porque significa que, esperando el suficiente tiempo, vamos a poder llegar a los 30 Time Exceeded iniciales que queriamos (o los que fueran por parametro)

				minimoTimeExceededRequeridos -= 1

				if (cantidadTimeExceeded >= minimoTimeExceededRequeridos):
					# Si estamos aca es porque realmente la IP no quiere respondernos con un Time Exceeded

					# Ya decrementamos tanto minimoTimeExceededRequeridos que cantidadTimeExceeded lo supero
					# Volvemos a setear minimoTimeExceededRequeridos a su valor inicial
					# y salimos de este while
					minimoTimeExceededRequeridos = respuestasTimeExceededDeseadas
					next_ttl = True
		
		if next_ttl:
			break

	# Llegamos a las 30 (o mas) respuestas Time Exceeded para este TTL (o a una cantidad considerable de timeouts)
	# Flusheamos el buffer de print
	if args.verbose:
		print ("|")
		print ("| Cantidad total de time-exceeded recibidos: %d/%d" %(cantidadTimeExceeded, respuestasTimeExceededDeseadas))
		print ("|_____")
	print ("")
	print ("")

	# Pasamos al siguiente TTL
	actualTTL += 1

	# Si ya llegamos aca es porque ya llegamos al host destino y ademas
	# ya hicimos las 30 mediciones sobre el. Salimos, no hace falta esperar a llegar al maximo TTL
	if (ultimaIP == hostDestino):
		break;

# Si llegamos aca es porque ya llegamos al host destino y el mismo nos respondio unas 30 veces	
if distanciasAlHost:	
	print("Se ha llegado al host %s en %d hops" %(args.host, actualTTL-1))
else:
	print("No se ha podido llegar al host %s en %d hops" %(args.host, actualTTL-1))

print("")

# Calculamos distancias promedio
# Para ello, tomamos los valores de distancias acumulados (campo RTT de la tupla) y los dividimos por la cantidad (campo cantidad de la tupla)
for x in range(0, len(distancias)):
	# Nota: la unica forma de modificar una tupla es creando una tupla nueva usando los valores anteriores
	distancias[x] = (distancias[x][0], distancias[x][1], distancias[x][2]/distancias[x][3], distancias[x][3])

# Calculamos la distancia al host promedio (si es que llegamos)
if distanciasAlHost:
	distanciaAlHostPromedio = average(distanciasAlHost)

# Calculamos los outliers y los guardamos en una variable global
findOutliers()

# Calculo la media de todas las distancias
media = reduce(lambda x, y: x + y, [ x[2] for x in distancias ]) / len(distancias)

# Calculo el desvio estandar de la muestra
sumatoria = 0
for x in range(0, len(distancias)):
    sumatoria += ((distancias[x][2] - media)**2)
desvioEstandar = math.sqrt((sumatoria/(len(distancias)-1)))

# Imprimimos la tabla con toda la info
print ("+-----------------+-----------------+----------+------------+------------------+-------------+")
print ("|", end=' ')
print (("IP1").center(15), end=' ')
print ("|", end=' ')
print (("IP2").center(15), end=' ')
print ("|", end=' ')
print (("RTT (ms)").center(8), end=' ')
print ("|", end=' ')
print (("Mediciones").center(10), end=' ')
print ("|", end=' ')
print (("(x_i-media(X))/S").center(16), end=' ')
print ("|", end=' ')
print (("Es Outlier?").center(10), end=' ')
print ("|")
print ("+-----------------+-----------------+----------+------------+------------------+-------------+")

for x in range(0, len(distancias)):
	print ("|", end=' ')
	print ((distancias[x][0]).ljust(15), end=' ')
	print ("|", end=' ')
	print ((distancias[x][1]).ljust(15), end=' ')
	print ("|", end=' ')
	print (("%.2f" %(distancias[x][2])).rjust(8), end=' ')
	print ("|", end=' ')
	print (("%d" %(distancias[x][3])).rjust(10), end=' ')
	print ("|", end=' ')
	print (("%.2f" %((distancias[x][2] - media)/desvioEstandar)).rjust(16), end=' ')
	print ("|", end=' ')
	print (("X" if esOutlier(x) else "").center(11), end=' ')
	print ("|")

print ("+-----------------+-----------------+----------+------------+------------------+-------------+")

print("")
