# Aplicación para BRO
## Emparejamiento de paquetes

La documentación usada es la que nos proporciona BRO a través de su [web](https://www.bro.org/documentation/index.html "documentacion de BRO")

Consiste en un script para BRO el cual mediante DPI empareja los paquetes.

En este momento empareja los paquetes TCP, UDP e ICMP, mediante la gestión de distintos eventos.

Para ejecutar el script bastará con instalar BRO como se dice en la documentación y en la carpeta raíz usar:
Primero
`````````````
export PATH=/usr/local/bro/bin:$PATH

`````````````
Y después:

``````````````

~$ bro -b -r pcap/nitroba.pcap scripts/aprox2.bro

``````````````

Obviamente se podrá usar otro archivo pcap o cualquier otro script de BRO.

La función que se usará para el emparejamiento de flujos será la dada en el articulo "A generalizable dynamic flow pairing method for traffic classification"

`````````````````

resultado=(Nip-1)+(1/((Po1-Po2)+k1))+(1/((Pd1-Pd2)+k1))+(1/(dt+k2))

`````````````````
Donde Nip es el número de flujos con la misma IP y puerto, Po1, Pd1, Po2 y Pd2 son los puertos de origen y de destino de los dos paquetes, k1 y k2 son variables que ponemos nosotros y dt es la diferencia de tiempo entre el primer paquete del primer flujo y el primer paquete del segundo flujo.
