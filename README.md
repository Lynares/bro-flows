# Aplicación para BRO
## Emparejamiento de paquetes

La documentación usada es la que nos proporciona BRO a través de su [web](https://www.bro.org/documentation/index.html "documentacion de BRO")

Consiste en un script para BRO el cual mediante DPI empareja los paquetes.

En este momento empareja los paquetes TCP, UDP e ICMP, mediante la gestión de distintos eventos.

Para ejecutar el script bastará con instalar BRO como se dice en la documentación y en la carpeta raíz usar:

``````````````

~$ bro -b -r pcap/nitroba.pcap scripts/aprox2.bro

``````````````

Obviamente se podrá usar otro archivo pcap o cualquier otro script de BRO.

La función que se usará para el emparejamiento de flujos será la dada en el articulo "A generalizable dynamic flow pairing method for traffic classification"

`````````````````

resultado=(Nip-1)+(1/((Po1-Po2)+k1))+(1/((Pd1-Pd2)+k1))+(1/(dt+k2));

`````````````````
