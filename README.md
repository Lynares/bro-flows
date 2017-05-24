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
