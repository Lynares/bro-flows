
#Cambio de vector a set por las comparaciones, el tipo vector en bro no las soporta
global conex: set[connection];
global tam=0;
# Cada vez que entra un nuevo paquete lo comparo con lo que ya tengo en el set
event new_connection(c: connection){
# Si el set esta vacio meto el primer paquete
   add conex[c];
   tam=tam+1;
   print fmt("Numero total paquetes = %d",|conex|);
   print fmt("Tamanio con tam: %d", tam);

}
