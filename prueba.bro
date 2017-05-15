
#@load base/protocols/conn/main.bro

## Para conexiones de tipo TCP
## connection_established se ejecuta cada vez que un SYN-ACK pasa por nosotros desde el receptor del TCP handshake.
##event connection_established(c: connection)
  ##{
  ##  print fmt("%s:  Nueva conexion establecida desde %s a %s\n", strftime("%Y/%M/%d %H:%m:%S", network_time()), c$id$orig_h, c$id$resp_h);
  ##}
## Para todo tipo de conexiones, ya sean TCP, UDP o ICMP. Este evento salta con cada nueva conexion, con el primer paquete de una conexion desconocida, por lo que mirando el documento generado vemos que esto es un nuevo flujo.
event new_connection(c: connection)
  {
  # NO usar \n en print fmt para no mostrar \x04 en el terminal
  if(connection_exists(c$id)){
    print fmt("Nueva conexion establecida Timestamp: %s desde %s a %s", strftime("%Y/%M/%d %H:%m:%S", network_time()), c$id$orig_h, c$id$resp_h);
    print fmt("Protocolo del puerto: %s", get_port_transport_proto(c$id$orig_p));
    print fmt("Informacion de las 4 tuplas del paquete: %s", c$id);
  }else{
  print fmt("La conexion ya existe");
  print fmt("___________________________________________________________________________");
  }
#   print fmt("Servicio: %s\n", c$service); #Lo devuelve vacio
#    print c; #Mostrar toda la informacion de la conexion.
  }
# Solo disponible para conexiones TCP, se genera cuando no hay actividad en un
# periodo de tiempo determinado.
event connection_timeout(c: connection)
  {
    print fmt("Conexion TCP ha excedido el timeout: %s",c$id);
  }
# Este evento salta para todo tipo de conexion, se da cuando el estado interno
# esta a punto de eliminarse de memoria
event connection_state_remove(c: connection)
{
  #print fmt("Conexion %s para eliminar de la memoria", c$uid);
  print fmt("Conexion %s a %s para eliminar de la memoria", c$id$orig_h, c$id$resp_h);
}




#event connection_established(c: connection)
#  {
#    print fmt("Nueva conexion establecida con connection_established"); #Solo trafico TCP con un SYN-ACK
#  }
