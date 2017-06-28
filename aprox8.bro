
## PRIMERA APROXIMACION con un solo set, simplemente almaceno los flujos en un set (PARA FLUJOS ACTIVOS) y cuando mueren los elimino
## El contenido del set si se ve alterado, pero el tamaño no, pues no es memoria dinamica
## Cambio de vector a set por las comparaciones, el tipo vector en bro no las soporta
## global conex: set[connection];

## Variable global para conocer el tamaño del set
global tams=0;
## Variable global para conocer el numero de flujos que hay en el archivo pcap
global tam=0;
## Variable para ver los flujos que eliminamos y comprobar si son los mismos que los que hemos añadido
global elimi=0;

## Tabla para guardar los flujos que son emparejados
## global emparejados: table[connection] of connection;
global collection: table[addr, addr, port, port] of vector of connection;

## El umbral: "Comparar la constante 'k', que es el umbral que fijaré con el resultado que devuelve la función,
## si es más grande el resultado que 'k' se puede decir que los dos flujos son iguales, si es más pequeño podemos decir que los dos flujos no son iguales"
## resultado del umbral
global umbral: double;

## Definimos el umbral, de manera global para hacer las comparaciones
global k=0.01;


## Creo funcion auxiliar para ver la informacion del flujo nuevo que se añade, no de todos los flujos todo el rato
function informacion_flujo(c: connection){
    print fmt("Informacion del flujo nuevo IPo: %s , Po: %s , IPd: %s , Pd: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
}


## Creo funcion auxiliar para ver la informacion del flujo que se coincide
function informacion_coincidencia(c: connection, p: connection){
    print fmt("Informacion del primer flujo  IPo: %s , Po: %s , IPd: %s , Pd: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    print fmt("Informacion del flujo coincidente  IPo: %s , Po: %s , IPd: %s , Pd: %s ", p$id$orig_h, p$id$orig_p, p$id$resp_h, p$id$resp_p);
}

## funcion para la comparacion de los flujos, c1 el flujo que esta en el set conex y c2 para el flujo que es candidato a guardarse en empa
function emparejamiento(c1: connection, c2: connection ):double {

  local Nip=1; ## Variable para saber cuantas conexiones tenemos
  local Po1: count; ## Puerto origen del primer flujo
  local Po2: count; ## Puerto origen del segundo flujo
  local Pd1: count; ## Puerto destino del primer flujo
  local Pd2: count; ## Puerto destino del segundo flujo
  local k1 = 1;  ## Variable fija
  local k2 = 10; ## Variable fija
  local dt: double; ## Variable para la diferencia de los tiempos
  local resultado = 0.0; ## Lo ponemos a 0
  print c1$uid;
  print c2$uid;
## Podemos saltarnos este bucle si inicializamos Nip a 1
  ## for (s in conex){

  ##   if((s$id$orig_h == c1$id$orig_h) && (s$id$resp_h == c1$id$resp_h) && (s$id$orig_p == c1$id$orig_p) && (s$id$resp_p == c1$id$resp_p)){
  ##           Nip=Nip+1;
  ##           print fmt("Numero de Nip sin table: %d", Nip);
  ##           break;
  ##   }
  ## }

  if(c1$uid==c2$uid){
    print fmt("Son el mismo flujo, no se realiza incremento en Nip");
  }else{
## Este bucle lo puedo hacer sin ningun problema, pues en los eventos todavia no se ha dicho que se guarde en el set
  for (i in empa){
    if((i$id$orig_h == c2$id$orig_h) && (i$id$resp_h == c2$id$resp_h) && (i$id$orig_p == c2$id$orig_p) && (i$id$resp_p == c2$id$resp_p)){
            Nip=Nip+1;

    }
  }
  print fmt("Numero de Nip en table: %d", Nip);
  informacion_coincidencia(c1,c2);
  print fmt("Tiempo de inicio del flujo: %s", |c1$start_time|);
  print fmt("Tiempo de inicio del flujo: %s", |c2$start_time|);
  ## Para dp1 y dp2 que son 1-norm usamos la "Manhattan norm" que dice lo siguiente: SAD(x1,x2) = sumatoria(x1i - x2i)
  ## k1 y k2 son dos variables que nosotros le ponemos de forma manual, en este caso las pondremos como locales con 1 y 10 respectivamente
  ## dt es la diferencia de tiempo entre los time stamp de los primeros flujos de los flujos
  ## el tipo time se supone que es como un double, por lo tanto podremos restarlos sin problemas
  ## para la comparacion de puertos primero tendremos que hacer uso de la funcion  port_to_count [https://www.bro.org/sphinx/scripts/base/bif/bro.bif.bro.html#id-port_to_count]
  ## la cual nos pasa el puerto, que recordamos que va tambien con un string en el cual se nos dice que tipo es, a un
  ## valor numerico que si podremos restar sin problemas
  ## La funcion quedaria asi: (Nip-1)+(1/(dp1+k1))+(1/(dp2+k1))+(1/(dt+k2))
  Po1=port_to_count(c1$id$orig_p);
  Pd1=port_to_count(c1$id$resp_p);
  Po2=port_to_count(c2$id$orig_p);
  Pd2=port_to_count(c2$id$resp_p);
  ## local t1: double;
  ## local t2: double;
  ## t1 = time_to_double(c1$start_time);
  ## t2 = time_to_double(c2$start_time);

  dt=(|c1$start_time| - |c2$start_time|);

  ## print fmt("Tiempo paquete 1: %s", t1);
  ## print fmt("Tiempo paquete 2: %s", t2);
  print fmt("Diferencia de tiempo: %s", dt);
  resultado=(Nip-1)+(1/((Po1-Po2)+k1))+(1/((Pd1-Pd2)+k1))+(1/(dt+k2));
 }
 return resultado;

}

## Cada vez que entra un nuevo flujo compruebo que si esta en la tabla
## Este evento se lanza con cada nueva conexion de un flujo que no sea conocido, por lo tanto se supone que nunca entrara en el else
## Generated for every new connection. This event is raised with the first packet of a previously unknown connection. Bro uses a flow-based definition of “connection” here that includes not only TCP sessions but also UDP and ICMP flows.
event new_connection(c: connection){
  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  if( [orig,dest,po,pd] !in collection ){

    ## Si no estan los valores clave del flujo lo creamos
    collection[orig,dest,po,pd]=vector(c);

  } else {

    ## Si ya esta, lo añadimos
    collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = c;

  }

}

## Cuando la conexion va a ser borrada la eliminamos del set y en caso de tener otra conexion en el empa la añadimos
## se obtienen los mismos flujos añadidos que eliminados, por lo tanto hay que controlar cuando lo añadimos y cuando lo eliminamos
## Sirve para TCP, UDP e ICMP
## Generated when a connection’s internal state is about to be removed from memory. Bro generates this event reliably
## once for every connection when it is about to delete the internal state. As such, the event is well-suited for
## script-level cleanup that needs to be performed for every connection.
## This event is generated not only for TCP sessions but also for UDP and ICMP flows.
event connection_state_remove(c: connection){

  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  if( [orig,dest,po,pd] in collection ){
    ## Si existe en la coleccion




  } else {
    ## Si no existe en la coleccion

  }

    ## Aqui si tenemos otro flujo igual al que vamos a eliminar lo metemos en conex para que ocupe el lugar del que vamos a borrar
    ## Con la variable booleana controlamos el decrecimiento del set
    ##if (esta==T){
    ##  delete conex[c];
    ##  add conex[cl];
    ##  delete empa[cl];
      ## print fmt("Hemos borrado");
      ## print empa[cl];
    ##} else {
    ##  delete conex[c];
    ##}

}

## Cuando la conexion se establece vemos si hay flujos que emparejar y los metemos en la tabla
## Solo sirve para conexiones TCP, se genera cuando ve un SYN-ACK que responde al handshake de un TCP
event connection_established(c: connection){

  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = collection[orig,dest,po,pd][0];

  if( [orig,dest,po,pd] in collection ){
    ## Si existe en la coleccion
    if(cl$uid == c$uid){
      ## Si tienen el mismo uid pasamos del flujo, pues son el mismo
      next;

    } else {
      ## Si no tienen el mismo uid pasamos a comprobar
      umbral=emparejamiento(cl,c);

      if(umbral>k){
        ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
        print fmt("Si son emparejables TCP"); ## Mostramos TCP para saber en que evento se han calculado
        collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = c;

      } else{
        ## Si el umbral calculado es menor que el umbral de comparacion no lo añadimos
        print fmt("No son emparejables TCP");

      }
    }
  }

}


## Este evento se lanza cuando una conexion TCP finaliza de forma normal
event connection_finished(c: connection){

  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = collection[orig,dest,po,pd][0];

  if( [orig,dest,po,pd] in collection ){
    ## Si existe en la coleccion
    if(cl$uid == c$uid){
      ## Si tienen el mismo uid pasamos del flujo, pues son el mismo
      next;

    } else {
      ## Si no tienen el mismo uid pasamos a comprobar
      umbral=emparejamiento(cl,c);

      if(umbral>k){
        ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
        print fmt("Si son emparejables TCP"); ## Mostramos TCP para saber en que evento se han calculado
        collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = c;

      } else{
        ## Si el umbral calculado es menor que el umbral de comparacion no lo añadimos
        print fmt("No son emparejables TCP");

      }
    }
  }

}


## Para protocolo UDP usaremos otro evento
## Son funciones muy costosas por lo que se deberia de evitar su uso a menos que sea necesario
## udp_request se lanza por cada flujo UDP del flujo que es enviado por el origen.
event udp_request(u: connection){

  local orig = u$id$orig_h;
  local dest = u$id$resp_h;
  local po = u$id$orig_p;
  local pd = u$id$resp_p;

  local ul = collection[orig,dest,po,pd][0];

  if( [orig,dest,po,pd] in collection ){
    ## Si existe en la coleccion
    if(ul$uid == u$uid){
      ## Si tienen el mismo uid pasamos del flujo, pues son el mismo
      next;

    } else {
      ## Si no tienen el mismo uid pasamos a comprobar
      umbral=emparejamiento(ul,u);

      if(umbral>k){
        ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
        print fmt("Si son emparejables UDP request"); ## Mostramos UDP para saber en que evento se han calculado
        collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = u;

      } else{
        ## Si el umbral calculado es menor que el umbral de comparacion no lo añadimos
        print fmt("No son emparejables UDP request");

      }
    }
  }

}

## udp_reply se lanza por cada flujo UDP del flujo que es devuelto por el destinatario del primer envio.
## cabecera del evento event udp_reply(u: connection)
event udp_reply(u: connection){

  local orig = u$id$orig_h;
  local dest = u$id$resp_h;
  local po = u$id$orig_p;
  local pd = u$id$resp_p;

  local ul = collection[orig,dest,po,pd][0];

  if( [orig,dest,po,pd] in collection ){
    ## Si existe en la coleccion
    if(ul$uid == u$uid){
      ## Si tienen el mismo uid pasamos del flujo, pues son el mismo
      next;

    } else {
      ## Si no tienen el mismo uid pasamos a comprobar
      umbral=emparejamiento(ul,u);

      if(umbral>k){
        ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
        print fmt("Si son emparejables UDP reply"); ## Mostramos UDP para saber en que evento se han calculado
        collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = u;

      } else{
        ## Si el umbral calculado es menor que el umbral de comparacion no lo añadimos
        print fmt("No son emparejables UDP reply");

      }
    }
  }

}

## udp_session_done se lanza cuando la conexion UDP finaliza, por lo tanto tendremos que borrar del set conex los flujos que se correspondan
## Generated when a UDP session for a supported protocol has finished. Some of Bro’s application-layer UDP analyzers flag the end of a session by raising this event. Currently, the analyzers for DNS, NTP, Netbios, Syslog, AYIYA, Teredo, and GTPv1 support this.
## Segun la documentacion esto es soportado por los siguientes protocolos DNS, NTP, Netbios, Syslog, AYIYA, Teredo y GTPv1.
## la cabecera es event udp_session_done(u: connection)
## valorar si se debe de poner

## Para mensajes ICMP, tendremos que usar otro tipo de evento especifico para este tipo
## ICMP manda mensajes de echo, el primero de tipo request, mensaje de control para recibir un mensaje reply
## icmp_echo_request Type:	event (c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
## ICMP manda el reply una vez que se manda el request
## icmp_echo_reply Type:	event (c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
## Habra que tener en cuenta que no se exceda el payload
## icmp_conn extiende la informacion de connection, en esta aproximacion no sera necesario usarlo
## Segun la documentacion la descripcion de las variables para los dos eventos son:
## c:	The connection record for the corresponding ICMP flow.
## icmp:	Additional ICMP-specific information augmenting the standard connection record c.
## id:	The echo reply identifier.
## seq:	The echo reply sequence number.
## payload:	The message-specific data of the packet payload, i.e., everything after the first 8 bytes of the ICMP header.

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = collection[orig,dest,po,pd][0];

  if( [orig,dest,po,pd] in collection ){
    ## Si existe en la coleccion
    if(cl$uid == c$uid){
      ## Si tienen el mismo uid pasamos del flujo, pues son el mismo
      next;

    } else {
      ## Si no tienen el mismo uid pasamos a comprobar
      umbral=emparejamiento(cl,c);

      if(umbral>k){
        ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
        print fmt("Si son emparejables ICMP request"); ## Mostramos ICMP para saber en que evento se han calculado
        collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = c;

      } else{
        ## Si el umbral calculado es menor que el umbral de comparacion no lo añadimos
        print fmt("No son emparejables ICMP request");

      }
    }
  }

}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = collection[orig,dest,po,pd][0];

  if( [orig,dest,po,pd] in collection ){
    ## Si existe en la coleccion
    if(cl$uid == c$uid){
      ## Si tienen el mismo uid pasamos del flujo, pues son el mismo
      next;

    } else {
      ## Si no tienen el mismo uid pasamos a comprobar
      umbral=emparejamiento(cl,c);

      if(umbral>k){
        ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
        print fmt("Si son emparejables ICMP reply"); ## Mostramos ICMP para saber en que evento se han calculado
        collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = c;

      } else{
        ## Si el umbral calculado es menor que el umbral de comparacion no lo añadimos
        print fmt("No son emparejables ICMP reply");

      }
    }
  }

}

## Evento que se lanza cuando se inicia BRO.
event bro_init(){

  print fmt("Hora de inicio: %s", current_time());

}

## Evento que se genera cuando BRO va a tenerminar, menos si se realiza mediante una llamada a la funcion exit (ver documentacion)
event bro_done(){

  ## Mostramos lo que tenemos en la tabla de emparejados
  for(s in emparejados){
    ## print fmt("Tamaño de la fila de la tabla: %d", |empa[s]|);
    ## print fmt("Tenemos: %s en %s a %s en %s", emparejados[s]$id$orig_h, emparejados[s]$id$orig_p, emparejados[s]$id$resp_h, emparejados[s]$id$resp_p);
    ## print fmt(" de %s en %s a %s en %s", s$id$orig_h, s$id$orig_p, s$id$resp_h, s$id$resp_p);
    informacion_coincidencia(emparejados[s], s);
  }

  ## for(i in emparejados){
    ## print fmt("Tenemos lo siguiente:");
    ## print emparejados[i];
  ## }

  print fmt("Total de flujos: %d", tam);
  print fmt("Hora de finalizacion: %s", current_time());
}
