
## Tabla para guardar los flujos que son emparejados
global collection: table[addr, addr, port, port] of vector of connection &synchronized;
global collection_added: table[addr, addr, port, port] of vector of connection;

## El umbral: "Comparar la constante 'k', que es el umbral que fijaré con el resultado que devuelve la función,
## si es más grande el resultado que 'k' se puede decir que los dos flujos son iguales, si es más pequeño podemos decir que los dos flujos no son iguales"
## resultado del umbral que calculamos
global umbral: double;

## Definimos el umbral, de manera global para hacer las comparaciones
global k=10;

## Creo funcion auxiliar para ver la informacion del flujos que son coincidentes
function informacion_coincidencia(c: connection, p: connection){
    print fmt("Informacion del primer flujo  IPo: %s , Po: %s , IPd: %s , Pd: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    print fmt("Informacion del flujo coincidente  IPo: %s , Po: %s , IPd: %s , Pd: %s ", p$id$orig_h, p$id$orig_p, p$id$resp_h, p$id$resp_p);
}

## Funcion auxiliar para mostrar la informacion de un solo flujo
function informacion_flujo(c: connection){
    print fmt("Informacion del flujo añadido IPo: %s , Po: %s , IPd: %s , Pd: %s, uid: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, c$uid);
}

## funcion para la comparacion de los flujos, c1 el flujo que esta el primero en el vector de la tabla y c2 para el flujo que es candidato a ser emparejado
function emparejamiento(c1: connection, c2: connection ):double {

  ## Añadimos variables para comprobar en la tabla, sin hacer bucle
  local orig = c1$id$orig_h;
  local dest = c1$id$resp_h;
  local po = c1$id$orig_p;
  local pd = c1$id$resp_p;

  local Nip = |collection[orig,dest,po,pd]|; ## Variable para saber cuantas conexiones tenemos
  local Po1: count; ## Puerto origen del primer flujo
  local Po2: count; ## Puerto origen del segundo flujo
  local Pd1: count; ## Puerto destino del primer flujo
  local Pd2: count; ## Puerto destino del segundo flujo
  local k1 = 1;  ## Variable fija
  local k2 = 10; ## Variable fija
  local dt: double; ## Variable para la diferencia de los tiempos
  local resultado = 0.0; ## Lo inciamos a 0
  print c1$uid;
  print c2$uid;

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

 return resultado;

}

## Cada vez que entra un nuevo flujo compruebo que si esta en la tabla
## Este evento se lanza con cada nueva conexion de un flujo que no sea conocido, pero al borrarlo de memoria será desconocido aunque ya lo tengamos en la tabla
## Generated for every new connection. This event is raised with the first packet of a previously unknown connection. Bro uses a flow-based definition of “connection” here that includes not only TCP sessions but also UDP and ICMP flows.
event new_connection(c: connection){
  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;
  print fmt("new_connection");
  if( [orig,dest,po,pd] !in collection ){

    ## Si no estan los valores clave del flujo lo creamos
    collection[orig,dest,po,pd]=vector(c);
    informacion_flujo(c);
    print fmt("Añadimos una nueva conexion");
  } else {

    ## Si ya esta, lo añadimos
    collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = c;
    informacion_flujo(c);
    print fmt("Ya esta y la añadimos");
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
  local coleccion = collection[orig,dest,po,pd];
  local tama=|coleccion|;


  for(j in coleccion){
    if(j+1 >= tama){
      if(tama==1){
        collection[orig,dest,po,pd]=vector();
      }
      if(j+1==tama){
        delete collection[orig,dest,po,pd][tama]; ## Aqui esta el error
      }
      break;
    } else {
      collection[orig,dest,po,pd][j]=coleccion[j+1];
    }
  }

  print fmt("Terminamos copia y borrado...");

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
      print fmt("connection_established");

      if(umbral>k){
        ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
        print fmt("Si son emparejables TCP"); ## Mostramos TCP para saber en que evento se han calculado
        collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = c;
        informacion_coincidencia(cl, c);
        if( [orig,dest,po,pd] !in collection_added ){

          collection_added[orig,dest,po,pd]=vector(c);
          print fmt("Añadimos una nueva conexion al vector de coincidencias");
        } else {

          ## Si ya esta, lo añadimos
          collection_added[orig,dest,po,pd][|collection_added[orig,dest,po,pd]|] = c;
          print fmt("Ya esta en vector de coincidencias y la añadimos");
        }

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
      print fmt("connection_finished");
      if(umbral>k){
        ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
        print fmt("Si son emparejables TCP"); ## Mostramos TCP para saber en que evento se han calculado
        collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = c;
        informacion_coincidencia(cl, c);
        if( [orig,dest,po,pd] !in collection_added ){

          collection_added[orig,dest,po,pd]=vector(c);
          print fmt("Añadimos una nueva conexion al vector de coincidencias");
        } else {

          ## Si ya esta, lo añadimos
          collection_added[orig,dest,po,pd][|collection_added[orig,dest,po,pd]|] = c;
          print fmt("Ya esta en vector de coincidencias y la añadimos");
        }

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
      print fmt("udp_request");
      if(umbral>k){
        ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
        print fmt("Si son emparejables UDP request"); ## Mostramos UDP para saber en que evento se han calculado
        collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = u;
        informacion_coincidencia(ul, u);
        if( [orig,dest,po,pd] !in collection_added ){

          collection_added[orig,dest,po,pd]=vector(u);
          print fmt("Añadimos una nueva conexion al vector de coincidencias");
        } else {

          ## Si ya esta, lo añadimos
          collection_added[orig,dest,po,pd][|collection_added[orig,dest,po,pd]|] = u;
          print fmt("Ya esta en vector de coincidencias y la añadimos");
        }
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
      print fmt("udp_reply");
      if(umbral>k){
        ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
        print fmt("Si son emparejables UDP reply"); ## Mostramos UDP para saber en que evento se han calculado
        collection[orig,dest,po,pd][|collection[orig,dest,po,pd]|] = u;
        informacion_coincidencia(ul, u);
        if( [orig,dest,po,pd] !in collection_added ){

          collection_added[orig,dest,po,pd]=vector(u);
          print fmt("Añadimos una nueva conexion al vector de coincidencias");
        } else {

          ## Si ya esta, lo añadimos
          collection_added[orig,dest,po,pd][|collection_added[orig,dest,po,pd]|] = u;
          print fmt("Ya esta en vector de coincidencias y la añadimos");
        }

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
        informacion_coincidencia(cl, c);
        if( [orig,dest,po,pd] !in collection_added ){

          collection_added[orig,dest,po,pd]=vector(c);
          print fmt("Añadimos una nueva conexion al vector de coincidencias");
        } else {

          ## Si ya esta, lo añadimos
          collection_added[orig,dest,po,pd][|collection_added[orig,dest,po,pd]|] = c;
          print fmt("Ya esta en vector de coincidencias y la añadimos");
        }

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
        informacion_coincidencia(cl, c);
        if( [orig,dest,po,pd] !in collection_added ){

          collection_added[orig,dest,po,pd]=vector(c);
          print fmt("Añadimos una nueva conexion al vector de coincidencias");
        } else {

          ## Si ya esta, lo añadimos
          collection_added[orig,dest,po,pd][|collection_added[orig,dest,po,pd]|] = c;
          print fmt("Ya esta en vector de coincidencias y la añadimos");
        }

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

  ##local cl: connection;

  ## Mostramos lo que tenemos en la tabla de emparejados
   ##for([o, d, s, f] in collection_added){
     ##cl = collection_added[o,d,s,f][0];
     ##print fmt("Tenemos: %s en %s a %s en %s", cl$id$orig_h, cl$id$orig_p, cl$id$resp_h, cl$id$resp_p);
     ##print fmt(" de %s en %s a %s en %s", collection_added[o,d,s,f][|collection_added[o,d,s,f]|]$id$orig_h, collection_added[o,d,s,f][|collection_added[o,d,s,f]|]$id$orig_p, collection_added[o,d,s,f][|collection_added[o,d,s,f]|]$id$resp_h, collection_added[o,d,s,f][|collection_added[o,d,s,f]|]$id$resp_p);
  ##  informacion_coincidencia(cl, collection[o,d,s,f][|collection[o,d,s,f]|]);
  ##}

  ## print fmt("Total de flujos: %d", tam);
  print fmt("Hora de finalizacion: %s", current_time());
}
