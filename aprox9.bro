#Autor: Álvaro Maximino Linares Herrera
#Descripción: Script de Bro para la identificación de tráfico mediante emparejamiento de flujos

module BROFLOWS;

## Tablas para guardar los flujos
global collection: table[addr, port] of vector of connection &synchronized;
global collection_added: table[addr, port] of vector of connection;

export{
  redef enum Log::ID += { LOG };
  type Info: record {
    orig1: addr &log;
    po1: port &log;
    dest1: addr &log;
    pd1: port &log;
    uid1: string &log;
    informacion: string &log;
    orig2: addr &log;
    po2: port &log;
    dest2: addr &log;
    pd2: port &log;
    uid2: string &log;
  };
  global log_flow: event(rec: Info);

}

## Evento que se lanza cuando se inicia BRO.
event bro_init(){

  Log::create_stream(BROFLOWS::LOG, [$columns=Info, $ev=log_flow]);

}

## Evento que se genera cuando BRO va a tenerminar, menos si se realiza mediante una llamada a la funcion exit (ver documentacion)
event bro_done(){

  print fmt("Hora de finalizacion: %s", current_time());

}



## El umbral: "Comparar la constante 'k', que es el umbral que fijaré con el resultado que devuelve la función,
## si es más grande el resultado que 'k' se puede decir que los dos flujos son iguales, si es más pequeño podemos decir que los dos flujos no son iguales"
## resultado del umbral que calculamos
global umbral: double;

## Definimos el umbral, de manera global para hacer las comparaciones
global k=0.01;

## Creo funcion auxiliar para ver la informacion del flujos que son coincidentes
function informacion_coincidencia(c: connection, p: connection){
    print fmt("Informacion del primer flujo  IPo: %s , Po: %s , IPd: %s , Pd: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    print fmt("Informacion del flujo coincidente  IPo: %s , Po: %s , IPd: %s , Pd: %s ", p$id$orig_h, p$id$orig_p, p$id$resp_h, p$id$resp_p);
}

## Funcion auxiliar para mostrar la informacion de un solo flujo
function informacion_flujo(c: connection){
    print fmt("Informacion del flujo aniadido IPo: %s , Po: %s , IPd: %s , Pd: %s, uid: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, c$uid);
}

## funcion para la comparacion de los flujos, c1 el flujo que esta el primero en el vector de la tabla y c2 para el flujo que es candidato a ser emparejado
function emparejamiento(c1: connection, c2: connection ):double {

  ## Añadimos variables para comprobar en la tabla, sin hacer bucle
  local orig = c1$id$orig_h;
  local dest = c1$id$resp_h;
  local po = c1$id$orig_p;
  local pd = c1$id$resp_p;
  local uid1 = c1$uid;

  local orig2 = c2$id$orig_h;
  local dest2 = c2$id$resp_h;
  local po2 = c2$id$orig_p;
  local pd2 = c2$id$resp_p;
  local uid2 = c2$uid;

  local Nip: double;

  if((orig==orig2) && (dest==dest2)){
    Nip=2;
  } else if((orig==dest2) && (dest==orig2)){
    Nip=2;
  }else if((orig==dest2) || (dest==orig2)){
    Nip=1;
  }else if((orig==orig2) || (dest==dest2)){
    Nip=1;
  } else {
    Nip=0;
  }


  local Po1: count; ## Puerto origen del primer flujo
  local Po2: count; ## Puerto origen del segundo flujo
  local Pd1: count; ## Puerto destino del primer flujo
  local Pd2: count; ## Puerto destino del segundo flujo
  local k1 = 10;  ## Variable fija
  local k2 = 1000; ## Variable fija
  local dt: double; ## Variable para la diferencia de los tiempos
  local resultado = 0.0; ## Lo inciamos a 0

  ## Se imprimen los dos uid's a eliminar'
  print c1$uid;
  print c2$uid;

  print fmt("Numero de IP coincidentes: %s", Nip);
  informacion_coincidencia(c1,c2);
  ## print fmt("Tiempo de inicio del flujo: %s", |c1$start_time|);
  ## print fmt("Tiempo de inicio del flujo: %s", |c2$start_time|);
  ## Para dp1 y dp2 que son 1-norm usamos la "Manhattan norm" que dice lo siguiente: SAD(x1,x2) = sumatoria(x1i - x2i)
  ## k1 y k2 son dos variables que nosotros le ponemos de forma manual, en este caso las pondremos como locales con 1 y 10 respectivamente
  ## dt es la diferencia de tiempo entre los time stamp de los primeros flujos de los flujos
  ## el tipo time se supone que es como un double, por lo tanto podremos restarlos sin problemas
  ## para la comparacion de puertos primero tendremos que hacer uso de la funcion  port_to_count [https://www.bro.org/sphinx/scripts/base/bif/bro.bif.bro.html#id-port_to_count]
  ## la cual nos pasa el puerto, que recordamos que va tambien con un string en el cual se nos dice que tipo es, a un
  ## valor numerico que si podremos restar sin problemas
  ## La funcion quedaria asi: (Nip-1)+(1/(dp1+k1))+(1/(dp2+k1))+(1/(dt+k2))
  Po1=port_to_count(po);
  ## (c1$id$orig_p); Como ejemplo
  Pd1=port_to_count(pd);
  Po2=port_to_count(po2);
  Pd2=port_to_count(pd2);
  ## local t1: double;
  ## local t2: double;
  ## t1 = time_to_double(c1$start_time);
  ## t2 = time_to_double(c2$start_time);

  dt=(|c1$start_time| - |c2$start_time|);

  ## print fmt("Tiempo paquete 1: %s", t1);
  ## print fmt("Tiempo paquete 2: %s", t2);
  ## print fmt("Diferencia de tiempo: %s", dt);
  if(Nip==2){
    resultado=1+(1/((Po1-Po2)+k1))+(1/((Pd1-Pd2)+k1))+(1/(dt+k2));
  } else if(Nip==1){
    resultado=(1/((Po1-Po2)+k1))+(1/((Pd1-Pd2)+k1))+(1/(dt+k2));
  } else if(Nip==0){
    resultado=1+(1/((Po1-Po2)+k1))+(1/((Pd1-Pd2)+k1))+(1/(dt+k2));
  }
 return resultado;

}

## funcion para la comparacion de los flujos, c1 el flujo que esta el primero en el vector de la tabla y c2 para el flujo que es candidato a ser emparejado
function calculo(c1: connection, c2: connection ):double {

  local cl = c1;
  local c = c2;

  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;
  local uid = c$uid;

  local informacion = " emparejado con ";

  local origl = cl$id$orig_h;
  local destl = cl$id$resp_h;
  local pol = cl$id$orig_p;
  local pdl = cl$id$resp_p;
  local uidl = cl$uid;

  if(cl$uid == c$uid){
    ## Si tienen el mismo uid pasamos del flujo, pues son el mismo
    return 0.0;

  } else {
    ## Si no tienen el mismo uid pasamos a comprobar

    umbral=emparejamiento(cl,c);

    if(umbral>k){

      ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
      collection[orig,po][|collection[orig,po]|] = c;
      informacion_coincidencia(cl, c);

      if( [orig,po] !in collection_added ){

        collection_added[orig,po]=vector(c);
      ##  print fmt("Aniadimos una nueva conexion al vector de coincidencias");

      } else {

        ## Si ya esta, lo añadimos
        collection_added[orig,po][|collection_added[orig,po]|] = c;
      ##  print fmt("Ya esta en vector de coincidencias y la aniadimos");

      }

      local rec: BROFLOWS::Info = [$orig1=origl, $po1=pol, $dest1=destl, $pd1=pdl, $uid1=uidl, $informacion=informacion, $orig2=orig, $po2=po, $dest2=dest, $pd2=pd, $uid2=uid];
      Log::write(BROFLOWS::LOG, rec);

      return 1.0;

    } else{

      return 0.0;

    }

  }

}


## Cada vez que entra un nuevo flujo compruebo que si esta en la tabla
## Este evento se lanza con cada nueva conexion de un flujo que no sea conocido, pero al borrarlo de memoria será desconocido aunque ya lo tengamos en la tabla
## Generated for every new connection. This event is raised with the first packet of a previously unknown connection. Bro uses a flow-based definition of “connection” here that includes not only TCP sessions but also UDP and ICMP flows.
event new_connection(c: connection){
  local orig = c$id$orig_h;
  local po = c$id$orig_p;

  if( [orig,po] !in collection ){

    ## Si no estan los valores clave del flujo lo creamos
    collection[orig,po]=vector(c);
    informacion_flujo(c);
    print fmt("Aniadimos una nueva conexion");
  } else {

    ## Si ya esta, lo añadimos
    collection[orig,po][|collection[orig,po]|] = c;
    informacion_flujo(c);
    print fmt("Ya esta y la aniadimos");
  }

}

## Generated when a connection’s internal state is about to be removed from memory. Bro generates this event reliably
## once for every connection when it is about to delete the internal state. As such, the event is well-suited for
## script-level cleanup that needs to be performed for every connection.
## This event is generated not only for TCP sessions but also for UDP and ICMP flows.
event connection_state_remove(c: connection){

  local orig = c$id$orig_h;
  local po = c$id$orig_p;

  local copia = collection[orig,po];
  local tam = |copia|;
  local primero = collection[orig,po][0];
  if([orig,po] in collection){
        collection[orig,po]=vector();
  }

  for(i in copia){
    if(tam==1){
      break;
    }else{
      if(tam>i){
        collection[orig,po][|collection[orig,po]|]=copia[i+1];
      }else{
        next;
      }
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

  local cl = collection[orig,po][0];

  local es = 0.0;

  if( [orig,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables TCP");
    } else {
      print fmt("No son emparejables TCP");
    }
  }
  if( [dest,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables TCP2");
    } else {
      print fmt("No son emparejables TCP2");
    }
  }
  if( [dest,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables TCP3");
    } else {
      print fmt("No son emparejables TCP3");
    }
  }
  if( [orig,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables TCP4");
    } else {
      print fmt("No son emparejables TCP4");
    }
  }

}

## Este evento se lanza cuando una conexion TCP finaliza de forma normal
event connection_finished(c: connection){

  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = collection[orig,po][0];

  local es = 0.0;

  if( [orig,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables TCP");
    } else {
      print fmt("No son emparejables TCP");
    }
  }
  if( [dest,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables TCP2");
    } else {
      print fmt("No son emparejables TCP2");
    }
  }
  if( [dest,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables TCP3");
    } else {
      print fmt("No son emparejables TCP3");
    }
  }
  if( [orig,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables TCP4");
    } else {
      print fmt("No son emparejables TCP4");
    }
  }

}


## Para protocolo UDP usaremos otro evento
## Son funciones muy costosas por lo que se deberia de evitar su uso a menos que sea necesario
## udp_request se lanza por cada flujo UDP del flujo que es enviado por el origen.
event udp_request(c: connection){

  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = collection[orig,po][0];

  local es = 0.0;

  if( [orig,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables UDP request");
    } else {
      print fmt("No son emparejables UDP request");
    }
  }
  if( [dest,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables UDP request2");
    } else {
      print fmt("No son emparejables UDP request2");
    }
  }
  if( [dest,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables UDP request3");
    } else {
      print fmt("No son emparejables UDP request3");
    }
  }
  if( [orig,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables UDP request4");
    } else {
      print fmt("No son emparejables UDP request4");
    }
  }

}

## udp_reply se lanza por cada flujo UDP del flujo que es devuelto por el destinatario del primer envio.
## cabecera del evento event udp_reply(u: connection)
event udp_reply(c: connection){

  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = collection[orig,po][0];

  local es = 0.0;

  if( [orig,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables UDP reply");
    } else {
      print fmt("No son emparejables UDP reply");
    }
  }
  if( [dest,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables UDP reply2");
    } else {
      print fmt("No son emparejables UDP reply2");
    }
  }
  if( [dest,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables UDP reply3");
    } else {
      print fmt("No son emparejables UDP reply3");
    }
  }
  if( [orig,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables UDP reply4");
    } else {
      print fmt("No son emparejables UDP reply4");
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

  local cl = collection[orig,po][0];

  local es = 0.0;

  if( [orig,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables ICMP request");
    } else {
      print fmt("No son emparejables ICMP request");
    }
  }
  if( [dest,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables ICMP request2");
    } else {
      print fmt("No son emparejables ICMP request2");
    }
  }
  if( [dest,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables ICMP request3");
    } else {
      print fmt("No son emparejables ICMP request3");
    }
  }
  if( [orig,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables ICMP request4");
    } else {
      print fmt("No son emparejables ICMP request4");
    }
  }
}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = collection[orig,po][0];

  local es = 0.0;

  if( [orig,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables ICMP reply");
    } else {
      print fmt("No son emparejables ICMP reply");
    }
  }
  if( [dest,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables ICMP reply2");
    } else {
      print fmt("No son emparejables ICMP reply2");
    }
  }
  if( [dest,po] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables ICMP reply3");
    } else {
      print fmt("No son emparejables ICMP reply3");
    }
  }
  if( [orig,pd] in collection ){
    es = calculo(cl,c);
    if (es==1) {
      print fmt("Si son emparejables ICMP reply4");
    } else {
      print fmt("No son emparejables ICMP reply4");
    }
  }

}
