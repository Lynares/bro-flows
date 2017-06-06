
## PRIMERA APROXIMACION con un solo set, simplemente almaceno los flujos en un set (PARA FLUJOS ACTIVOS) y cuando mueren los elimino
## El contenido del set si se ve alterado, pero el tamaño no, pues no es memoria dinamica
## Cambio de vector a set por las comparaciones, el tipo vector en bro no las soporta
global conex: set[connection];

## Variable global para conocer el tamaño del set
global tams=0;
## Variable global para conocer el numero de flujos que hay en el archivo pcap
global tam=0;
## Variable para ver los flujos que eliminamos y comprobar si son los mismos que los que hemos añadido
global elimi=0;

## SEGUNDA APROXIMACION... FICHERO aprox2.bro CREO SET COMPLEMENTARIO PARA ALMACENAR LOS QUE YA TENGO ALMACENADOS EN ALGUN MOMENTO

## set para almacenar los flujos que coinciden con los que ya tenemos en conex... (PARA FLUJOS EMPAREJADOS)
## Incluidos TCP, UDP e ICMP
global matchs: set[connection]; ## Tal vez una table con indice connection para saber con cual esta emparejado (?)
## variable global para controlar su crecimiento
## global tamm=0;
## variable global para ver la cantidad de matchs distintos que hacemos
## global nmatchs=0;

## TERCERA APROXIMACION... CREO TABLE PARA ALMACENAR EN EL INDICE LA INFORMACION DEL PRIMER SET Y METERLE LA INFORMACION DEL SEGUNDO CUANDO CASEN.
global empa: table[connection] of connection;

## CUARTA APROXIMACION... Crear una funcion en la cual se analice mediante la funcion requerida si los flujos se pueden emparejar o no...
## El umbral: "Comparar la constante 'k', que es el umbral que fijaré con el resultado que devuelve la función,
## si es más grande el resultado que 'k' se puede decir que los dos flujos son iguales, si es más pequeño podemos decir que los dos flujos no son iguales"
## resultado del umbral
global umbral: double;

## Definimos el umbral, de manera global para hacer las comparaciones
global k=0.01;


## Creo funcion auxiliar para ver la informacion del flujonuevo que se añade, no de todos los flujos todo el rato
function informacion_paquete(c: connection){
    print fmt("Informacion del flujonuevo IPo: %s , Po: %s , IPd: %s , Pd: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
}

## Esta funcion es solo para depuracion, al final sera borrada
## Creo funcion auxiliar para ver la informacion del flujoque se coincide
function informacion_coincidencia(c: connection, p: connection){
    print fmt("Informacion del primer flujo IPo: %s , Po: %s , IPd: %s , Pd: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    print fmt("Informacion del flujocoincidente  IPo: %s , Po: %s , IPd: %s , Pd: %s ", p$id$orig_h, p$id$orig_p, p$id$resp_h, p$id$resp_p);
}


## funcion para la comparacion de los flujos, c1 el flujo que esta en el set conex y c2 para el flujo que es candidato a guardarse en matchs
function emparejamiento(c1: connection, c2: connection ):double {
  local resultado = 0.0; ## Lo ponemos a 0
  if(c1$uid==c2$uid){
    return resultado;
  } else {
  local Nip=1; ## Variable para saber cuantas conexiones tenemos
  local Po1: count; ## Puerto origen del primer flujo
  local Po2: count; ## Puerto origen del segundo flujo
  local Pd1: count; ## Puerto destino del primer flujo
  local Pd2: count; ## Puerto destino del segundo flujo
  local k1 = 1;  ## Variable fija
  local k2 = 10; ## Variable fija
  local dt: double; ## Variable para la diferencia de los tiempos


  ## for (s in conex){

  ##  if(s$id$orig_h == c2$id$orig_h){
  ##    if(s$id$resp_h == c2$id$resp_h){
  ##      if(s$id$orig_p == c2$id$orig_p){
  ##        if(s$id$resp_p == c2$id$resp_p){
  ##          Nip=Nip+1;
  ##          break;
  ##        }
  ##      }
  ##    }
  ##  }
  ## }
## Este bucle lo puedo hacer sin ningun problema, pues en los eventos todavia no se ha dicho que se guarde en el set
  for (i in empa){
    if((i$id$orig_h == c2$id$orig_h) && (i$id$resp_h == c2$id$resp_h) && (i$id$orig_p == c2$id$orig_p) && (i$id$resp_p == c2$id$resp_p)){
            Nip=Nip+1;

    }

  }
  print fmt("Numero de Nip en table: %d", Nip);
  informacion_coincidencia(c1,c2);
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
  dt=(|c1$start_time| - |c2$start_time|);
  resultado=(Nip-1)+(1/((Po1-Po2)+k1))+(1/((Pd1-Pd2)+k1))+(1/(dt+k2));
  return resultado;
}


}

## Cada vez que entra un nuevo flujolo comparo con lo que ya tengo en el set
## Este evento se lanza con cada nueva conexion de un flujo que no sea conocido
## Generated for every new connection. This event is raised with the first packet of a previously unknown connection. Bro uses a flow-based definition of “connection” here that includes not only TCP sessions but also UDP and ICMP flows.
event new_connection(c: connection){

## Si el set esta vacio meto el primer paquete
   if(tam==0){
    add conex[c];
   }
## Sumamos uno al tamaño del set
    tam=tam+1;

## Variable booleana para controlar el acceso al set
    local met = F;

## for que va recorriendo el set y haciendo comparaciones
    for(s in conex){
## Copiamos en la variable local para comparar con todo lo que hay en el set
      if(s$id$orig_h != c$id$orig_h){
        if(s$id$resp_h != c$id$resp_h){
          if(s$id$orig_p != c$id$orig_p){
            if(s$id$resp_p != c$id$resp_p){
## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
              met=T;
             }
           }
         }
       }

     }
## Con la variable booleana controlamos el crecimiento del set
     if (met==T){
      add conex[c];
      tams=tams+1;
      ## print fmt("Meto un flujonuevo por la conexion de origen distinta");
     }
     met=F;
    ## print fmt("Numero de flujos al momento: %d", tam);
    ## print fmt("Tamanio del set: %d", tams);
    ## informacion_paquete(c);

}

## Cuando la conexion va a ser borrada la eliminamos del set y en caso de tener otra conexion en el matchs la añadimos
## se obtienen los mismos flujos añadidos que eliminados, por lo tanto hay que controlar cuando lo añadimos y cuando lo eliminamos
## Sirve para TCP, UDP e ICMP
## Generated when a connection’s internal state is about to be removed from memory. Bro generates this event reliably
## once for every connection when it is about to delete the internal state. As such, the event is well-suited for
## script-level cleanup that needs to be performed for every connection.
## This event is generated not only for TCP sessions but also for UDP and ICMP flows.
event connection_state_remove(c: connection){

## Creo un connection local para poder pasarlo de matchs a conex
    local cl: connection;
## Variable booleana para controlar el acceso al set
    local met = F;

## for que va recorriendo el set y haciendo comparaciones
    for(s in matchs){
      if((s$id$orig_h == c$id$orig_h) && (s$id$resp_h == c$id$resp_h) && (s$id$orig_p == c$id$orig_p) && (s$id$resp_p == c$id$resp_p)){
## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
              met=T;
## Al existir otro flujo lo copiamos en cl
              cl=s;
              break;
      }
    }

    ## Aqui si tenemos otro flujo igual al que vamos a eliminar lo metemos en conex para que ocupe el lugar del que vamos a borrar
    ## Con la variable booleana controlamos el decrecimiento del set
    if (met==T){
      delete conex[c];
      add conex[cl];
      delete matchs[cl];
    ## decrece la variable de matchs
      ## nmatchs= nmatchs-1;
    ## Controlamos que el tamaño que manejamos por pantalla del set no sea menor que 0 para que no de valores basura
    } else {
      delete conex[c];
    }
    elimi=elimi+1;
    if(tams==0){
      tams=0;
    }
    if(tams>0){
      tams=tams-1;
    }

    met=F;
    ##  print fmt("Tamanio del set: %d", tams);
    ##  informacion_paquete(c);

}

## Cuando la conexion se establece vemos si hay flujos que emparejar y los metemos en matchs
## Solo sirve para conexiones TCP, se genera cuando ve un SYN-ACK que responde al handshake de un TCP
event connection_established(c: connection){

  ## Creo un connection local para poder hacer comparaciones con el set y poder descartar flujos que no coinciden
    local cl: connection;

  ## Variable booleana para controlar el acceso al set
    local met = F;

  ## for que va recorriendo el set y haciendo comparaciones
    for(s in conex){

      if((s$id$orig_h == c$id$orig_h) && (s$id$resp_h == c$id$resp_h) && (s$id$orig_p == c$id$orig_p) && (s$id$resp_p == c$id$resp_p)){
        ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
        met=T;
        cl=s;
        ## informacion_coincidencia(c, cl);
        umbral=emparejamiento(cl, c);
        if(umbral>k){
          ## Mostrar en el mensaje TCP es para control
          print fmt("Si son emparejables TCP");
          ## Metemos la informacion en la tabla
          empa[cl]=c;
          if (met==T){
            add matchs[c];
            ## Sumamos uno al tamaño del set de matchs
            ## tamm= tamm+1;
            ## print fmt("Encontrado un flujoTCP que coincide con otro de las conexiones que ya tenemos");
            ## nmatchs= nmatchs+1;
            ## print fmt("De la tabla en %s con %s con %s con %s añadimos: %s con %s con %s con %s", cl$id$orig_h, cl$id$orig_p, cl$id$resp_h, cl$id$resp_p, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
          }
          met=F;
          }else{
            print fmt("No son emparejables TCP");
          }
          ## print fmt("De la tabla en %s con %s con %s con %s añadimos: %s con %s con %s con %s", cl$id$orig_h, cl$id$orig_p, cl$id$resp_h, cl$id$resp_p, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
          ## print fmt("Metido en tabla");
          break;

    }

  }
  ## Con la variable booleana controlamos el crecimiento del set

  ## print fmt("Tamanio del set matchs: %d", tamm);
  ## informacion_paquete(c);

}

## Para protocolo UDP usaremos otro evento
## Son funciones muy costosas por lo que se deberia de evitar su uso a menos que sea necesario
## udp_request se lanza por cada flujoUDP del flujo que es enviado por el origen.
event udp_request(u: connection){


  ## Creo un connection local para poder hacer comparaciones con el set y poder descartar flujos que no coinciden
    local ul: connection;
  ## Variable booleana para controlar el acceso al set
    local met = F;

  ## for que va recorriendo el set y haciendo comparaciones
     for(s in conex){

       if((s$id$orig_h == u$id$orig_h) && (s$id$resp_h == u$id$resp_h) && (s$id$orig_p == u$id$orig_p) && (s$id$resp_p == u$id$resp_p)){
               ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
               met=T;
               ul=s;
               ## Cambiar para que no se vea toda la informacion del paquete, solo las IP's y los puertos
               ## informacion_coincidencia(u, ul);
               ## Metemos la informacion aquí pues los datos se falsearán si los metemos en la tabla después
               umbral=emparejamiento(ul, u);
               if(umbral>k){
               ## Mostrar en el mensaje UDP es para control
                print fmt("Si son emparejables UDP request");
                empa[ul]=u;
               }else{
                 print fmt("No son emparejables UDP request");
               }
                ## print fmt("De la tabla en %s con %s con %s con %s añadimos: %s con %s con %s con %s", ul$id$orig_h, ul$id$orig_p, ul$id$resp_h, ul$id$resp_p, u$id$orig_h, u$id$orig_p, u$id$resp_h, u$id$resp_p);
                ## print fmt("Metido en tabla");
                break;

         }

       }
      ## Con la variable booleana controlamos el crecimiento del set
       if (met==T){
         add matchs[u];
         ## tamm = tamm+1;
         ## print fmt("Encontrado un flujoUDP request que coincide con otro de las conexiones que ya tenemos");
         ## nmatchs= nmatchs+1;
       }
       met=F;
       ## print fmt("Tamanio del set matchs: %d", tamm);
       ## informacion_paquete(u);

}

## udp_reply se lanza por cada flujoUDP del flujo que es devuelto por el destinatario del primer envio.
## cabecera del evento event udp_reply(u: connection)
event udp_reply(u: connection){

  ## Creo un connection local para poder hacer comparaciones con el set y poder descartar flujos que no coinciden
    local ul: connection;
    ## Variable booleana para controlar el acceso al set
    local met = F;

  ## for que va recorriendo el set y haciendo comparaciones
     for(s in conex){

       if((s$id$orig_h == u$id$orig_h) && (s$id$resp_h == u$id$resp_h) && (s$id$orig_p == u$id$orig_p) && (s$id$resp_p == u$id$resp_p)){
               ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
               met=T;
               ul=s;
               ## Cambiar para que no se vea toda la informacion del paquete, solo las IP's y los puertos
               ## informacion_coincidencia(u, ul);
               ## Metemos la informacion aquí pues los datos se falsearán si los metemos en la tabla después
               umbral=emparejamiento(ul, u);
               if(umbral>k){
               ## Mostrar en el mensaje UDP es para control
                print fmt("Si son emparejables UDP request");
                empa[ul]=u;
               }else{
                 print fmt("No son emparejables UDP request");
               }
                ## print fmt("De la tabla en %s con %s con %s con %s añadimos: %s con %s con %s con %s", ul$id$orig_h, ul$id$orig_p, ul$id$resp_h, ul$id$resp_p, u$id$orig_h, u$id$orig_p, u$id$resp_h, u$id$resp_p);
                ## print fmt("Metido en tabla");
                break;

         }

       }
       ## Con la variable booleana controlamos el crecimiento del set
       if (met==T){
         add matchs[u];
         ## tamm=tamm+1;
         ## print fmt("Encontrado un flujoUDP request que coincide con otro de las conexiones que ya tenemos");
         ## nmatchs= nmatchs+1;
       }
       met=F;
       ## print fmt("Tamanio del set matchs: %d", tamm);
       ## informacion_paquete(u);

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

     ## Creo un connection local para poder hacer comparaciones con el set y poder descartar flujos que no coinciden
     local cl: connection;
     ## Variable booleana para controlar el acceso al set
     local met = F;

     ## for que va recorriendo el set y haciendo comparaciones
     for(s in conex){

       if((s$id$orig_h == c$id$orig_h) && (s$id$resp_h == c$id$resp_h) && (s$id$orig_p == c$id$orig_p) && (s$id$resp_p == c$id$resp_p)){
               ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
               met=T;
               cl=s;
               ## Cambiar para que no se vea toda la informacion del paquete, solo las IP's y los puertos
               ## informacion_coincidencia(c, cl);
               ## Metemos la informacion aquí pues los datos se falsearán si los metemos en la tabla después
               umbral=emparejamiento(cl, c);
               if(umbral>k){
                 ## Mostrar en el mensaje ICMP es para control
                 print fmt("Si son emparejables ICMP request");
                 empa[cl]=c;
               }else{
                 print fmt("No son emparejables ICMP request");
               }
               ## print fmt("De la tabla en %s con %s con %s con %s añadimos: %s con %s con %s con %s", cl$id$orig_h, cl$id$orig_p, cl$id$resp_h, cl$id$resp_p, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
               ## print fmt("Metido en tabla");
               break;

       }

     }
     ## Con la variable booleana controlamos el crecimiento del set
     if (met==T){
       add matchs[c];
       ## tamm= tamm+1;
       ## print fmt("Encontrado un flujoICMP request que coincide con otro de las conexiones que ya tenemos");
       ## nmatchs= nmatchs+1;
     }
     met=F;
     ## print fmt("Tamanio del set matchs: %d", tamm);
     ## informacion_paquete(c);

}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){

     ## Creo un connection local para poder hacer comparaciones con el set y poder descartar flujos que no coinciden
     local cl: connection;
     ## Variable booleana para controlar el acceso al set
     local met = F;

     ## for que va recorriendo el set y haciendo comparaciones
     for(s in conex){

       if((s$id$orig_h == c$id$orig_h) && (s$id$resp_h == c$id$resp_h) && (s$id$orig_p == c$id$orig_p) && (s$id$resp_p == c$id$resp_p)){
               ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
               met=T;
               cl=s;
               ## Cambiar para que no se vea toda la informacion del paquete, solo las IP's y los puertos
               ## informacion_coincidencia(c, cl);
               ## Metemos la informacion aquí pues los datos se falsearán si los metemos en la tabla después
               umbral=emparejamiento(cl, c);
               if(umbral>k){
                 ## Mostrar en el mensaje ICMP es para control
                 print fmt("Si son emparejables ICMP request");
                 empa[cl]=c;
               }else{
                 print fmt("No son emparejables ICMP request");
               }
               ## print fmt("De la tabla en %s con %s con %s con %s añadimos: %s con %s con %s con %s", cl$id$orig_h, cl$id$orig_p, cl$id$resp_h, cl$id$resp_p, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
               ## print fmt("Metido en tabla");
               break;

       }

     }
     ## Con la variable booleana controlamos el crecimiento del set
     if (met==T){
       add matchs[c];
       ## tamm= tamm+1;
       ## print fmt("Encontrado un flujoICMP request que coincide con otro de las conexiones que ya tenemos");
       ## nmatchs= nmatchs+1;
     }
     met=F;
     ## print fmt("Tamanio del set matchs: %d", tamm);
     ## informacion_paquete(c);

}


## Evento que se lanza cuando se inicia BRO.
event bro_init(){
  print fmt("Hora de inicio: %s", current_time());
}
## Evento que se genera cuando BRO va a tenerminar, menos si se realiza mediante una llamada a la funcion exit (ver documentacion)
event bro_done(){
  ## print fmt("El numero total de coincidencias es: %d", nmatchs);
  ## print fmt("El tamaño maximo del set de coincidencias es: %d", |matchs|);
  ## Mostramos lo que tenemos en la tabla
  for(s in empa){
    ## print fmt("Tamaño de la fila de la tabla: %d", |empa[s]|);
    print fmt("Tenemos: %s en %s a %s en %s", empa[s]$id$orig_h, empa[s]$id$orig_p, empa[s]$id$resp_h, empa[s]$id$resp_p);
    print fmt(" de %s en %s a %s en %s", s$id$orig_h, s$id$orig_p, s$id$resp_h, s$id$resp_p);
  }
  print fmt("Total de flujos: %d", tam);
  print fmt("Hora de finalizacion: %s", current_time());
}
