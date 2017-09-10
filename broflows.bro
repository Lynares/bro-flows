#Autor: Álvaro Maximino Linares Herrera
#Descripción: Script de Bro para la identificación de tráfico mediante emparejamiento de flujos

module BROFLOWS;

## Tablas para guardar los flujos
global activos: table[addr, port] of vector of connection;
global emparejados: table[addr, port] of vector of connection;

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

## Evento que se lanza cuando se inicia Bro, para crear registro
event bro_init(){

  Log::create_stream(BROFLOWS::LOG, [$columns=Info, $ev=log_flow]);

}

## Variable en la que se guarda el resultado de aplicar la ecuacion
global k: double;

## Definimos el umbral, de manera global para hacer las comparaciones
global umbral=1;

## Variables para el calculo de la ecuacion
global k1 = 3;
global k2 = 100;

## Creo funcion auxiliar para ver la informacion del flujos que son coincidentes
function informacion_coincidencia(c: connection, p: connection){
    print fmt("Informacion del primer flujo  IPo: %s , Po: %s , IPd: %s , Pd: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    print fmt("Informacion del flujo coincidente  IPo: %s , Po: %s , IPd: %s , Pd: %s ", p$id$orig_h, p$id$orig_p, p$id$resp_h, p$id$resp_p);
}

## funcion para la comparacion de los flujos, c1 el flujo que esta el primero en el vector de la tabla y c2 para el flujo que es candidato a ser emparejado
function emparejamiento(c1: connection, c2: connection ):double {

  ## Sacamos variables de los flujos
  local orig = c1$id$orig_h;
  local dest = c1$id$resp_h;
  local po = c1$id$orig_p;
  local pd = c1$id$resp_p;

  local orig2 = c2$id$orig_h;
  local dest2 = c2$id$resp_h;
  local po2 = c2$id$orig_p;
  local pd2 = c2$id$resp_p;

  ## Variable para el numero de IPs coincidentes
  local Nip: double;

  ## calculamos cuantas IPs coinciden
  if((orig==orig2) && (dest==dest2)){
    Nip=2;
  } else if((orig==dest2) && (dest==orig2)){
    Nip=2;
  }else if((orig==dest2) || (dest==orig2) || (orig==orig2) || (dest==dest2)){
    Nip=1;
  } else {
    Nip=0;
  }

  local Po1: count; ## Puerto origen del primer flujo
  local Po2: count; ## Puerto origen del segundo flujo
  local Pd1: count; ## Puerto destino del primer flujo
  local Pd2: count; ## Puerto destino del segundo flujo
  local dt: double; ## Variable para la diferencia de los tiempos
  local resultado = 0.0; ## Lo inciamos a 0

  print c1$uid;
  print c2$uid;

  print fmt("Numero de IP coincidentes: %s", Nip);

  ## Para dp1 y dp2 que son 1-norm usamos la "Manhattan norm" que dice lo siguiente: SAD(x1,x2) = sumatoria(x1i - x2i)
  ## k1 y k2 son dos variables que nosotros le ponemos de forma manual, en este caso las pondremos como locales con 1 y 10 respectivamente
  ## dt es la diferencia de tiempo entre los time stamp de los primeros flujos de los flujos
  ## el tipo time se supone que es como un double, por lo tanto podremos restarlos sin problemas
  ## para la comparacion de puertos primero tendremos que hacer uso de la funcion  port_to_count [https://www.bro.org/sphinx/scripts/base/bif/bro.bif.bro.html#id-port_to_count]
  ## la cual nos pasa el puerto, que recordamos que va tambien con un string en el cual se nos dice que tipo es, a un
  ## valor numerico que si podremos restar sin problemas
  ## La funcion quedaria asi: (Nip-1)+(1/(dp1+k1))+(1/(dp2+k1))+(1/(dt+k2))
  Po1=port_to_count(po);
  Pd1=port_to_count(pd);
  Po2=port_to_count(po2);
  Pd2=port_to_count(pd2);

  ## Calculamos la diferencia de tiempo
  dt=(|c1$start_time| - |c2$start_time|);

  ## Aplicamos la ecuacion
  if(Nip==2){
    resultado=1+(1/((Po1-Po2)+k1))+(1/((Pd1-Pd2)+k1))+(1/(dt+k2));
  } else if(Nip==1){
    resultado=(1/((Po1-Po2)+k1))+(1/((Pd1-Pd2)+k1))+(1/(dt+k2));
  } else if(Nip==0){
    resultado=1+(1/((Po1-Po2)+k1))+(1/((Pd1-Pd2)+k1))+(1/(dt+k2));
  }
 return resultado;

}

## Funcion en la que se detecta si dos flujos pasan a calcular el emparejamiento
function calculo(c1: connection, c2: connection ){

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

  if(uidl == uid){
    ## Si tienen el mismo uid pasamos del flujo, pues son el mismo
    break;

  } else {
    ## Si no tienen el mismo uid pasamos a comprobar

    k=emparejamiento(cl,c);

    if(k>umbral){

      ## Si el umbral calculado es mayor que el umbral de comparacion lo añadimos
      activos[orig,po][|activos[orig,po]|] = c;
      informacion_coincidencia(cl, c);

      if( [orig,po] !in emparejados ){
        emparejados[orig,po]=vector(c);
      } else {
        emparejados[orig,po][|emparejados[orig,po]|] = c;
      }

      local rec: BROFLOWS::Info = [$orig1=origl, $po1=pol, $dest1=destl, $pd1=pdl, $uid1=uidl, $informacion=informacion, $orig2=orig, $po2=po, $dest2=dest, $pd2=pd, $uid2=uid];
      Log::write(BROFLOWS::LOG, rec);

    } else {

      break;

    }

  }

}

## Este evento se lanza con cada nueva conexion de un flujo
event new_connection(c: connection){
  local orig = c$id$orig_h;
  local po = c$id$orig_p;

  if( [orig,po] !in activos ){
    ## Si no estan los valores clave del flujo lo creamos
    activos[orig,po]=vector(c);

  } else {
    ## Si ya esta, lo añadimos
    activos[orig,po][|activos[orig,po]|] = c;

  }

}

## Este evento se lanza cuando se detecta un flujo de cualquier tipo que va a ser borrado de memoria
event connection_state_remove(c: connection){

  local orig = c$id$orig_h;
  local po = c$id$orig_p;

  local copia = activos[orig,po];
  local tam = |copia|;
  local primero = activos[orig,po][0];

  if([orig,po] in activos){
        activos[orig,po]=vector();
  }

  for(i in copia){
    if(tam==1){
      break;
    }else{
      if(primero$uid!=copia[i]$uid){
        activos[orig,po][|activos[orig,po]|]=copia[i];
      }else{
        next;
      }
    }
  }

}

## Solo sirve para conexiones TCP, se genera cuando ve un SYN-ACK que responde al handshake de un TCP
event connection_established(c: connection){

  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = activos[orig,po][0];

  if( [orig,po] in activos ){
    calculo(cl,c);
  }else if( [dest,pd] in activos ){
    calculo(cl,c);
  }else if( [dest,po] in activos ){
    calculo(cl,c);
  }else if( [orig,pd] in activos ){
    calculo(cl,c);
  }

}

## Este evento se lanza cuando una conexion TCP finaliza de forma normal
event connection_finished(c: connection){

  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = activos[orig,po][0];

    if( [orig,po] in activos ){
      calculo(cl,c);
    }else if( [dest,pd] in activos ){
      calculo(cl,c);
    }else if( [dest,po] in activos ){
      calculo(cl,c);
    }else if( [orig,pd] in activos ){
      calculo(cl,c);
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

  local cl = activos[orig,po][0];

    if( [orig,po] in activos ){
      calculo(cl,c);
    }
    if( [dest,pd] in activos ){
      calculo(cl,c);
    }
    if( [dest,po] in activos ){
      calculo(cl,c);
    }
    if( [orig,pd] in activos ){
      calculo(cl,c);
    }
}

## udp_reply se lanza por cada flujo UDP del flujo que es devuelto por el destinatario del primer envio.
## cabecera del evento event udp_reply(u: connection)
event udp_reply(c: connection){

  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = activos[orig,po][0];

    if( [orig,po] in activos ){
      calculo(cl,c);
    }
    if( [dest,pd] in activos ){
      calculo(cl,c);
    }
    if( [dest,po] in activos ){
      calculo(cl,c);
    }
    if( [orig,pd] in activos ){
      calculo(cl,c);
    }
}

## Eventos para los flujos tipo ICMP
event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = activos[orig,po][0];

    if( [orig,po] in activos ){
      calculo(cl,c);
    }
    if( [dest,pd] in activos ){
      calculo(cl,c);
    }
    if( [dest,po] in activos ){
      calculo(cl,c);
    }
    if( [orig,pd] in activos ){
      calculo(cl,c);
    }
}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string){
  local orig = c$id$orig_h;
  local dest = c$id$resp_h;
  local po = c$id$orig_p;
  local pd = c$id$resp_p;

  local cl = activos[orig,po][0];

    if( [orig,po] in activos ){
      calculo(cl,c);
    }
    if( [dest,pd] in activos ){
      calculo(cl,c);
    }
    if( [dest,po] in activos ){
      calculo(cl,c);
    }
    if( [orig,pd] in activos ){
      calculo(cl,c);
    }
}
