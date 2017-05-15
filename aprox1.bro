
## Incluyo librerias como en el ejemplo del evento de paquetes eliminados de la documentacion
## @load base/protocols/conn
## @load base/protocols/http
##global conexiones: vector of connection;

## Primera aproximacion con un solo set, simplemente almaceno los paquetes en un set y cuando mueren los elimino
## Cambio de vector a set por las comparaciones, el tipo vector en bro no las soporta
global conex: set[connection];
## Variable global para conocer el tamaño del set
global tams=0;
## Variable global para conocer el numero de paquetes que hay en el archivo pcap
global tam=0;
## Variable para ver los paquetes que eliminamos y comprobar si son los mismos que los que hemos añadido
global elimi=0;

## Segunda aproximacion... FICHERO aprox2.bro CREO SET COMPLEMENTARIO PARA ALMACENAR LOS QUE YA TENGO ALMACENADOS EN ALGUN MOMENTO


## Creo funcion auxiliar para ver la informacion del paquete nuevo que se añade, no de todos los paquetes todo el rato
function informacion_paquete(c: connection){
    print fmt("Informacion del paquete nuevo IPo: %s , Po: %s , IPd: %s , Pd: %s ", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
}

## Cada vez que entra un nuevo paquete lo comparo con lo que ya tengo en el set
event new_connection(c: connection){

## Sumamos uno para poder ver el numero de paquetes totales que tenemos
  tam=tam+1;
## Si el set esta vacio meto el primer paquete
  if(|conex|==0){
   add conex[c];
  }
## Creo un connection local para poder hacer comparaciones con el set y poder descartar paquetes
  local cd: connection;
## Variable booleana para controlar el acceso al set
  local met = F;
## Si el set está vacio le permitimos escritura
  if(|conex|==0){
    add conex[c];
    tams=tams+1;
  }


## for que va recorriendo el set y haciendo comparaciones
  for(s in conex){
    ## Copiamos en la variable local para comparar con todo lo que hay en el set
    cd=s;
    if(cd$id$orig_h != c$id$orig_h){
      if(cd$id$resp_h != c$id$resp_h){
        if(cd$id$orig_p != c$id$orig_p){
          if(cd$id$resp_p != c$id$resp_p){
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
    print fmt("Meto un paquete nuevo por la conexion de origen distinta");
  }
  met=F;
  print fmt("Numero de paquetes al momento: %d", tam);
  print fmt("Tamanio del set: %d", tams);
  informacion_paquete(c);
}

## cuando la conexion es borrada
## se obtienen los mismos paquetes añadidos que eliminados, por lo tanto hay que controlar cuando lo añadimos y cuando lo eliminamos
event connection_state_remove(c: connection){

##  print fmt("Conexion eliminada : %s", c$id$orig_h);
##  elimi=elimi+1;
##  print fmt("Numero de paquetes eliminados: %d", elimi);


  ## Creo un connection local para poder hacer comparaciones con el set y poder descartar paquetes
    local cd: connection;
  ## Variable booleana para controlar el acceso al set
    local met = F;

  ## for que va recorriendo el set y haciendo comparaciones
    for(s in conex){
      ## Copiamos en la variable local para comparar con todo lo que hay en el set
      cd=s;
      if(cd$id$orig_h == c$id$orig_h){
        if(cd$id$resp_h == c$id$resp_h){
          if(cd$id$orig_p == c$id$orig_p){
            if(cd$id$resp_p == c$id$resp_p){
              ## Si se dan todas las condiciones la variable booleana de control de acceso al set se cambia a true, T
              met=T;
            }
          }
        }
      }

    }
    ## Con la variable booleana controlamos el decrecimiento del set
    if (met==T){
      delete conex[c];
      elimi=elimi+1;
    ## Controlamos que el tamaño que manejamos por pantalla del set no sea menor que 0 para que no de valores basura
      if(tams==0){
        tams=0;
      }
      if(tams>0){
        tams=tams-1;
      }
    ## Mostramos por pantalla un mensaje de eliminacion de un paquete si procede
      print fmt("Elimino un paquete por la conexion de origen distinta");
    }
    met=F;
    print fmt("Numero de paquetes al momento: %d", tam);
    print fmt("Tamanio del set: %d", tams);
    informacion_paquete(c);
    ## print fmt("Numero de paquetes en set: %d", |conex|);
}

## Evento que se lanza cuando BRO termina
event bro_done(){
  print fmt("Numero de paquetes en set: %d", |conex|);
}
