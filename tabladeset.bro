event bro_init(){
  local t: table[count] of vector of count;
  local v: vector of int;
  local j = 0;


  while(j < 10){
    t[j]=vector(j,j+1);
    ++j;
  }
  j=0;

  print fmt("Pruebas: ");

  while(j<10){
    v[j]=j;
    ++j;
  }

## IDEA USAR RESIZE PARA EL VECTOR

  j=0;
  print |v|;
  for (s in v){
    print v[s];
    print fmt("Vector");
  }

  for(s in t){
    ## local v = vector(1,1,1);
    ## print |t[s]|;
    local i= |t[s]|;## solo saca el tamaño de lo que hay guardado, 1 en este caso
    local e: vector of count;
  ##  e=v[s];
    while(i>0){
      t[s]=vector(1);
     --i;
    }
    print |t[s]|;
    print t[s];
  }

}
