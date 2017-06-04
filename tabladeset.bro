event bro_init(){
  local t: table[count] of vector of count;
  local j = 0;
  local se: count;
  local se2: set[double];

  while(j < 10){
    t[j]=vector(j,j+1);
    ++j;
  }
  j=0;
  ##while(j <10){
  ##  t[|t|]=vector(11); ++j;
  ##}
  se=3;
  t[1]=vector(se,3,3,3,3,3,3,3,3,3);
  for(s in t){
    print |t[s]|;
     local i= |t[s]|;## solo saca el tamaño de lo que hay guardado, 1 en este caso
     while(i>0){
      t[|t[s]|]=vector(1,1,1); --i;
     }
      print |t[s]|;
    print t[s];
  }
}
