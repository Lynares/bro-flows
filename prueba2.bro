local myset = set(80/tcp, 81/tcp);
local mytable = table([10.0.0.1, 80/tcp]="s1", [10.0.0.2, 81/tcp]="s2");

for (p in myset)
    print p;

for ([i,j] in mytable) {
    if (mytable[i,j] == "done")
        break;
    if (mytable[i,j] == "skip")
        next;
## Poniendo las dos variables accedemos a lo que contiene la tabla
    print mytable[i,j];
    print i,j;
}
