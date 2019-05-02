
### ContainerDump Utility Class

To run the container dumper utility, run the ContainerDump class from the full jar:

`java -cp 85b-swing-gui-all.jar gov.gsa.conformancelib.pivconformancetools.ContainerDump -l -o `(whatever directory you'd like to dump into)
```
usage: ContainerDump <options>
 -a,--appPin <arg>     PIV application PIN
 -defaultGetResponse   Use default javax.scardio GET RESPONSE processing
 -h,--help             Print this help and exit
 -l,--login            Log in to PIV applet using PIV application PIN
                       prior to attempting dump
 -listOids             list container OIDs and exit
 -listReaders          list connected readers and exit
 -o,--outDir <arg>     Directory to receive containers
 -reader <arg>         Use the specified reader instead of the first one
                       with a card
```
If you specify a single container OID after all the options, it will dump just that container. Otherwise it runs
through the list and tries to dump all containers.
