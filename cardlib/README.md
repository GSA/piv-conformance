
### ContainerDump Utility Class

From the repository root, run the container dumper utility from the Java 17 GUI Shadow JAR:

`java -cp tools/85b-swing-gui/build/libs/gov.gsa.pivconformance.gui-1.1.0-rc1-shadow.jar gov.gsa.pivconformance.conformancelib.tools.ContainerDump -h`
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
