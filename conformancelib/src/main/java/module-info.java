open module gov.gsa.conformancelib {
    requires java.smartcardio;
    requires java.sql;
    requires org.slf4j;
    requires org.apache.commons.codec;
    requires commons.cli;
    requires bcpkix.jdk15on;
    requires bcprov.jdk15on;
    requires gov.gsa.pivconformance;
    requires org.junit.jupiter.api;
    requires junit;
    exports gov.gsa.conformancelib.tests;
    exports gov.gsa.conformancelib.configuration;
}

