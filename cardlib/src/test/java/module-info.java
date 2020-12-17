open module gov.gsa.pivconformance.cardlib.test {
    exports gov.gsa.pivconformance.cardlib.test;
    requires transitive gov.gsa.pivconformance.cardlib;
    requires transitive java.smartcardio;
    requires transitive org.slf4j;
    requires transitive org.apache.commons.codec;
    requires transitive org.apache.commons.cli;
    requires transitive org.bouncycastle.provider;
    requires transitive org.bouncycastle.pkix;
    requires transitive org.junit.jupiter.api;
    requires transitive org.junit.jupiter.params;
}
