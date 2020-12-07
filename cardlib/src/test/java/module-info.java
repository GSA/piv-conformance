open module gov.gsa.pivconformance.cardlib.test {
    exports gov.gsa.pivconformance.cardlib.test;
    requires gov.gsa.pivconformance.cardlib;
    requires java.smartcardio;
    requires org.slf4j;
    requires org.apache.commons.codec;
    requires org.apache.commons.cli;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires org.junit.jupiter.api;
    requires org.junit.jupiter.params;
}
