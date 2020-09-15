open module gov.gsa.pivconformance.cardlib {
    requires java.smartcardio;
    requires java.sql;
    requires org.slf4j;
    requires org.apache.commons.codec;
    requires org.apache.commons.cli;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
    exports gov.gsa.pivconformance.cardlib.tlv;
    exports gov.gsa.pivconformance.cardlib.card.client;
    exports gov.gsa.pivconformance.cardlib.tools;
    exports gov.gsa.pivconformance.cardlib.utils;
}
