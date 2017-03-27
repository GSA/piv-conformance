open module gov.gsa.pivconformance {
    requires java.smartcardio;
    requires org.slf4j;
    requires org.apache.commons.codec;
    requires commons.cli;
    requires bcpkix.jdk15on;
    requires bcprov.jdk15on;
    exports gov.gsa.pivconformance.tlv;
    exports gov.gsa.pivconformance.card.client;
    exports gov.gsa.pivconformance.tools;
    exports gov.gsa.pivconformance.utils;
}
