open module gov.gsa.pivconformancetools {
    requires java.smartcardio;
    requires java.sql;
    requires org.slf4j;
    requires org.apache.commons.codec;
    requires commons.cli;
    requires bcpkix.jdk15on;
    requires bcprov.jdk15on;
    requires gov.gsa.pivconformance;
    //requires gov.gsa.pivconformance.card.client;
    requires gov.gsa.conformancelib;
    requires org.junit.platform.commons;
    requires org.junit.platform.engine;
    requires org.junit.platform.launcher;
    //requires org.junit.platform.
    requires ch.qos.logback.classic;
    requires ch.qos.logback.core;
}
