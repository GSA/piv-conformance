module gov.gsa.pivconformance.conformancelib {
    exports gov.gsa.pivconformance.conformancelib.configuration;
    exports gov.gsa.pivconformance.conformancelib.junitoptions;
    exports gov.gsa.pivconformance.conformancelib.tests;
    exports gov.gsa.pivconformance.conformancelib.tools;
    exports gov.gsa.pivconformance.conformancelib.tools.junitconsole;
    exports gov.gsa.pivconformance.conformancelib.utilities;

    requires gov.gsa.pivconformance.cardlib;

    requires java.smartcardio;
    requires java.sql;
    requires org.slf4j;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires org.apache.commons.codec;
    requires org.apache.commons.csv;
    requires org.mybatis;
    requires org.junit.jupiter.api;
    requires org.junit.jupiter.params;
    requires org.junit.platform.commons;
    requires org.junit.platform.engine;
    requires org.junit.platform.launcher;
    requires org.junit.platform.runner;
    requires info.picocli;
    requires transitive ch.qos.logback.classic;
    requires transitive ch.qos.logback.core;
}
