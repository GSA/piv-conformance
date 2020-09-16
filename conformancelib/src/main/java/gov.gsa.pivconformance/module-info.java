open module gov.gsa.pivconformance.conformancelib {
    requires java.smartcardio;
    requires java.sql;
    requires org.slf4j;
    requires org.apache.ibatis;
    requires org.apache.commons.codec;
    requires org.apache.commons.cli;
    requires org.apache.commons.csv;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
    requires org.junit.jupiter;
    requires org.junit.jupiter.api;
    requires org.junit.jupiter.params;
    requires org.junit.jupiter.engine;
    requires org.junit.platform.engine;
    requires org.junit.platform.commons;
    requires org.junit.platform.launcher;
    requires ch.qos.logback.classic;
    requires ch.qos.logback.core;
    requires org.xerial.sqlite;
    requires gov.gsa.pivconformance.cardlib;
    exports gov.gsa.pivconformance.conformancelib.tests;
    exports gov.gsa.pivconformance.conformancelib.utilities;
    exports gov.gsa.pivconformance.conformancelib.tools;
    exports gov.gsa.pivconformance.conformancelib.configuration;
}

