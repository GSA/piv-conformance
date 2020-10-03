module gov.gsa.pivconformance.conformancelib {
	exports gov.gsa.pivconformance.conformancelib.utilities;
	exports gov.gsa.pivconformance.conformancelib.tools.junitconsole;
	exports gov.gsa.pivconformance.conformancelib.tools;
	exports gov.gsa.pivconformance.conformancelib.tests;
	exports gov.gsa.pivconformance.conformancelib.configuration;
	exports gov.gsa.pivconformance.conformancelib.junitoptions;

	requires java.smartcardio;
	requires java.sql;
	requires org.slf4j;
	requires gov.gsa.pivconformance.cardlib;
	requires org.apache.ibatis;
	requires org.xerial.sqlite;
	requires org.junit.jupiter.api;
	requires org.junit.jupiter.params;
	requires org.junit.platform.engine;
	requires org.junit.platform.launcher;
	requires org.junit.platform.commons;
	requires org.bouncycastle.pkix;
	requires org.bouncycastle.provider;
	requires org.apache.commons.cli;
	requires org.apache.commons.csv;
	requires org.apache.commons.codec;
	requires ch.qos.logback.classic;
	requires ch.qos.logback.core;
	requires java.desktop;
	requires jdk.compiler;
	requires java.base;
	requires jdk.jlink;
	requires jdk.jdeps;
	requires java.scripting;
}
