module gov.gsa.pivconformance.gui {
	exports gov.gsa.pivconformance.gui;

	requires ch.qos.logback.classic;
	requires ch.qos.logback.core;
	requires gov.gsa.pivconformance.cardlib;
	requires gov.gsa.pivconformance.conformancelib;
	requires java.desktop;
	requires java.smartcardio;
	requires java.sql;
	requires java.xml;
	//requires forms;
	requires org.apache.commons.codec;
	requires org.junit.platform.commons;
	requires org.junit.platform.engine;
	requires org.junit.platform.launcher;
	requires org.slf4j;
}
