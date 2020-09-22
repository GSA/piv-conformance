module gov.gsa.pivconformance.cardlib {
	exports gov.gsa.pivconformance.cardlib.card.client;
	exports gov.gsa.pivconformance.cardlib.tools;
	exports gov.gsa.pivconformance.cardlib.utils;
	exports gov.gsa.pivconformance.cardlib.tlv;

	requires java.smartcardio;
	requires java.sql;
	requires org.apache.commons.cli;
	requires org.apache.commons.codec;
	requires org.bouncycastle.pkix;
	requires org.bouncycastle.provider;
	requires org.slf4j;
}