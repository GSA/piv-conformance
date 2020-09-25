module gov.gsa.pivconformance.cardlib {
	exports gov.gsa.pivconformance.cardlib.card.client;
	exports gov.gsa.pivconformance.cardlib.tools;
	exports gov.gsa.pivconformance.cardlib.utils;
	exports gov.gsa.pivconformance.cardlib.tlv;

	requires java.smartcardio;
	requires java.sql;
	requires commons.cli;
	requires commons.codec;
	requires org.apache.commons.csv;
	requires org.bouncycastle.pkix;
	requires org.bouncycastle.provider;
	requires org.slf4j;
}
