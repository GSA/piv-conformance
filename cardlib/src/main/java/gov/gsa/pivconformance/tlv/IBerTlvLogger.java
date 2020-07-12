package gov.gsa.pivconformance.tlv;

public interface IBerTlvLogger {

	boolean isDebugEnabled();

	void debug(String aFormat, Object... args);
}
