package gov.gsa.pivconformance.cardlib.tlv;

public interface IBerTlvLogger {

    boolean isDebugEnabled();

    void debug(String aFormat, Object ...args);
}
