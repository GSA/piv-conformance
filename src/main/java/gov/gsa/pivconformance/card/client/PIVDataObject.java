package gov.gsa.pivconformance.card.client;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a PIV data object as read to or written from the card.
 * Subclasses may provide abstractions for field access.
 */
public class PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PIVDataObject.class);

    private byte[] m_dataBytes;
    private String m_OID;
    private boolean m_signed;


    public PIVDataObject() {

        m_OID = null;
        m_signed = false;
    }

    public PIVDataObject(String OID) {
        m_OID = OID;
    }

    public void setBytes(byte[] dataBytes) {
        m_dataBytes = dataBytes;
    }

    public byte[] getBytes() { return m_dataBytes; }

    public String getOID() {
        return m_OID;
    }

    public void setOID(String OID) {
        m_OID = OID;
    }

    public String getFriendlyName() {
        return APDUConstants.oidNameMAP.getOrDefault(m_OID, "Undefined");
    }

    public byte[] getTag() {
        byte[] rv = APDUConstants.oidMAP.getOrDefault(m_OID, new byte[]{});
        return rv;
    }

    public boolean decode() {
        // XXX *** make this throw a RuntimeError once implementations are notionally in place
        s_logger.error("decode() called without a concrete implementation.");
        return false;
    }

    public String toRawHexString() {
        return Hex.encodeHexString(m_dataBytes);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PIV Data Object with OID " + m_OID + " (" + getFriendlyName() + "):");
        sb.append(toRawHexString());
        return sb.toString();
    }

    public void setSigned(boolean signed) {
        m_signed = signed;
    }

    public boolean isSigned() {
        return m_signed;
    }
}
