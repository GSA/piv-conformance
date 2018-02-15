package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a PIV data object as read to or written from the card.
 * Subclasses may provide abstractions for field access.
 */
public class PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PIVDataObject.class);

    public PIVDataObject() {
        m_OID = null;
    }

    public PIVDataObject(String OID) {

        m_OID = OID;
    }

    public byte[] getBytes() { return null; }

    public String getOID() {
        return m_OID;
    }

    public void setOID(String OID) {
        m_OID = OID;
    }

    private String m_OID;
}
