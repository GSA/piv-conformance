package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * encapsulates a PIV application identifier
 */
public class ApplicationAID {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(ApplicationAID.class);

    public ApplicationAID() {
        m_appIDBytes = null;
    }

    public ApplicationAID(byte[] appIDBytes) {
        m_appIDBytes = appIDBytes;
    }

    private byte[] m_appIDBytes;

    public void setBytes(byte[] appIDBytes) {
        m_appIDBytes = appIDBytes;
    }

    public byte[] getBytes() { return m_appIDBytes; }
}
