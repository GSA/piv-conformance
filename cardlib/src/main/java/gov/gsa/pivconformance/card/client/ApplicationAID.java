package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encapsulates a PIV application identifier
 */
public class ApplicationAID {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(ApplicationAID.class);

    /**
     * ApplicationAID class constructor, initializes all the class fields.
     */
    public ApplicationAID() {
        m_appIDBytes = null;
    }

    /**
     *
     * ApplicationAID class constructor, sets the app ID value bassed on the passed in buffer
     *
     * @param appIDBytes
     */
    public ApplicationAID(byte[] appIDBytes) {
        m_appIDBytes = appIDBytes;
    }


    private byte[] m_appIDBytes;

    /**
     *
     * Sets the app id value
     *
     * @param appIDBytes Byte array with app id value
     */
    public void setBytes(byte[] appIDBytes) {
        m_appIDBytes = appIDBytes;
    }

    /**
     *
     * Returns app id value
     *
     * @return Byte array with app id value
     */
    public byte[] getBytes() { return m_appIDBytes; }
}
