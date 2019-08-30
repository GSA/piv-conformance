package gov.gsa.pivconformance.card.client;

/**
 * Encapsulates a PIV application identifier
 */
public class ApplicationAID {
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
