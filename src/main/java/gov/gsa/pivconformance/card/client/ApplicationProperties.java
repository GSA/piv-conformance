package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encapsulates the application properties record for a PIV application, as described in SP800-73-4 part 2, table 3
 */
public class ApplicationProperties {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(ApplicationProperties.class);

    private byte[] m_appPropertiesBytes;


    public void setBytes(byte[] appPropertiesBytes) {
        m_appPropertiesBytes = appPropertiesBytes;
    }

    public byte[] getBytes() {
        return m_appPropertiesBytes;
    }
}
