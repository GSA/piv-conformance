package gov.gsa.pivconformance.cardlib.card.client;

import gov.gsa.pivconformance.cardlib.tlv.TagConstants;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class that serves the function of the handle objects passed around that encapsulate authenticator information
 */
public class PIVAuthenticator {
    private static final Logger s_logger = LoggerFactory.getLogger(PIVAuthenticator.class);

    byte m_type;
    byte[] m_data;

    /**
     *
     * Constructor that initializes PIVAuthenticator object based on passed in parameter
     *
     * @param type Authenticator type either an Application Pin or a Global PIN
     * @param data String object containing the pin information
     */
    public PIVAuthenticator(byte type, String data) {
        this(type, data.getBytes());
    }

    /**
     *
     * Constructor that initializes PIVAuthenticator object based on passed in parameter
     *
     * @param type Authenticator type either an Application Pin or a Global PIN
     * @param data Byte array object containing the pin information
     */
    public PIVAuthenticator(byte type, byte[] data) {
        m_type = type;
        if(m_type == TagConstants.KEY_REFERENCE_APPLICATION_PIN_TAG ||
                m_type == TagConstants.KEY_REFERENCE_GLOBAL_PIN_TAG) {
            if(data.length == 0) {
            	m_data = new byte[0];
            } else {
	        	if(data.length > 8 || data.length < 6) {
	                throw new IllegalArgumentException("PIN must be between 6 and 8 digits");
	            }
	            m_data = Arrays.copyOf(data, 8);
	            Arrays.fill(m_data, data.length, m_data.length, (byte)0xff);
            }
        }
    }

    /**
     *
     * Get the authenticator type
     *
     * @return Byte identifying authenticator type
     */
    public byte getType() {
        return m_type;
    }

    /**
     *
     * Set the authenticator type
     *
     * @param type byte containing authenticator type
     */
    public void setType(byte type) {
        m_type = type;
    }

    /**
     *
     * Get the pin information
     *
     * @return Byte array containing pin information
     */
    public byte[] getData() {
        return m_data;
    }

    /**
     *
     * Set the pin
     *
     * @param data byte array containing pin information
     */
    public void setData(byte[] data) {
        m_data = data;
    }

}
