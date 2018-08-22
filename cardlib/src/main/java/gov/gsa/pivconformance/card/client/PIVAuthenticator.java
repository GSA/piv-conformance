package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.TagConstants;

import java.util.Arrays;

public class PIVAuthenticator {
    byte m_type;
    byte[] m_data;

    public PIVAuthenticator(byte type, String data) {
        this(type, data.getBytes());
    }

    public PIVAuthenticator(byte type, byte[] data) {
        m_type = type;
        if(m_type == TagConstants.KEY_REFERENCE_APPLICATION_PIN_TAG ||
                m_type == TagConstants.KEY_REFERENCE_GLOBAL_PIN_TAG) {
            if(data.length > 8 || data.length < 6) {
                throw new IllegalArgumentException("PIN must be between 6 and 8 digits");
            }
            m_data = Arrays.copyOf(data, 8);
            Arrays.fill(m_data, data.length, m_data.length, (byte)0xff);
        }
    }

    public byte getType() {
        return m_type;
    }

    public void setType(byte type) {
        m_type = type;
    }

    public byte[] getData() {
        return m_data;
    }

    public void setData(byte[] data) {
        m_data = data;
    }

}
