package gov.gsa.pivconformance.cardlib.card.client;

import gov.gsa.pivconformance.cardlib.tlv.*;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * A class that serves the function of the handle to a list of authenticator objects
 * in SP800-73
 */
public class PIVAuthenticators {
    private static final Logger s_logger = LoggerFactory.getLogger(PIVAuthenticators.class);

    private ArrayList<PIVAuthenticator> m_authenticators = new ArrayList<PIVAuthenticator>();

    /**
     *
     * Get the list of authenticators
     *
     * @return List of PIVAuthenticator objects
     */
    public List<PIVAuthenticator> getAuthenticators() {
        return m_authenticators;
    }


    /**
     *
     * Add a global pin authenticator object
     *
     * @param pin String containing pin value
     */
    public void addGlobalPin(String pin) {
        PIVAuthenticator a = new PIVAuthenticator(TagConstants.KEY_REFERENCE_GLOBAL_PIN_TAG, pin);
        m_authenticators.add(a);
    }

    /**
     *
     * Add an application pin authenticator object
     *
     * @param pin String containing pin value
     */
    public void addApplicationPin(String pin) {
        PIVAuthenticator a = new PIVAuthenticator(TagConstants.KEY_REFERENCE_APPLICATION_PIN_TAG, pin);
        m_authenticators.add(a);
    }


    /**
     *
     * Returns a byte array representation of a list of authenticator objects
     *
     * @return Byte array containing authenticator list
     */
    public byte[] getBytes() {
        byte[] rv = {};
        if(m_authenticators.size() == 0) return rv;
        BerTlvBuilder b = new BerTlvBuilder();
        for(PIVAuthenticator authenticator: m_authenticators) {
            b.addBytes(new BerTag(TagConstants.REFERENCE_DATA_TAG), authenticator.getData());
            b.addByte(new BerTag(TagConstants.KEY_REFERENCE_TAG), authenticator.getType());
        }
        rv = b.buildArray();
        //s_logger.debug("Encoded authenticators: {}", Hex.encodeHexString(rv));
        return rv;
    }

    /**
     *
     * Helper function that decodes byte array containing authenticator list and populates various class fields.
     *
     * @param authenticators Byte array containing authenticator list
     */
    public boolean decode(byte[] authenticators) {
        m_authenticators.clear();
        if(authenticators.length == 0) return true;
        BerTlvParser p = new BerTlvParser(new CCTTlvLogger(this.getClass()));
        BerTlvs tlvs = p.parse(authenticators);
        byte[] refData = null;
        byte refId = 0x00;
        for(BerTlv t : tlvs.getList()) {
            switch(t.getTag().bytes[0] ) {
                case (byte)0x81:
                {
                    refData = t.getBytesValue();
                    break;
                }
                case (byte)0x83:
                {
                    if(refData == null) {
                        throw new IllegalStateException("Unexpected 0x83 tag without having seen 0x81 tag while parsing authenticator");
                    }
                    refId = t.getBytesValue()[0];
                    PIVAuthenticator parsed = new PIVAuthenticator(refId, refData);
                    m_authenticators.add(parsed);
                    refData = null;
                    refId = 0x00;
                    break;
                }
                default:
                    throw new IllegalStateException("Unexpected tag in authenticator");
            }
        }
        return true;
    }



}
