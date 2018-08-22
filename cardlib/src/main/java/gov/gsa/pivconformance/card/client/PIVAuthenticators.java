package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class PIVAuthenticators {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PIVAuthenticators.class);
    private ArrayList<PIVAuthenticator> m_authenticators = new ArrayList<PIVAuthenticator>();

    public List<PIVAuthenticator> getAuthenticators() {
        return m_authenticators;
    }


    public void addGlobalPin(String pin) {
        PIVAuthenticator a = new PIVAuthenticator(TagConstants.KEY_REFERENCE_GLOBAL_PIN_TAG, pin);
        m_authenticators.add(a);
    }

    public void addApplicationPin(String pin) {
        PIVAuthenticator a = new PIVAuthenticator(TagConstants.KEY_REFERENCE_APPLICATION_PIN_TAG, pin);
        m_authenticators.add(a);
    }

    public byte[] getBytes() {
        byte[] rv = {};
        if(m_authenticators.size() == 0) return rv;
        BerTlvBuilder b = new BerTlvBuilder();
        for(PIVAuthenticator authenticator: m_authenticators) {
            b.addBytes(new BerTag(TagConstants.REFERENCE_DATA_TAG), authenticator.getData());
            b.addByte(new BerTag(TagConstants.KEY_REFERENCE_TAG), authenticator.getType());
        }
        rv = b.buildArray();
        s_logger.debug("Encoded authenticators: {}", Hex.encodeHexString(rv));
        return rv;
    }

    public boolean decode(byte[] authenticators) {
        m_authenticators.clear();
        if(authenticators.length == 0) return true;
        BerTlvParser p = new BerTlvParser(new CCTTlvLogger(this.getClass()));
        BerTlvs tlvs = p.parse(authenticators);
        int currTagIndex = 0;
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
