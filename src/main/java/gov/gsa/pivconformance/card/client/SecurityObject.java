package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

public class SecurityObject extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(SecurityObject.class);
    private byte[] m_mapping;
    private byte[] m_so;

    public byte[] getMapping() {
        return m_mapping;
    }

    public void setMapping(byte[] mapping) {
        m_mapping = mapping;
    }

    public byte[] getSecurityObject() {
        return m_so;
    }

    public void setSecurtiyObject(byte[] so) {
        m_so = so;
    }

    public boolean decode() {
        byte[] rawBytes = this.getBytes();
        BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
        BerTlvs outer = tlvp.parse(rawBytes);
        List<BerTlv> outerTlvs = outer.getList();
        if(outerTlvs.size() == 1 && outerTlvs.get(0).isTag(new BerTag(0x53))) {
            byte[] tlvBuf = outerTlvs.get(0).getBytesValue();
            outer = tlvp.parse(tlvBuf);
        }
        for(BerTlv tlv : outer.getList()) {
            byte[] tag = tlv.getTag().bytes;
            if(Arrays.equals(tag, TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG)) {
                m_mapping = tlv.getBytesValue();
            } else if(Arrays.equals(tag, TagConstants.SECURITY_OBJECT_TAG)) {
                m_so = tlv.getBytesValue();
            } else {
                if(!Arrays.equals(tag, TagConstants.ERROR_DETECTION_CODE_TAG) && tlv.getBytesValue().length != 0) {
                    s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));
                }
            }
        }
        return true;
    }

}
