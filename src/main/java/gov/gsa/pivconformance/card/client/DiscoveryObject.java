package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

public class DiscoveryObject extends PIVDataObject {

    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(DiscoveryObject.class);

    private byte[] m_aid;
    private byte[] m_pinPolicy;
    private boolean m_globalPINSatisfiesACR;
    private boolean m_appPINSatisfiesACR;
    private boolean m_globalPINisPrimary;
    private boolean m_occSatisfiesACR;

    public byte[] getAid() {
        return m_aid;
    }

    public void setAid(byte[] aid) {
        m_aid = aid;
    }

    public byte[] getPinPolicy() {
        return m_pinPolicy;
    }

    public void setPinPolicy(byte[] pinPolicy) {
        m_pinPolicy = pinPolicy;
    }

    public boolean globalPINSatisfiesACR() {
        return m_globalPINSatisfiesACR;
    }

    public void setGlobalPINSatisfiesACR(boolean globalPINSatisfiesACR) {
        m_globalPINSatisfiesACR = globalPINSatisfiesACR;
    }

    public boolean globalPINisPrimary() {
        return m_globalPINisPrimary;
    }

    public void setGlobalPINisPrimary(boolean globalPINisPrimary) {
        m_globalPINisPrimary = globalPINisPrimary;
    }

    // XXX *** MOVE this
    private boolean is_set(byte field, int position) {
        return ((field >> position) & 1) == 1;
    }

    public boolean appPINSatisfiesACR() {
        return m_appPINSatisfiesACR;
    }

    public void setAppPINSatisfiesACR(boolean appPINSatisfiesACR) {
        m_appPINSatisfiesACR = appPINSatisfiesACR;
    }

    public boolean occSatisfiesACR() {
        return m_occSatisfiesACR;
    }

    public void setOccSatisfiesACR(boolean occSatisfiesACR) {
        m_occSatisfiesACR = occSatisfiesACR;
    }

    public boolean decode() {
        byte[] rawBytes = this.getBytes();
        if(rawBytes.length == 0) {
            s_logger.info("DiscoveryObject.decode() called for empty discovery object.");
            return false;
        }
        BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
        BerTlv outer = tlvp.parseConstructed(rawBytes);
        for(BerTlv tlv : outer.getValues()) {
            byte[] tag = tlv.getTag().bytes;
            if(Arrays.equals(tag, TagConstants.PIV_CARD_APPLICATION_AID_TAG)) {
                m_aid = tlv.getBytesValue();
            } else if(Arrays.equals(tag, TagConstants.PIN_USAGE_POLICY_TAG)) {
                m_pinPolicy = tlv.getBytesValue();
                m_globalPINisPrimary = false;
                m_globalPINSatisfiesACR = false;
                m_appPINSatisfiesACR = false;
                m_occSatisfiesACR = false;
                if(is_set(m_pinPolicy[0], 8)) {
                    s_logger.error("PIN Policy bit 8 was set");
                }
                if(is_set(m_pinPolicy[0], 7)){
                   m_appPINSatisfiesACR = true;
                }
                if(is_set(m_pinPolicy[0], 6)) {
                    m_globalPINSatisfiesACR = true;
                    if(m_pinPolicy[1] == 0x20) {
                        m_globalPINisPrimary = true;
                    }
                }
                if(is_set(m_pinPolicy[0], 5)) {
                    m_occSatisfiesACR = true;
                }

            } else {
                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));
            }
        }
        return true;
    }
}
