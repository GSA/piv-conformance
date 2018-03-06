package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class BiometricInformationTemplatesGroupTemplate extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(BiometricInformationTemplatesGroupTemplate.class);

    private byte[] m_numberOfFingers;
    private byte[] m_bITForFirstFinger;
    private byte[] m_bITForSecondFinger;


    public BiometricInformationTemplatesGroupTemplate() {
        m_numberOfFingers = null;
        m_bITForFirstFinger = null;
        m_bITForSecondFinger = null;
    }

    public byte[] getNumberOfFingers() {
        return m_numberOfFingers;
    }

    public void setNumberOfFingers(byte[] numberOfFingers) {
        m_numberOfFingers = numberOfFingers;
    }

    public byte[] getbITForFirstFinger() {
        return m_bITForFirstFinger;
    }

    public void setbITForFirstFinger(byte[] bITForFirstFinger) {
        m_bITForFirstFinger = bITForFirstFinger;
    }

    public byte[] getbITForSecondFinger() {
        return m_bITForSecondFinger;
    }

    public void setbITForSecondFinger(byte[] bITForSecondFinger) {
        m_bITForSecondFinger = bITForSecondFinger;
    }

    public boolean decode() {

        try{
            byte[] rawBytes = this.getBytes();

            if(rawBytes == null){
                s_logger.error("No buffer to decode for {}.", APDUConstants.oidNameMAP.get(super.getOID()));
                return false;
            }

            BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
            BerTlv outer = tlvp.parseConstructed(rawBytes);

            if(outer == null){
                s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMAP.get(super.getOID()));
                return false;
            }

            for(BerTlv tlv : outer.getValues()) {
                byte[] tag = tlv.getTag().bytes;
                if(Arrays.equals(tag, TagConstants.NUMBER_OF_FINGERS_TAG)) {
                    m_numberOfFingers = tlv.getBytesValue();
                } else if(Arrays.equals(tag, TagConstants.PIN_USAGE_POLICY_TAG)) {

                    if(m_bITForFirstFinger == null)
                        m_bITForFirstFinger = tlv.getBytesValue();
                    else
                        m_bITForSecondFinger = tlv.getBytesValue();

                } else {
                    s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));
                }
            }
        }catch (Exception ex) {

            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }
        return true;
    }
}
