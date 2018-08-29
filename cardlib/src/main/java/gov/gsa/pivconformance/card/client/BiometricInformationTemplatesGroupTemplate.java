package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 *
 * Encapsulates a Biometric Information Templates Group Template data object  as defined by SP800-73-4 Part 2 Appendix A Table 41
 *
 */
public class BiometricInformationTemplatesGroupTemplate extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(BiometricInformationTemplatesGroupTemplate.class);

    private byte[] m_numberOfFingers;
    private byte[] m_bITForFirstFinger;
    private byte[] m_bITForSecondFinger;


    /**
     * BiometricInformationTemplatesGroupTemplate class constructor, initializes all the class fields.
     */
    public BiometricInformationTemplatesGroupTemplate() {
        m_numberOfFingers = null;
        m_bITForFirstFinger = null;
        m_bITForSecondFinger = null;
    }

    /**
     *
     * Returns byte array containing number of fingers information
     *
     * @return Byte array containing number of fingers information
     */
    public byte[] getNumberOfFingers() {
        return m_numberOfFingers;
    }

    /**
     *
     * Sets the number of fingers information
     *
     * @param numberOfFingers Byte array containing number of fingers information
     */
    public void setNumberOfFingers(byte[] numberOfFingers) {
        m_numberOfFingers = numberOfFingers;
    }

    /**
     *
     * Returns the BIT information for the first finger
     *
     * @return Byte array containing BIT information for the first finger
     */
    public byte[] getbITForFirstFinger() {
        return m_bITForFirstFinger;
    }

    /**
     *
     * Sets the BIT information for the first finger
     *
     * @param bITForFirstFinger Byte array containing BIT information for the first finger
     */
    public void setbITForFirstFinger(byte[] bITForFirstFinger) {
        m_bITForFirstFinger = bITForFirstFinger;
    }

    /**
     *
     * Returns the BIT information for the second finger
     *
     * @return Byte array containing BIT information for the second finger
     */
    public byte[] getbITForSecondFinger() {
        return m_bITForSecondFinger;
    }

    /**
     *
     * Sets the BIT information for the second finger
     *
     * @param bITForSecondFinger Byte array containing BIT information for the second finger
     */
    public void setbITForSecondFinger(byte[] bITForSecondFinger) {
        m_bITForSecondFinger = bITForSecondFinger;
    }

    /**
     *
     * Decode function that decodes Biometric Information Templates Group Template object retrieved from the card and populates various class fields.
     *
     * @return True if decode was successful, false otherwise
     */
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
                } else if(Arrays.equals(tag, TagConstants.BIT_FOR_FIRST_FINGER_TAG)) {

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

        if(m_numberOfFingers == null || m_bITForFirstFinger == null)
            return false;

        return true;
    }
}
