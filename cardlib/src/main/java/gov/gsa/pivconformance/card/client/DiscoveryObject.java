package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;

/**
 *
 * Encapsulates a Discovery Object data object  as defined by SP800-73-4 Part 2 Appendix A Table 18
 *
 */
public class DiscoveryObject extends PIVDataObject {

    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(DiscoveryObject.class);

    private byte[] m_aid;
    private byte[] m_pinPolicy;
    private boolean m_globalPINSatisfiesACR;
    private boolean m_appPINSatisfiesACR;
    private boolean m_globalPINisPrimary;
    private boolean m_occSatisfiesACR;
    private byte[] m_signedContent;


    /**
     *
     * Returns byte array with signed content
     *
     * @return Byte array with signed content buffer
     */
    public byte[] getSignedContent() {
        return m_signedContent;
    }

    /**
     *
     * Sets the signed content value
     *
     * @param signedContent Byte array with signed content buffer
     */
    public void setSignedContent(byte[] signedContent) {
        m_signedContent = signedContent;
    }

    /**
     *
     * Returns PIV Card Application AID value
     *
     * @return Byte array containing PIV Card Application AID value
     */
    public byte[] getAid() {
        return m_aid;
    }

    /**
     *
     * Sets the PIV Card Application AID value
     *
     * @param aid Byte array containing PIV Card Application AID value
     */
    public void setAid(byte[] aid) {
        m_aid = aid;
    }

    /**
     *
     * Returns PIN Usage Policy value
     *
     * @return Byte array containing PIN Usage Policy value
     */
    public byte[] getPinPolicy() {
        return m_pinPolicy;
    }

    /**
     *
     * Sets the PIN Usage Policy value
     *
     * @param pinPolicy Byte array containing PIN Usage Policy value
     */
    public void setPinPolicy(byte[] pinPolicy) {
        m_pinPolicy = pinPolicy;
    }


    /**
     *
     * Returns true if Global PIN satisfies the PIV ACRs, false otherwise
     *
     * @return True if Global PIN satisfies the PIV ACRs, false otherwise
     */
    public boolean globalPINSatisfiesACR() {
        return m_globalPINSatisfiesACR;
    }

    /**
     *
     * Sets if Global PIN satisfies the PIV ACRs, false otherwise
     *
     * @param globalPINSatisfiesACR True if Global PIN satisfies the PIV ACRs, false otherwise
     */
    public void setGlobalPINSatisfiesACR(boolean globalPINSatisfiesACR) {
        m_globalPINSatisfiesACR = globalPINSatisfiesACR;
    }

    /**
     *
     * Returns true if Global PIN is primary, false otherwise
     *
     * @return True if Global PIN is primary, false otherwise
     */
    public boolean globalPINisPrimary() {
        return m_globalPINisPrimary;
    }

    /**
     *
     * Sets if Global PIN is primary
     *
     * @param globalPINisPrimary True if Global PIN is primary, false otherwise
     */
    public void setGlobalPINisPrimary(boolean globalPINisPrimary) {
        m_globalPINisPrimary = globalPINisPrimary;
    }

    // XXX *** MOVE this

    /**
     *
     * Helper function to determine if byte if set at a given position
     *
     * @param field Byte value
     * @param position Integer specifying the position to check
     * @return True if set, false otherwise
     */
    private boolean is_set(byte field, int position) {
        return ((field >> position) & 1) == 1;
    }

    /**
     *
     * Returns true if App PIN satisfies the PIV ACRs, false otherwise
     *
     * @return True if App PIN satisfies the PIV ACRs, false otherwise
     */
    public boolean appPINSatisfiesACR() {
        return m_appPINSatisfiesACR;
    }

    /**
     *
     * Sets if App PIN satisfies the PIV ACRs
     *
     * @param appPINSatisfiesACR True if App PIN satisfies the PIV ACRs, false otherwise
     */
    public void setAppPINSatisfiesACR(boolean appPINSatisfiesACR) {
        m_appPINSatisfiesACR = appPINSatisfiesACR;
    }

    /**
     *
     * Returns true if OCC satisfies the PIV ACRs, false otherwise
     *
     * @return True if OCC satisfies the PIV ACRs, false otherwise
     */
    public boolean occSatisfiesACR() {
        return m_occSatisfiesACR;
    }

    /**
     *
     * Sets if OCC satisfies the PIV ACRs
     *
     * @param occSatisfiesACR True if OCC satisfies the PIV ACRs, false otherwise
     */
    public void setOccSatisfiesACR(boolean occSatisfiesACR) {
        m_occSatisfiesACR = occSatisfiesACR;
    }


    /**
     *
     * Decode function that decodes Discovery Object object retrieved from the card and populates various class fields.
     *
     * @return True if decode was successful, false otherwise
     */
    public boolean decode() {
        byte[] rawBytes = this.getBytes();
        if(rawBytes.length == 0) {
            s_logger.info("DiscoveryObject.decode() called for empty discovery object.");
            return false;
        }

        try {
            BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
            BerTlv outer = tlvp.parseConstructed(rawBytes);

            ByteArrayOutputStream scos = new ByteArrayOutputStream();
            for (BerTlv tlv : outer.getValues()) {
                byte[] tag = tlv.getTag().bytes;
                if (Arrays.equals(tag, TagConstants.PIV_CARD_APPLICATION_AID_TAG)) {
                    m_aid = tlv.getBytesValue();

                    scos.write(APDUUtils.getTLV(TagConstants.PIV_CARD_APPLICATION_AID_TAG, m_aid));

                } else if (Arrays.equals(tag, TagConstants.PIN_USAGE_POLICY_TAG)) {
                    m_pinPolicy = tlv.getBytesValue();

                    scos.write(APDUUtils.getTLV(TagConstants.PIN_USAGE_POLICY_TAG, m_pinPolicy));

                    m_globalPINisPrimary = false;
                    m_globalPINSatisfiesACR = false;
                    m_appPINSatisfiesACR = false;
                    m_occSatisfiesACR = false;
                    if (is_set(m_pinPolicy[0], 8)) {
                        s_logger.error("PIN Policy bit 8 was set");
                    }
                    if (is_set(m_pinPolicy[0], 7)) {
                        m_appPINSatisfiesACR = true;
                    }
                    if (is_set(m_pinPolicy[0], 6)) {
                        m_globalPINSatisfiesACR = true;
                        if (m_pinPolicy[1] == 0x20) {
                            m_globalPINisPrimary = true;
                        }
                    }
                    if (is_set(m_pinPolicy[0], 5)) {
                        m_occSatisfiesACR = true;
                    }

                } else {
                    s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));
                }
            }

            m_signedContent = scos.toByteArray();

        }catch (Exception ex) {

            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }
        return true;
    }
}
