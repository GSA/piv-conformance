package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 *
 * Encapsulates a Pairing Code Reference Data Container data object  as defined by SP800-73-4 Part 2 Appendix A Table 43
 *
 */
public class PairingCodeReferenceDataContainer extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PairingCodeReferenceDataContainer.class);

    private String m_pairingCode;
    private boolean m_errorDetectionCode;

    /**
     * PairingCodeReferenceDataContainer class constructor, initializes all the class fields.
     */
    public PairingCodeReferenceDataContainer() {
        m_pairingCode = "";
        m_errorDetectionCode = false;
        m_content = new HashMap<BerTag, byte[]>();
    }

    /**
     *
     * Returns a String with pairing code name
     *
     * @return String containing pairing code name
     */
    public String getName() {
        return m_pairingCode;
    }

    /**
     *
     * Sets the pairing code name
     *
     * @param pairingCode String containing pairing code name
     */
    public void setName(String pairingCode) {
        m_pairingCode = pairingCode;
    }

    /**
     *
     * Returns True if error Error Detection Code is present, false otherwise
     *
     * @return True if error Error Detection Code is present, false otherwise
     */
    @Override
	public boolean getErrorDetectionCode() {
        return m_errorDetectionCode;
    }

    /**
     *
     * Sets if error Error Detection Code is present
     *
     * @param errorDetectionCode True if error Error Detection Code is present, false otherwise
     */
    @Override
	public void setErrorDetectionCode(boolean errorDetectionCode) {
        m_errorDetectionCode = errorDetectionCode;
    }

    /**
     *
     * Decode function that decodes Pairing Code Reference Data Container object retrieved from the card and populates various class fields.
     *
     * @return True if decode was successful, false otherwise
     */
    @Override
	public boolean decode() {

        try{
            byte[] rawBytes = this.getBytes();

            if(rawBytes == null){
                s_logger.error("No buffer to decode for {}.", APDUConstants.oidNameMAP.get(super.getOID()));
                return false;
            }

            BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
            BerTlvs outer = tlvp.parse(rawBytes);

            if(outer == null){
                s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMAP.get(super.getOID()));
                return false;
            }

            List<BerTlv> values = outer.getList();
            for(BerTlv tlv : values) {
                if(tlv.isPrimitive()) {
                    s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                    BerTlvs outer2 = tlvp.parse(tlv.getBytesValue());

                    if (outer2 == null) {
                        s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMAP.get(super.getOID()));
                        return false;
                    }

                    List<BerTlv> values2 = outer2.getList();
                    for (BerTlv tlv2 : values2) {
                        if (tlv2.isPrimitive()) {
                            if (Arrays.equals(tlv2.getTag().bytes, TagConstants.PAIRING_CODE_TAG)) {

                                m_pairingCode = new String(tlv2.getBytesValue());
                                m_content.put(tlv2.getTag(), tlv2.getBytesValue());

                            } else{
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }
                        } else {
                            if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {

                                m_errorDetectionCode = true;
                                m_content.put(tlv2.getTag(), tlv2.getBytesValue());

                            } else {
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }
                        }
                    }
                }
            }
        }catch (Exception ex) {

            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
            return false;
        }

        if (m_pairingCode == "")
            return false;

        return true;
    }
}
