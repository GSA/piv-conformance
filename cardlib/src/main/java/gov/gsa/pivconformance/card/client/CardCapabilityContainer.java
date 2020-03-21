package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;
import java.util.HashMap;

/**
 *
 * Encapsulates a Card Capability Container data object  as defined by SP800-73-4 Part 2 Appendix A Table 8
 *
 */
public class CardCapabilityContainer extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(CardCapabilityContainer.class);

    private byte[] m_cardIdentifier;
    private byte[] m_capabilityContainerVersionNumber;
    private byte[] m_capabilityGrammarVersionNumber;
    private List<byte[]> m_appCardURL;
    private byte[] m_pkcs15;
    private byte[] m_registeredDataModelNumber;
    private byte[] m_accessControlRuleTable;
    private boolean m_cardAPDUs;
    private boolean m_redirectionTag;
    private boolean m_capabilityTuples;
    private boolean m_statusTuples;
    private boolean m_nextCCC;
    private List<byte[]> m_extendedApplicationCardURL;
    private byte[] m_securityObjectBuffer;
    private byte[] m_signedContent;
    //private HashMap<BerTag, byte[]> m_content;


	/**
     * CardCapabilityContainer class constructor, initializes all the class fields.
     */
    public CardCapabilityContainer() {

        m_cardIdentifier = null;
        m_capabilityContainerVersionNumber = null;
        m_capabilityGrammarVersionNumber = null;
        m_appCardURL = null;
        m_pkcs15 = null;
        m_registeredDataModelNumber = null;
        m_accessControlRuleTable = null;
        m_cardAPDUs = false;
        m_redirectionTag = false;
        m_capabilityTuples = false;
        m_statusTuples = false;
        m_nextCCC = false;
        m_extendedApplicationCardURL = null;
        m_securityObjectBuffer = null;
        setErrorDetectionCode(false);
        setErrorDetectionCodeHasData(false);
        m_content = new HashMap<BerTag, byte[]>();
    }

    /**
     *
     * Returns byte array with signed content buffer
     *
     * @return Byte array with signed content buffer
     */
    public byte[] getSignedContent() {
        return m_signedContent;
    }

    /**
     *
     * Sets the signed content buffer
     *
     * @param signedContent Byte array with signed content buffer
     */
    public void setSignedContent(byte[] signedContent) {
        m_signedContent = signedContent;
    }

    /**
     *
     * Returns card identifier
     *
     * @return Byte array containing card identifier
     */
    public byte[] getCardIdentifier() {

        return m_cardIdentifier;
    }

    /**
     *
     *  Returns capability container version number
     *
     * @return Byte array containing capability container version number
     */
    public byte[] getCapabilityContainerVersionNumber() {

        return m_capabilityContainerVersionNumber;
    }

    /**
     *
     * Returns capability grammar version number
     *
     * @return Byte array containing capability grammar version number
     */
    public byte[] getCapabilityGrammarVersionNumber() {

        return m_capabilityGrammarVersionNumber;
    }

    /**
     *
     * Returns a list of application card urls
     *
     * @return List of application card urls
     */
    public List<byte[]> getAppCardURL() {

        return m_appCardURL;
    }

    /**
     *
     * Returns PKCS15 value
     *
     * @return Byte array containing PKCS15 value
     */
    public byte[] getPkcs15() {

        return m_pkcs15;
    }

    /**
     *
     * Returns Registered Data Model number value
     *
     * @return Byte array containing Registered Data Model number
     */
    public byte[] getRegisteredDataModelNumber() {

        return m_registeredDataModelNumber;
    }

    /**
     *
     * Returns Access Control Rule Table value
     *
     * @return Byte array containing Access Control Rule Table value
     */
    public byte[] getAccessControlRuleTable() {

        return m_accessControlRuleTable;
    }

    /**
     *
     * Returns Card APDUs value
     *
     * @return Byte array containing Card APDUs value
     */
    public boolean getCardAPDUs() {

        return m_cardAPDUs;
    }

    /**
     *
     * Returns Redirection Tag value
     *
     * @return Byte array containing Redirection Tag value
     */
    public boolean getRedirectionTag() {

        return m_redirectionTag;
    }

    /**
     *
     * Returns Capability Tuples value
     *
     * @return Byte array containing Capability Tuples value
     */
    public boolean getCapabilityTuples() {

        return m_capabilityTuples;
    }

    /**
     *
     * Returns Status Tuples value
     *
     * @return Byte array containing Status Tuples value
     */
    public boolean getStatusTuples() {

        return m_statusTuples;
    }

    /**
     *
     * Returns Next CCC value
     *
     * @return Byte array containing Next CCC value
     */
    public boolean getNextCCC() {

        return m_nextCCC;
    }

    /**
     *
     * Returns a list of if Extended Application CardURL
     *
     * @return List of if Extended Application CardURL
     */
    public List<byte[]> getExtendedApplicationCardURL() {

        return m_extendedApplicationCardURL;
    }

    /**
     *
     * Returns Security Object Buffer value
     *
     * @return Byte array containing Security Object Buffer
     */
    public byte[] getSecurityObjectBuffer() {

        return m_securityObjectBuffer;
    }


    /**
     *
     * Decode function that decodes Card Capability Container object retrieved from the card and populates various class fields.
     *
     * @return True if decode was successful, false otherwise
     */
    @Override
	public boolean decode() {

        try{
            byte [] raw = super.getBytes();

            if(raw == null){
                s_logger.error("No buffer to decode for {}.", APDUConstants.oidNameMap.get(super.getOID()));
                return false;
            }

            BerTlvParser tp = new BerTlvParser(new CCTTlvLogger(CardCapabilityContainer.class));
            BerTlvs outer = tp.parse(raw);

            if(outer == null){
                s_logger.error("Error parsing CCC container, unable to parse TLV value 1.");
                return false;
            }

            List<BerTlv> values = outer.getList();
            for(BerTlv tlv : values) {
                if(tlv.isPrimitive()) {
                    s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                    BerTlvs outer2 = tp.parse(tlv.getBytesValue());

                    if(outer2 == null){
                        s_logger.error("Error parsing CCC, unable to parse TLV value 2.");
                        return false;
                    }

                    ByteArrayOutputStream scos = new ByteArrayOutputStream();
                    List<BerTlv> values2 = outer2.getList();
                    for(BerTlv tlv2 : values2) {
                        if(tlv2.isPrimitive()) {
                            s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                        } else {
                        	super.m_tagList.add(tlv2.getTag());
                            if(Arrays.equals(tlv2.getTag().bytes,TagConstants.CARD_IDENTIFIER_TAG)) {
                                if (tlv2.hasRawValue()) {
                                    m_cardIdentifier = tlv2.getBytesValue();
                                    m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                    scos.write(APDUUtils.getTLV(TagConstants.CARD_IDENTIFIER_TAG, m_cardIdentifier));
                                }
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.CAPABILITY_CONTAINER_VERSION_NUMBER_TAG)) {
                                if (tlv2.hasRawValue()) {
                                    m_capabilityContainerVersionNumber = tlv2.getBytesValue();
                                    m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                    scos.write(APDUUtils.getTLV(TagConstants.CAPABILITY_CONTAINER_VERSION_NUMBER_TAG, m_capabilityContainerVersionNumber));
                                }
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.CAPABILITY_GRAMMAR_VERSION_NUMBER_TAG)) {
                                if (tlv2.hasRawValue()) {
                                    m_capabilityGrammarVersionNumber = tlv2.getBytesValue();
                                    m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                }
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.APPLICATIONS_CARDURL_TAG)) {
                                if (tlv2.hasRawValue()) {

                                    if(m_appCardURL == null)
                                        m_appCardURL = new ArrayList<>();
                                    m_appCardURL.add(tlv2.getBytesValue());
                                    m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                    scos.write(APDUUtils.getTLV(TagConstants.APPLICATIONS_CARDURL_TAG, tlv2.getBytesValue()));
                                }
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.PKCS15_TAG)) {
                                if (tlv2.hasRawValue()) {
                                    m_pkcs15 = tlv2.getBytesValue();
                                    m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                    scos.write(APDUUtils.getTLV(TagConstants.PKCS15_TAG, m_pkcs15));
                                }
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.REGISTERED_DATA_MODEL_NUMBER_TAG)) {
                                if (tlv2.hasRawValue()) {
                                    m_registeredDataModelNumber = tlv2.getBytesValue();
                                    m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                    scos.write(APDUUtils.getTLV(TagConstants.REGISTERED_DATA_MODEL_NUMBER_TAG, m_registeredDataModelNumber));
                                }
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.ACCESS_CONTROL_RULE_TABLE_TAG)) {
                                if (tlv2.hasRawValue()) {
                                    m_accessControlRuleTable = tlv2.getBytesValue();
                                    m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                    scos.write(APDUUtils.getTLV(TagConstants.ACCESS_CONTROL_RULE_TABLE_TAG, m_accessControlRuleTable));
                                }
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.CARD_APDUS_TAG)) {
                                 m_cardAPDUs = true;
                                 m_content.put(tlv2.getTag(), tlv2.getBytesValue());                        
                                 scos.write(APDUUtils.getTLV(TagConstants.CARD_APDUS_TAG, tlv2.getBytesValue()));
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.REDIRECTION_TAG_TAG)) {
                                 m_redirectionTag = true;
                                 m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                 scos.write(APDUUtils.getTLV(TagConstants.REDIRECTION_TAG_TAG, tlv2.getBytesValue()));

                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.CAPABILITY_TUPLES_TAG)) {
                                 m_capabilityTuples = true;
                                 m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                 scos.write(APDUUtils.getTLV(TagConstants.CAPABILITY_TUPLES_TAG, tlv2.getBytesValue()));
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.STATUS_TUPLES_TAG)) {
                                 m_statusTuples = true;
                                 m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                 scos.write(APDUUtils.getTLV(TagConstants.STATUS_TUPLES_TAG, tlv2.getBytesValue()));
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.NEXT_CCC_TAG)) {
                                 m_nextCCC = true;
                                 m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                 scos.write(APDUUtils.getTLV(TagConstants.NEXT_CCC_TAG, tlv2.getBytesValue()));
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.EXTENDED_APPLICATION_CARDURL_TAG)) {
                                if(m_extendedApplicationCardURL == null)
                                    m_extendedApplicationCardURL = new ArrayList<>();
                                m_extendedApplicationCardURL.add(tlv2.getBytesValue());
                                m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                scos.write(APDUUtils.getTLV(TagConstants.EXTENDED_APPLICATION_CARDURL_TAG, tlv2.getBytesValue()));
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.SECURITY_OBJECT_BUFFER_TAG)) {
                                m_securityObjectBuffer = tlv2.getBytesValue();
                                m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                scos.write(APDUUtils.getTLV(TagConstants.SECURITY_OBJECT_BUFFER_TAG, tlv2.getBytesValue()));
                            }
                            if(Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {
                            	setErrorDetectionCode(true);
                                m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                scos.write(TagConstants.ERROR_DETECTION_CODE_TAG);
                                scos.write((byte) 0x00);
                            }
                        }
                    }


                    m_signedContent = scos.toByteArray();

                } else {
                    s_logger.info("Object: {}", Hex.encodeHexString(tlv.getTag().bytes));
                }
            }
        } catch (Exception ex) {

            s_logger.error("Error parsing CCC: {}", ex.getMessage());
            return false;
        }

        if (m_cardIdentifier == null || m_capabilityContainerVersionNumber == null ||
                m_capabilityGrammarVersionNumber == null || m_appCardURL == null || m_pkcs15 == null ||
                m_registeredDataModelNumber == null || m_accessControlRuleTable == null || m_cardAPDUs == false ||
                m_redirectionTag ==  false || m_capabilityTuples == false || m_statusTuples == false ||
                m_nextCCC == false) {
            return false;
        }
        
        dump(this.getClass());
        return true;
    }
}
