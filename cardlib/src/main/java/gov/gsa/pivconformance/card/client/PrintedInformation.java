package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 *
 * Encapsulates a Printed Information data object  as defined by SP800-73-4 Part 2 Appendix A Table 9
 *
 */
public class PrintedInformation extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PrintedInformation.class);

    private String m_name;
    private String m_employeeAffiliation;
    private String m_expirationDate;
    private String m_agencyCardSerialNumber;
    private String m_issuerIdentification;
    private String m_organizationAffiliation1;
    private String m_organizationAffiliation2;
    private boolean m_errorDetectionCode;
    private byte[] m_signedContent;


    /**
     * PrintedInformation class constructor, initializes all the class fields.
     */
    public PrintedInformation() {
        m_name = "";
        m_employeeAffiliation = "";
        m_expirationDate = "";
        m_agencyCardSerialNumber = "";
        m_issuerIdentification = "";
        m_organizationAffiliation1 = "";
        m_organizationAffiliation2 = "";
        m_errorDetectionCode = false;
        m_signedContent = null;
    }

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
     * Returns the Name value as String
     *
     * @return String with the Name value
     */
    public String getName() {
        return m_name;
    }


    /**
     *
     * Sets the name value
     *
     * @param name String with the Name value
     */
    public void setName(String name) {
        m_name = name;
    }

    /**
     *
     * Returns the Employee Affiliation value as String
     *
     * @return String with the Employee Affiliation value
     */
    public String getEmployeeAffiliation() {
        return m_employeeAffiliation;
    }

    /**
     *
     * Sets the Employee Affiliation value
     *
     * @param employeeAffiliation String with the Employee Affiliation value
     */
    public void setEmployeeAffiliation(String employeeAffiliation) {
        m_employeeAffiliation = employeeAffiliation;
    }

    /**
     *
     * Returns the Expiration Date value as String
     *
     * @return String with the Expiration Date value
     */
    public String getExpirationDate() {
        return m_expirationDate;
    }

    /**
     *
     * Sets the Expiration Date value
     *
     * @param expirationDate String with the Expiration Date value
     */
    public void setExpirationDate(String expirationDate) {
        m_expirationDate = expirationDate;
    }

    /**
     *
     * Returns the Agency Card Serial Number value as String
     *
     * @return String with the Agency Card Serial Number value
     */
    public String getAgencyCardSerialNumber() {
        return m_agencyCardSerialNumber;
    }

    /**
     *
     * Sets the Agency Card Serial Number value
     *
     * @param agencyCardSerialNumber String with the Agency Card Serial Number value
     */
    public void setAgencyCardSerialNumber(String agencyCardSerialNumber) {
        m_agencyCardSerialNumber = agencyCardSerialNumber;
    }

    /**
     *
     * Returns the Issuer Identification value as String
     *
     * @return String with the Issuer Identification value
     */
    public String getIssuerIdentification() {
        return m_issuerIdentification;
    }

    /**
     *
     * Sets the Issuer Identification value
     *
     * @param issuerIdentification String with the Issuer Identification value
     */
    public void setIssuerIdentification(String issuerIdentification) {
        m_issuerIdentification = issuerIdentification;
    }

    /**
     *
     * Returns the Organization Affiliation1 value as String
     *
     * @return String with the Organization Affiliation1 value
     */
    public String getOrganizationAffiliation1() {
        return m_organizationAffiliation1;
    }

    /**
     *
     * Sets the Organization Affiliation1 value
     *
     * @param organizationAffiliation1 String with the Organization Affiliation1 value
     */
    public void setOrganizationAffiliation1(String organizationAffiliation1) {
        m_organizationAffiliation1 = organizationAffiliation1;
    }

    /**
     *
     * Returns the Organization Affiliation2 value as String
     *
     * @return String with the Organization Affiliation2 value
     */
    public String getOrganizationAffiliation2() {
        return m_organizationAffiliation2;
    }

    /**
     *
     * Sets the Organization Affiliation2 value
     *
     * @param organizationAffiliation2 String with the Organization Affiliation2 value
     */
    public void setOrganizationAffiliation2(String organizationAffiliation2) {
        m_organizationAffiliation2 = organizationAffiliation2;
    }

    /**
     *
     * Returns True if error Error Detection Code is present, false otherwise
     *
     * @return True if error Error Detection Code is present, false otherwise
     */
    public boolean getErrorDetectionCode() {
        return m_errorDetectionCode;
    }

    /**
     *
     * Sets if error Error Detection Code is present
     *
     * @param errorDetectionCode True if error Error Detection Code is present, false otherwise
     */
    public void setErrorDetectionCode(boolean errorDetectionCode) {
        m_errorDetectionCode = errorDetectionCode;
    }

    /**
     *
     * Decode function that decodes Printed Information object retrieved from the card and populates various class fields.
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

                    ByteArrayOutputStream scos = new ByteArrayOutputStream();

                    List<BerTlv> values2 = outer2.getList();
                    for (BerTlv tlv2 : values2) {
                        if (tlv2.isPrimitive()) {
                            if (Arrays.equals(tlv2.getTag().bytes, TagConstants.NAME_TAG)) {

                                m_name = new String(tlv2.getBytesValue());

                                scos.write(APDUUtils.getTLV(TagConstants.NAME_TAG, tlv2.getBytesValue()));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.EMPLOYEE_AFFILIATION_TAG)) {

                                m_employeeAffiliation = new String(tlv2.getBytesValue());

                                scos.write(APDUUtils.getTLV(TagConstants.EMPLOYEE_AFFILIATION_TAG, tlv2.getBytesValue()));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG)) {

                                m_expirationDate = new String(tlv2.getBytesValue());

                                scos.write(APDUUtils.getTLV(TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG, tlv2.getBytesValue()));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG)) {

                                m_agencyCardSerialNumber = new String(tlv2.getBytesValue());

                                scos.write(APDUUtils.getTLV(TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG, tlv2.getBytesValue()));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ISSUER_IDENTIFICATION_TAG)) {

                                m_issuerIdentification = new String(tlv2.getBytesValue());

                                scos.write(APDUUtils.getTLV(TagConstants.ISSUER_IDENTIFICATION_TAG, tlv2.getBytesValue()));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG)) {

                                m_organizationAffiliation1 = new String(tlv2.getBytesValue());

                                scos.write(APDUUtils.getTLV(TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG, tlv2.getBytesValue()));

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG)) {

                                m_organizationAffiliation2 = new String(tlv2.getBytesValue());

                                scos.write(APDUUtils.getTLV(TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG, tlv2.getBytesValue()));

                            }else{
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }
                        } else {
                            if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {

                                m_errorDetectionCode = true;

                                scos.write(TagConstants.ERROR_DETECTION_CODE_TAG);
                                scos.write((byte) 0x00);

                            } else {
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }
                        }
                    }

                    m_signedContent = scos.toByteArray();
                }
            }
        }catch (Exception ex) {

            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
            return false;
        }

        if (m_name == "" || m_employeeAffiliation == "" || m_expirationDate == "" ||
                m_agencyCardSerialNumber == "" || m_issuerIdentification == "")
            return false;

        return true;
    }
}
