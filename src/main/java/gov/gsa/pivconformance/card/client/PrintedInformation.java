package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

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


    public PrintedInformation() {
        m_name = "";
        m_employeeAffiliation = "";
        m_expirationDate = "";
        m_agencyCardSerialNumber = "";
        m_issuerIdentification = "";
        m_organizationAffiliation1 = "";
        m_organizationAffiliation2 = "";
        m_errorDetectionCode = false;
    }

    public String getName() {
        return m_name;
    }

    public void setName(String name) {
        m_name = name;
    }

    public String getEmployeeAffiliation() {
        return m_employeeAffiliation;
    }

    public void setEmployeeAffiliation(String employeeAffiliation) {
        m_employeeAffiliation = employeeAffiliation;
    }

    public String getExpirationDate() {
        return m_expirationDate;
    }

    public void setExpirationDate(String expirationDate) {
        m_expirationDate = expirationDate;
    }

    public String getAgencyCardSerialNumber() {
        return m_agencyCardSerialNumber;
    }

    public void setAgencyCardSerialNumber(String agencyCardSerialNumber) {
        m_agencyCardSerialNumber = agencyCardSerialNumber;
    }

    public String getIssuerIdentification() {
        return m_issuerIdentification;
    }

    public void setIssuerIdentification(String issuerIdentification) {
        m_issuerIdentification = issuerIdentification;
    }

    public String getOrganizationAffiliation1() {
        return m_organizationAffiliation1;
    }

    public void setOrganizationAffiliation1(String organizationAffiliation1) {
        m_organizationAffiliation1 = organizationAffiliation1;
    }

    public String getOrganizationAffiliation2() {
        return m_organizationAffiliation2;
    }

    public void setOrganizationAffiliation2(String organizationAffiliation2) {
        m_organizationAffiliation2 = organizationAffiliation2;
    }

    public boolean getErrorDetectionCode() {
        return m_errorDetectionCode;
    }

    public void setErrorDetectionCode(boolean errorDetectionCode) {
        m_errorDetectionCode = errorDetectionCode;
    }

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
                            if (Arrays.equals(tlv2.getTag().bytes, TagConstants.NAME_TAG)) {

                                m_name = new String(tlv2.getBytesValue());

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.EMPLOYEE_AFFILIATION_TAG)) {

                                m_employeeAffiliation = new String(tlv2.getBytesValue());

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG)) {

                                m_expirationDate = new String(tlv2.getBytesValue());

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG)) {

                                m_agencyCardSerialNumber = new String(tlv2.getBytesValue());

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ISSUER_IDENTIFICATION_TAG)) {

                                m_issuerIdentification = new String(tlv2.getBytesValue());

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG)) {

                                m_organizationAffiliation1 = new String(tlv2.getBytesValue());

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG)) {

                                m_organizationAffiliation2 = new String(tlv2.getBytesValue());

                            }else{
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }
                        } else {
                            if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {

                                m_errorDetectionCode = true;

                            } else {
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }
                        }
                    }
                }
            }
        }catch (Exception ex) {

            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }
        return true;
    }
}
