package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.List;

public class CardHolderUniqueIdentifier extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(CardHolderUniqueIdentifier.class);

    private byte[] m_bufferLength;
    private byte[] m_fASCN;
    private byte[] m_organizationalIdentifier;
    private byte[] m_dUNS;
    private byte[] m_gUID;
    private Date m_expirationDate;
    private byte[] m_cardholderUUID;
    private byte[] m_issuerAsymmetricSignature;
    private boolean m_errorDetectionCode;

    public CardHolderUniqueIdentifier() {
    }

    public byte[] getBufferLength() {
        return m_bufferLength;
    }

    public void setBufferLength(byte[] bufferLength) {
        m_bufferLength = bufferLength;
    }

    public byte[] getfASCN() {
        return m_fASCN;
    }

    public void setfASCN(byte[] fASCN) {
        m_fASCN = fASCN;
    }

    public byte[] getOrganizationalIdentifier() {
        return m_organizationalIdentifier;
    }

    public void setOrganizationalIdentifier(byte[] organizationalIdentifier) {
        m_organizationalIdentifier = organizationalIdentifier;
    }

    public byte[] getdUNS() {
        return m_dUNS;
    }

    public void setdUNS(byte[] dUNS) {
        m_dUNS = dUNS;
    }

    public byte[] getgUID() {
        return m_gUID;
    }

    public void setgUID(byte[] gUID) {
        m_gUID = gUID;
    }

    public Date getExpirationDate() {
        return m_expirationDate;
    }

    public void setExpirationDate(Date expirationDate) {
        m_expirationDate = expirationDate;
    }

    public byte[] getCardholderUUID() {
        return m_cardholderUUID;
    }

    public void setCardholderUUID(byte[] cardholderUUID) {
        m_cardholderUUID = cardholderUUID;
    }

    public byte[] getIssuerAsymmetricSignature() {
        return m_issuerAsymmetricSignature;
    }

    public void setIssuerAsymmetricSignature(byte[] issuerAsymmetricSignature) {
        m_issuerAsymmetricSignature = issuerAsymmetricSignature;
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
            BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
            BerTlvs outer = tlvp.parse(rawBytes);

            if(outer == null){
                s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMAP.get(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID));
                return false;
            }

            List<BerTlv> values = outer.getList();
            for(BerTlv tlv : values) {
                if(tlv.isPrimitive()) {
                    s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                    BerTlvs outer2 = tlvp.parse(tlv.getBytesValue());

                    if (outer2 == null) {
                        s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMAP.get(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID));
                        return false;
                    }

                    List<BerTlv> values2 = outer2.getList();
                    for (BerTlv tlv2 : values2) {
                        if (tlv2.isPrimitive()) {
                            s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                        } else {
                            if (Arrays.equals(tlv2.getTag().bytes, TagConstants.BUFFER_LENGTH_TAG)) {

                                m_bufferLength = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.FASC_N_TAG)) {

                                m_fASCN = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG)) {

                                m_organizationalIdentifier = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.DUNS_TAG)) {

                                m_dUNS = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.GUID_TAG)) {

                                m_gUID = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.CHUID_EXPIRATION_DATE_TAG)) {

                                String s = new String(tlv2.getBytesValue());

                                Date date = new SimpleDateFormat("yyyyMMdd").parse(s);
                                m_expirationDate = date;

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.CARDHOLDER_UUID_TAG)) {

                                m_cardholderUUID = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG)) {

                                m_issuerAsymmetricSignature = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {

                                m_errorDetectionCode = true;

                            } else {
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }
                        }
                    }
                }
            }
        }catch (Exception ex) {

            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID), ex.getMessage());
        }
        return true;
    }

}
