package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.nio.ByteBuffer;

public class CardholderBiometricData extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(CardholderBiometricData.class);


    private byte[] m_biometricData;
    private byte[] m_biometricCreationDate;
    private boolean m_errorDetectionCode;
    private byte[] m_validityPeriodFrom;
    private byte[] m_validityPeriodTo;
    private byte[] m_biometricDataBlock;
    private CMSSignedData m_signedData;;



    public CardholderBiometricData() {
        m_biometricData = null;
        m_errorDetectionCode = false;
        m_biometricCreationDate = null;
        m_validityPeriodFrom = null;
        m_validityPeriodTo = null;
        m_signedData = null;
        m_biometricDataBlock = null;
    }

    public byte[] getBiometricData() {
        return m_biometricData;
    }

    public void setBiometricData(byte[] biometricData) {
        m_biometricData = biometricData;
    }

    public boolean getErrorDetectionCode() {
        return m_errorDetectionCode;
    }

    public void setErrorDetectionCode(boolean errorDetectionCode) {
        m_errorDetectionCode = errorDetectionCode;
    }


    public byte[] getBiometricCreationDate() {
        return m_biometricCreationDate;
    }

    public void setBiometricCreationDate(byte[] biometricCreationDate) {
        m_biometricCreationDate = biometricCreationDate;
    }

    public byte[] getBiometricDataBlock() {
        return m_biometricDataBlock;
    }

    public void setBiometricDataBlock(byte[] biometricDataBlock) {
        m_biometricDataBlock = biometricDataBlock;
    }

    public byte[] getValidityPeriodFrom() {
        return m_validityPeriodFrom;
    }

    public void setValidityPeriodFrom(byte[] validityPeriodFrom) {
        m_validityPeriodFrom = validityPeriodFrom;
    }

    public byte[] getValidityPeriodTo() {
        return m_validityPeriodTo;
    }

    public void setValidityPeriodTo(byte[] validityPeriodTo) {
        m_validityPeriodTo = validityPeriodTo;
    }

    public CMSSignedData getSignedData() {
        return m_signedData;
    }

    public void setSignedData(CMSSignedData signedData) {
        m_signedData = signedData;
    }


    public boolean decode() {

        try{
            byte[] rawBytes = this.getBytes();

            s_logger.debug("rawBytes: {}", Hex.encodeHexString(rawBytes));

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
                            s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                        } else {
                            if (Arrays.equals(tlv2.getTag().bytes, TagConstants.FINGERPRINT_I_AND_II_TAG)) {

                                m_biometricData = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.IMAGE_FOR_VISUAL_VERIFICATION_TAG)) {

                                m_biometricData = tlv2.getBytesValue();

                            } else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.IMAGES_FOR_IRIS_TAG)) {

                                m_biometricData = tlv2.getBytesValue();

                            }else if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {

                                m_errorDetectionCode = true;

                            } else {
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }
                        }
                    }

                    if (m_biometricData != null) {

                        //Get Biometric data block (BDB) Length
                        byte[] biometricDataBlockLengthBytes = Arrays.copyOfRange(m_biometricData, 2, 6);
                        //Get Signature block (SB) Length
                        byte[] signatureDataBlockLengthBytes = Arrays.copyOfRange(m_biometricData, 6, 8);

                        //Get Biometric Creation Date
                        m_biometricCreationDate = Arrays.copyOfRange(m_biometricData, 12, 20);
                        //Get Validity Period From value
                        m_validityPeriodFrom = Arrays.copyOfRange(m_biometricData, 20, 28);
                        //Get Validity Period To value
                        m_validityPeriodTo = Arrays.copyOfRange(m_biometricData, 28, 36);

                        //Convert Biometric data block (BDB) Length byte[] value to int
                        ByteBuffer wrapped = ByteBuffer.wrap(biometricDataBlockLengthBytes);
                        int biometricDataBlockLength = wrapped.getInt();

                        //Convert Signature block (SB) Length byte[] value to int
                        wrapped = ByteBuffer.wrap(signatureDataBlockLengthBytes);
                        int signatureDataBlockLength = (int) wrapped.getShort();

                        m_biometricDataBlock = Arrays.copyOfRange(m_biometricData, 88, 88 + biometricDataBlockLength);

                        byte[] signatureDataBlock = Arrays.copyOfRange(m_biometricData, 88 + biometricDataBlockLength, 88 + biometricDataBlockLength + signatureDataBlockLength);

                        //Decode the ContentInfo and get SignedData object from the signature block.
                        ByteArrayInputStream bIn = new ByteArrayInputStream(signatureDataBlock);
                        ASN1InputStream aIn = new ASN1InputStream(bIn);
                        ContentInfo ci = ContentInfo.getInstance(aIn.readObject());
                        m_signedData = new CMSSignedData(ci);
                    }
                }
            }
        }catch (Exception ex) {

            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }
        return true;
    }

    public boolean decodeFacialImage() {

        try
        {

            s_logger.debug("Facial Image Data: {}", Hex.encodeHexString(m_biometricData));

            byte[] cbeffHeader = Arrays.copyOfRange(m_biometricData, 0, 88);

            s_logger.debug("cbeffHeader: {}", Hex.encodeHexString(cbeffHeader));

            byte[] biometricDataBlockLengthBytes = Arrays.copyOfRange(m_biometricData, 2, 6);
            byte[] signatureDataBlockLengthBytes = Arrays.copyOfRange(m_biometricData, 6, 8);


            byte[] biometricCreationDate = Arrays.copyOfRange(m_biometricData, 12, 20);
            byte[] validityPeriodFrom = Arrays.copyOfRange(m_biometricData, 20, 28);
            byte[] validityPeriodTo = Arrays.copyOfRange(m_biometricData, 28, 36);



            s_logger.debug("biometricCreationDate: {}", new String(biometricCreationDate));
            s_logger.debug("biometricCreationDateHEX: {}", Hex.encodeHexString(biometricCreationDate));
            s_logger.debug("validityPeriodFrom: {}", new String(biometricCreationDate));
            s_logger.debug("validityPeriodFromHEX: {}", Hex.encodeHexString(biometricCreationDate));
            s_logger.debug("validityPeriodTo: {}", new String(biometricCreationDate));
            s_logger.debug("validityPeriodToHEX: {}", Hex.encodeHexString(biometricCreationDate));

            s_logger.debug("biometricDataBlockLengthBytes: {}", Hex.encodeHexString(biometricDataBlockLengthBytes));

            s_logger.debug("signatureDataBlockLengthBytes: {}", Hex.encodeHexString(signatureDataBlockLengthBytes));

            ByteBuffer wrapped = ByteBuffer.wrap(biometricDataBlockLengthBytes);
            int biometricDataBlockLength = wrapped.getInt();

            wrapped = ByteBuffer.wrap(signatureDataBlockLengthBytes);
            int signatureDataBlockLength = (int) wrapped.getShort();

            byte[] biometricDataBlock = Arrays.copyOfRange(m_biometricData, 88, 88+biometricDataBlockLength);

            s_logger.debug("biometricDataBlock: {}", Hex.encodeHexString(biometricDataBlock));

            byte[] signatureDataBlock = Arrays.copyOfRange(m_biometricData, 88+biometricDataBlockLength, 88+biometricDataBlockLength+signatureDataBlockLength);

            s_logger.debug("signatureDataBlock: {}", Hex.encodeHexString(signatureDataBlock));



        }catch (Exception ex) {

            s_logger.error("Error extracting signature from {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }

        return true;
    }
}
