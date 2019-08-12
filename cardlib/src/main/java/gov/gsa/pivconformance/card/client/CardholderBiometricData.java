package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Iterator;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import org.bouncycastle.util.Store;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

/**
 *
 * Container class that parses and stores information about Biometric Data elements.  Biometric Data elements include Cardholder Fingerprints,
 * Cardholder Facial Image and  Cardholder Iris Image as defined by SP800-73-4 Part 2 Appendix A Table 11, Table 13 and Table 40
 *
 */
public class CardholderBiometricData extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(CardholderBiometricData.class);

    private byte[] m_biometricData;
    private String m_biometricCreationDate;
    private boolean m_errorDetectionCode;
    private String m_validityPeriodFrom;
    private String m_validityPeriodTo;
    private byte[] m_biometricDataBlock;
    private byte[] m_signatureBlock;
    private CMSSignedData m_signedData;
    private ContentInfo m_contentInfo;
    private byte[] m_signedContent;
    private byte[] m_cbeffContainer;

    /**
     * CardholderBiometricData class constructor, initializes all the class fields.
     */
    public CardholderBiometricData() {
        m_biometricData = null;
        m_errorDetectionCode = false;
        m_biometricCreationDate = null;
        m_validityPeriodFrom = null;
        m_validityPeriodTo = null;
        m_signedData = null;
        m_biometricDataBlock = null;
        m_signatureBlock = null;
        m_contentInfo = null;
        m_signedContent = null;
        m_cbeffContainer = null;
        m_content = new HashMap<BerTag, byte[]>();
    }

    /**
     *
     * Returns the CBEFF container value
     *
     * @return Byte array with CBEFF container value
     */
    public byte[] getCbeffContainer() {
        return m_cbeffContainer;
    }

    /**
     *
     * Sets the CBEFF container value
     *
     * @param cbeffContainer Byte array with CBEFF container value
     */
    public void setCbeffContainer(byte[] cbeffContainer) {
        m_cbeffContainer = cbeffContainer;
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
     * Returns the ContentInfo object
     *
     * @return ContentInfo object
     */
    public ContentInfo getContentInfo() {
        return m_contentInfo;
    }

    /**
     *
     * Sets the ContentInfo object
     *
     * @param contentInfo ContentInfo object
     */
    public void setContentInfo(ContentInfo contentInfo) {
        m_contentInfo = contentInfo;
    }

    /**
     *
     * Returns a byte array with biometric data
     *
     * @return Byte array with biometric data
     */
    public byte[] getBiometricData() {
        return m_biometricData;
    }

    /**
     *
     * Returns a byte array with the CMS
     *
     * @return Byte array with CMS
     */
    public byte[] getSignatureBlock() {
        return m_signatureBlock;
    }
    /**
     *
     * Sets the biometric data
     *
     * @param biometricData Byte array with biometric data
     */
    public void setBiometricData(byte[] biometricData) {
        m_biometricData = biometricData;
    }

    /**
     *
     * Returns true if error detection code is present, false otherwise
     *
     * @return Returns true if error detection code is present, false otherwise
     */
    public boolean getErrorDetectionCode() {
        return m_errorDetectionCode;
    }

    /**
     *
     * Sets if error detection code is present
     *
     * @param errorDetectionCode Boolean indicating if error detection code is present
     */
    public void setErrorDetectionCode(boolean errorDetectionCode) {
        m_errorDetectionCode = errorDetectionCode;
    }


    /**
     *
     * Returns biometric creation date value
     *
     * @return String indicating biometric creation date
     */
    public String getBiometricCreationDate() {
        return m_biometricCreationDate;
    }

    /**
     *
     * Sets the biometric creation date
     *
     * @param biometricCreationDate String indicating biometric creation date
     */
    public void setBiometricCreationDate(String biometricCreationDate) {
        m_biometricCreationDate = biometricCreationDate;
    }

    /**
     *
     * Returns the biometric data block
     *
     * @return Byte array containing biometric data block
     */
    public byte[] getBiometricDataBlock() {
        return m_biometricDataBlock;
    }

    /**
     *
     * Sets the biometric data block
     *
     * @param biometricDataBlock Byte array containing biometric data block
     */
    public void setBiometricDataBlock(byte[] biometricDataBlock) {
        m_biometricDataBlock = biometricDataBlock;
    }

    /**
     *
     * Returns the validity preriod from value
     *
     * @return String indicating validity from value
     */
    public String getValidityPeriodFrom() {
        return m_validityPeriodFrom;
    }

    /**
     *
     * Sets the validity from value
     *
     * @param validityPeriodFrom String indicating validity from value
     */
    public void setValidityPeriodFrom(String validityPeriodFrom) {
        m_validityPeriodFrom = validityPeriodFrom;
    }

    /**
     *
     * Returns the validity preriod to value
     *
     * @return String indicating validity to value
     */
    public String getValidityPeriodTo() {
        return m_validityPeriodTo;
    }

    /**
     *
     * Sets the validity from value
     *
     * @param validityPeriodTo String indicating validity from value
     */
    public void setValidityPeriodTo(String validityPeriodTo) {
        m_validityPeriodTo = validityPeriodTo;
    }

    /**
     *
     * Returns the CMSSignedData object
     *
     * @return CMSSignedData object
     */
    public CMSSignedData getSignedData() {
        return m_signedData;
    }

    /**
     *
     * Sets the CMSSignedData object
     *
     * @param signedData CMSSignedData object
     */
    public void setSignedData(CMSSignedData signedData) {
        m_signedData = signedData;
    }


    /**
     *
     * Decode function that decodes biometric data object retrieved from the card and populates various class fields.
     *
     * @return True if decode was successful, false otherwise
     */
    public boolean decode() {

    	boolean certFound = false;

        try {
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
                    s_logger.debug("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                    BerTlvs outer2 = tlvp.parse(tlv.getBytesValue());

                    if (outer2 == null) {
                        s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMAP.get(super.getOID()));
                        return false;
                    }
                    
                    ByteArrayOutputStream signedContentOutputStream = new ByteArrayOutputStream();

                    List<BerTlv> values2 = outer2.getList();
                    for (BerTlv tlv2 : values2) {
                        if (tlv2.isPrimitive()) {
                            s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                        } else {
                        	BerTag tag = tlv2.getTag();
                        	byte[] value = tlv2.getBytesValue();

                        	super.m_tagList.add(tag);
                            if (Arrays.equals(tag.bytes, TagConstants.FINGERPRINT_I_AND_II_TAG)) {

                                m_biometricData = value;
                                m_content.put(tag, value);
                                if (m_biometricData != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.FINGERPRINT_I_AND_II_TAG, m_biometricData));

                            } else if (Arrays.equals(tag.bytes, TagConstants.IMAGE_FOR_VISUAL_VERIFICATION_TAG)) {

                                m_biometricData = value;
                                m_content.put(tag, value);
                               if (m_biometricData != null)
                            	   signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.IMAGE_FOR_VISUAL_VERIFICATION_TAG, m_biometricData));

                            } else if (Arrays.equals(tag.bytes, TagConstants.IMAGES_FOR_IRIS_TAG)) {

                                m_biometricData = value;
                                m_content.put(tag, value);
                                if (m_biometricData != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.IMAGES_FOR_IRIS_TAG, m_biometricData));

                            } else if (Arrays.equals(tag.bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {

                                m_errorDetectionCode = true;
                                m_content.put(tag, value);
                                signedContentOutputStream.write(APDUUtils.getTLV(tag.bytes, value));
                            } else {
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tag.bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }

                            m_cbeffContainer = signedContentOutputStream.toByteArray();
                        }
                    }

                    // Break BC tag into Patron CBEFF header + BDB + SB
                    if (m_biometricData != null) {
                        s_logger.debug("m_biometricData: {}", Hex.encodeHexString(m_biometricData));
                        //Get Biometric data block (BDB) Length
                        byte[] biometricDataBlockLengthBytes = Arrays.copyOfRange(m_biometricData, 2, 6);
                        //Get Signature block (SB) Length
                        byte[] signatureDataBlockLengthBytes = Arrays.copyOfRange(m_biometricData, 6, 8);

                        //Get Biometric Creation Date
                        m_biometricCreationDate = BytesToDateString(Arrays.copyOfRange(m_biometricData, 12, 20));
                        //Get Validity Period From value
                        m_validityPeriodFrom = BytesToDateString(Arrays.copyOfRange(m_biometricData, 20, 28));
                        //Get Validity Period To value
                        m_validityPeriodTo = BytesToDateString(Arrays.copyOfRange(m_biometricData, 28, 36));

                        //Convert Biometric data block (BDB) Length byte[] value to int
                        ByteBuffer wrapped = ByteBuffer.wrap(biometricDataBlockLengthBytes);
                        int biometricDataBlockLength = wrapped.getInt();

                        //Convert Signature block (SB) Length byte[] value to int
                        wrapped = ByteBuffer.wrap(signatureDataBlockLengthBytes);
                        int signatureDataBlockLength = (int) wrapped.getShort();

                        m_signedContent = Arrays.copyOfRange(m_biometricData, 0, 88 + biometricDataBlockLength - 4);

                        m_biometricDataBlock = Arrays.copyOfRange(m_biometricData, 88, 88 + biometricDataBlockLength);

                        m_signatureBlock = Arrays.copyOfRange(m_biometricData, 88 + biometricDataBlockLength, 88 + biometricDataBlockLength + signatureDataBlockLength);

                        //Decode the ContentInfo and get SignedData object.
                        ByteArrayInputStream bIn = new ByteArrayInputStream(m_signatureBlock);
                        ASN1InputStream aIn = new ASN1InputStream(bIn);
                        m_contentInfo = ContentInfo.getInstance(aIn.readObject()); aIn.close();  			

                        CMSSignedData s = new CMSSignedData(m_signatureBlock);
            			if (s.isDetachedSignature()) {
            				CMSProcessableByteArray procesableContentBytes = new CMSProcessableByteArray(m_signedContent);
            				s = new CMSSignedData(procesableContentBytes, m_signatureBlock);
            			}
            			
            			m_signedData = s;
                        
                        if(m_signedData != null) {
                            //Decode the ContentInfo and get SignedData object.
                            try {
                                Security.addProvider(new BouncyCastleProvider());
                            } catch (Exception e) {
                                s_logger.error("Unable to add provider for signature verification: {}" , e.getMessage());
                                return false;
                            }
                            Store<X509CertificateHolder> certs = m_signedData.getCertificates();
                            SignerInformationStore signers = m_signedData.getSignerInfos();

                            for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext(); ) {
                                SignerInformation signer = i.next();
                                Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
                                Iterator<X509CertificateHolder> certIt = certCollection.iterator();
                                if (certIt.hasNext()) {
                                    X509CertificateHolder certHolder = certIt.next();

                                    // Note that setSignerCert internally increments a counter. If there are more than one
                                    // cert in PKCS7 cert bags then the consumer class should throw an exception.

                                    super.setSignerCert(new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder));
                                    super.setHasOwnSignerCert(true);
                                    certFound = true;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception ex) {

            s_logger.error("Error parsing {}", APDUConstants.oidNameMAP.get(super.getOID()), ex);
            return false;
        }

        super.setSigned(true);
        // This gets set in case hasOwnSignerCert() is false
        super.setChuidSignerCert(DataModelSingleton.getInstance().getChuidSignerCert());
        
        String message = APDUConstants.oidNameMAP.get(super.getOID()) + (certFound ? " had" : " did not have") + " an embedded certificate";
        s_logger.debug(message);
        
        if(m_biometricData == null)
            return false;

        return true;
    }

    /**
     *
     * Verifies the signature on the biometric data object
     *
     * @param signingCertificate X509Certificate object containing signing certificate
     * @return True if signature successfully verified, false otherwise
     */
    public boolean verifySignature(X509Certificate signingCertificate) {
        boolean rv_result = false;

        if(signingCertificate == null) {
            s_logger.error("Signing certificate is not provided for {}", APDUConstants.oidNameMAP.get(super.getOID()));
        }

        try {
            Security.addProvider(new BouncyCastleProvider());
        } catch (Exception e) {
            s_logger.error("Unable to add provider for signature verification: {}" , e.getMessage());
            return rv_result;
        }

        CMSSignedData s;
        try {
            s = new CMSSignedData(m_contentInfo);
            if (m_signedData.isDetachedSignature()) {
                CMSProcessable procesableContentBytes = new CMSProcessableByteArray(m_signedContent);
                s = new CMSSignedData(procesableContentBytes, m_contentInfo);
            }

            Store<X509CertificateHolder> certs = s.getCertificates();
            SignerInformationStore signers = s.getSignerInfos();
            X509Certificate signingCert = null;

            for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
                SignerInformation signer = i.next();

                Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
                Iterator<X509CertificateHolder> certIt = certCollection.iterator();
                if (certIt.hasNext()) {
                    X509CertificateHolder certHolder = certIt.next();
                    signingCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
                }
                else if(signingCertificate != null) {
                    signingCert = signingCertificate;
                }
                else {
                    s_logger.error("Missing signing certificate to verify signature on {}", APDUConstants.oidNameMAP.get(super.getOID()));
                    rv_result = false;
                    return rv_result;
                }

                try {
                    if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signingCert))) {
                        rv_result = true;
                    }
                } catch (CMSSignerDigestMismatchException e) {
                    s_logger.error("Message digest attribute value does not match calculated value for {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
                } catch (OperatorCreationException | CMSException e) {
                    s_logger.error("Error verifying signature on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
                }
            }
        } catch ( Exception ex) {
            s_logger.error("Error verifying signature on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }

        return rv_result;
    }


    /**
     *
     * Helper function that converts byte array to a date string
     *
     * @param buf  Byte array to be converted
     * @return String containing date value
     */
    private String BytesToDateString(byte[] buf) {
        if((char)buf[buf.length-1] != 'Z') {
            throw new IllegalArgumentException("bcd byte array doesn't end with Z");
        }
        StringBuilder outsb = new StringBuilder();
        for( int i = 0; i < buf.length-1; ++i ) {
            int digits = buf[i] & 0xFF;
            outsb.append(String.format("%02d", digits));
        }
        outsb.append('Z');
        return outsb.toString();
    }
}
