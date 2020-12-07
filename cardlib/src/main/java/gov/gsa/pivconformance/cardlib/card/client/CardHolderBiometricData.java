package gov.gsa.pivconformance.cardlib.card.client;

import gov.gsa.pivconformance.cardlib.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Iterator;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.Store;

import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

/**
 *
 * Container class that parses and stores information about Biometric Data elements.  Biometric Data elements include Cardholder Fingerprints,
 * Cardholder Facial Image and  Cardholder Iris Image as defined by SP800-73-4 Part 2 Appendix A Table 11, Table 13 and Table 40
 *
 */
public class CardHolderBiometricData extends SignedPIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(CardHolderBiometricData.class);

    private byte[] m_biometricData;
    private String m_biometricCreationDate;
    private boolean m_errorDetectionCode;
    private String m_validityPeriodFrom;
    private String m_validityPeriodTo;
    private byte[] m_biometricDataBlock;
    private byte[] m_signatureBlock;
    private byte[] m_cbeffContainer;

    /**
     * CardholderBiometricData class constructor, initializes all the class fields.
     */
    public CardHolderBiometricData() {
    	super();
        m_biometricData = null;
        m_errorDetectionCode = false;
        m_biometricCreationDate = null;
        m_validityPeriodFrom = null;
        m_validityPeriodTo = null;
        m_biometricDataBlock = null;
        m_signatureBlock = null;
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
    @Override
	public boolean getErrorDetectionCode() {
        return m_errorDetectionCode;
    }

    /**
     *
     * Sets if error detection code is present
     *
     * @param errorDetectionCode Boolean indicating if error detection code is present
     */
    @Override
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
     * Decode function that decodes biometric data object retrieved from the card and populates various class fields.
     *
     * @return True if decode was successful, false otherwise
     */
    @Override
	public boolean decode() {

    	boolean certFound = false;        
        ByteArrayOutputStream signedContentOutputStream = new ByteArrayOutputStream();
        SignerInformationStore signers = null;
        SignerInformation signer = null;
        try {
            byte[] rawBytes = this.getBytes();

            s_logger.trace("rawBytes: {}", Hex.encodeHexString(rawBytes));

            if(rawBytes == null){
                s_logger.error("No buffer to decode for {}.", APDUConstants.oidNameMap.get(super.getOID()));
                return false;
            }

            BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
            BerTlvs outer = tlvp.parse(rawBytes);

            if(outer == null){
                s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMap.get(super.getOID()));
                return false;
            }
            
            List<BerTlv> values = outer.getList();
            for(BerTlv tlv : values) {
                if(tlv.isPrimitive()) {
                    s_logger.trace("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                    BerTlvs outer2 = tlvp.parse(tlv.getBytesValue());

                    if (outer2 == null) {
                        s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMap.get(super.getOID()));
                        return false;
                    }

                    List<BerTlv> values2 = outer2.getList();
                    for (BerTlv tlv2 : values2) {
                        if (tlv2.isPrimitive()) {
                            s_logger.trace("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                        } else {
                        	BerTag tag = tlv2.getTag();
                        	byte[] value = tlv2.getBytesValue();

                        	super.m_tagList.add(tag);
                            if (Arrays.equals(tag.bytes, TagConstants.FINGERPRINT_I_AND_II_TAG) && getOID().compareTo(APDUConstants.CARDHOLDER_FINGERPRINTS_OID) == 0) {

                            	super.setContainerName("CardholderFingerprints");
                                m_biometricData = value;
                                m_content.put(tag, value);
                                if (m_biometricData != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.FINGERPRINT_I_AND_II_TAG, m_biometricData));

                            } else if (Arrays.equals(tag.bytes, TagConstants.IMAGE_FOR_VISUAL_VERIFICATION_TAG) && getOID().compareTo(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID) == 0) {

                            	setContainerName("CardholderFacialImage");
                                m_biometricData = value;
                                m_content.put(tag, value);
                               if (m_biometricData != null)
                            	   signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.IMAGE_FOR_VISUAL_VERIFICATION_TAG, m_biometricData));

                            } else if (Arrays.equals(tag.bytes, TagConstants.IMAGES_FOR_IRIS_TAG) && getOID().compareTo(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID) == 0) {

                            	setContainerName("CardholderIrisImages");
                                m_biometricData = value;
                                m_content.put(tag, value);
                                if (m_biometricData != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.IMAGES_FOR_IRIS_TAG, m_biometricData));

                            } else if (Arrays.equals(tag.bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {

                                m_errorDetectionCode = true;
                                m_content.put(tag, value);
                                if (m_biometricData != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.ERROR_DETECTION_CODE_TAG, value));

                            } else {
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tag.bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            }
                            m_cbeffContainer = signedContentOutputStream.toByteArray();
                        }
                    }

                    // Break BC tag into Patron CBEFF header + BDB + SB
                    if (m_biometricData != null) {
                        s_logger.info("m_biometricData: {}", Hex.encodeHexString(m_biometricData));
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
                        int signatureDataBlockLength = wrapped.getShort();


                        m_biometricDataBlock = Arrays.copyOfRange(m_biometricData, 88, 88 + biometricDataBlockLength);

                        m_signatureBlock = Arrays.copyOfRange(m_biometricData, 88 + biometricDataBlockLength, 88 + biometricDataBlockLength + signatureDataBlockLength);
         			
                        // Decode the ContentInfo and get SignedData objects.
                        ByteArrayInputStream bIn = new ByteArrayInputStream(m_signatureBlock);
                        ASN1InputStream      aIn = new ASN1InputStream(bIn);                      
                        // Set the ContentInfo structure in super class
                        setContentInfo(ContentInfo.getInstance(aIn.readObject())); aIn.close();
                        // Set the CMSSignedData object
                        setAsymmetricSignature(new CMSSignedData(getContentInfo()));
                        // Finally, see if there's a separate signer cert
                        CMSSignedData cmsSignedData = getAsymmetricSignature();
                        
                        if(cmsSignedData != null) {
                        	signers = cmsSignedData.getSignerInfos();

                        	for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
                        		signer = i.next();                               
                        	}

                            // The biometric data block is the detached signed content
                            setSignedContent(Arrays.copyOfRange(m_biometricData, 0, 88 + biometricDataBlockLength));
                            // Grab signed digest
                            setSignedAttrsDigest(signers);
                            // Precompute digest but don't compare -- let consumers do that
                            setComputedDigest(signer, getSignedContent());        
                            // Indicate this object needs a signature verification
                            setSigned(true);
            			
                            //Decode the ContentInfo and get SignedData object.
                            Store<X509CertificateHolder> certs = cmsSignedData.getCertificates();
                            signers = cmsSignedData.getSignerInfos();
                            for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext(); ) {
                                signer = i.next();
                                setDigestAlgorithmName(Algorithm.digAlgOidToNameMap.get(signer.getDigestAlgOID()));
                                setEncryptionAlgorithmName(Algorithm.encAlgOidToNameMap.get(signer.getEncryptionAlgOID()));
                                @SuppressWarnings("unchecked")
								Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
                                Iterator<X509CertificateHolder> certIt = certCollection.iterator();
                                if (certIt.hasNext()) {
                                    X509CertificateHolder certHolder = certIt.next();
                                    // Note that setSignerCert internally increments a counter. If there are more than one
                                    // cert in PKCS7 cert bags then the consumer class should throw an exception.
                                    X509Certificate signerCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
                                    if (signerCert != null) {
                                    	setSignerCert(signerCert);
                                    	setHasOwnSignerCert(true);
                                    	certFound = true;
                                    	// Extract signer's signature algorithm name and hang on to it.
                                    	setSignatureAlgorithmName(signerCert.getSigAlgName());
                                    } else {
                                    	s_logger.error("Can't extract signer certificate");
                                    }
                                }
                            }
                        } else {
                        	s_logger.error("Null CMSSignedData");
                        }
                    }
                }
            }
        } catch (Exception ex) {
            s_logger.error("Error parsing {}", APDUConstants.oidNameMap.get(super.getOID()), ex);
            return false;
        }

        String message = APDUConstants.oidNameMap.get(super.getOID()) + (certFound ? " had" : " did not have") + " an embedded certificate";
        s_logger.trace(message);
        
        if(m_biometricData == null)
            return false;

        dump(this.getClass());
        return true;
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
