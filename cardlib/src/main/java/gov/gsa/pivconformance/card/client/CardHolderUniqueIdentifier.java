package gov.gsa.pivconformance.card.client;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.text.SimpleDateFormat;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 *
 * Encapsulates a Card Holder Unique Identifier data object  as defined by SP800-73-4 Part 2 Appendix A Table 9
 *
 */
public class CardHolderUniqueIdentifier extends SignedPIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(CardHolderUniqueIdentifier.class);

    private byte[] m_bufferLength;
    private byte[] m_fASCN;
    private byte[] m_organizationalIdentifier;
    private byte[] m_dUNS;
    private byte[] m_gUID;
    private Date m_expirationDate;
    private byte[] m_cardholderUUID;
    private boolean m_errorDetectionCode;
    private byte[] m_chuidContainer;

    // TODO: Cache this 
    //HashMap<BerTag, byte[]> m_content;

    /**
     * CardCapabilityContainer class constructor, initializes all the class fields.
     */
    public CardHolderUniqueIdentifier() {
        super();
    	m_bufferLength = null;
        m_fASCN = null;
        m_organizationalIdentifier = null;
        m_dUNS = null;
        m_gUID = null;
        m_expirationDate = null;
        m_cardholderUUID = null;
        m_errorDetectionCode = false;
        m_chuidContainer = null;
        m_content = new HashMap<BerTag, byte[]>();
    }

    /**
     *
     * Returns Byte array with CHUID buffer
     *
     * @return Byte array with CHUID buffer
     */
    public byte[] getChuidContainer() {
        return m_chuidContainer;
    }

    /**
     *
     * Sets the CHUID value
     *
     * @param chuidContainer Byte array with CHUID value
     */
    public void setChuidContainer(byte[] chuidContainer) {
        m_chuidContainer = chuidContainer;
    }

    /**
     *
     * Returns buffer length value
     *
     * @return Byte array containing buffer length value
     */
    public byte[] getBufferLength() {
        return m_bufferLength;
    }

    /**
     *
     * Sets buffer length value
     *
     * @param bufferLength Byte array containing buffer length value
     */
    public void setBufferLength(byte[] bufferLength) {
        m_bufferLength = bufferLength;
    }


    /**
     *
     * Returns FASCN value
     *
     * @return Byte array containing FASCN value
     */
    public byte[] getfASCN() {
        return m_fASCN;
    }

    /**
     *
     * Sets the FASCN value
     *
     * @param fASCN Byte array containing FASCN value
     */
    public void setfASCN(byte[] fASCN) {
        m_fASCN = fASCN;
    }

    /**
     *
     * Returns byte array containing Organizational Identifier value
     *
     * @return Byte array containing Organizational Identifier value
     */
    public byte[] getOrganizationalIdentifier() {
        return m_organizationalIdentifier;
    }

    /**
     *
     * Sets Organizational Identifier value
     *
     * @param organizationalIdentifier Byte array containing Organizational Identifier value
     */
    public void setOrganizationalIdentifier(byte[] organizationalIdentifier) {
        m_organizationalIdentifier = organizationalIdentifier;
    }

    /**
     *
     * Returns DUNS value
     *
     * @return Byte array containing DUNS value
     */
    public byte[] getdUNS() {
        return m_dUNS;
    }

    /**
     *
     * Sets DUNS value
     *
     * @param dUNS Byte array containing DUNS value
     */
    public void setdUNS(byte[] dUNS) {
        m_dUNS = dUNS;
    }

    /**
     *
     * Returns byte array containing GUID value
     *
     * @return Byte array containing GUID value
     */
    public byte[] getgUID() {
        return m_gUID;
    }

    /**
     *
     * Sets the GUID value
     *
     * @param gUID Byte array containing GUID value
     */
    public void setgUID(byte[] gUID) {
        m_gUID = gUID;
    }

    /**
     *
     * Returns Expiration Date value
     *
     * @return Date object containing Expiration Date value
     */
    public Date getExpirationDate() {
        return m_expirationDate;
    }

    /**
     *
     * Sets  Expiration Date value
     *
     * @param expirationDate Date object containing Expiration Date value
     */
    public void setExpirationDate(Date expirationDate) {
        m_expirationDate = expirationDate;
    }

    /**
     *
     * Returns byte array containing Cardholder UUID value
     *
     * @return Byte array containing Cardholder UUID value
     */
    public byte[] getCardholderUUID() {
        return m_cardholderUUID;
    }

    /**
     *
     * Sets the Cardholder UUID value
     *
     * @param cardholderUUID Byte array containing Cardholder UUID value
     */
    public void setCardholderUUID(byte[] cardholderUUID) {
        m_cardholderUUID = cardholderUUID;
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
     * Decode function that decodes Card Holder Unique Identifier object retrieved from the card and populates various class fields.
     *
     * @return True if decode was successful, false otherwise
     */
    public boolean decode() {

    	SignerInformationStore signers = null;
    	SignerInformation signer = null;
    	
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

            boolean ecAdded = false;
            ByteArrayOutputStream signedContentOutputStream = new ByteArrayOutputStream();
            ByteArrayOutputStream containerOutputStream = new ByteArrayOutputStream();
            byte [] issuerAsymmetricSignature = null;

            List<BerTlv> values = outer.getList();
            for(BerTlv tlv : values) {
                if(tlv.isPrimitive()) {
                    s_logger.debug("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                    BerTlvs outer2 = tlvp.parse(tlv.getBytesValue());

                    if (outer2 == null) {
                        s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMAP.get(super.getOID()));
                        return false;
                    }

                    List<BerTlv> values2 = outer2.getList();
                    for (BerTlv tlv2 : values2) {
                        if (tlv2.isPrimitive()) {
                            s_logger.debug("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                        } else {
                        	
                        	BerTag tag = tlv2.getTag();
                        	byte[] value = tlv2.getBytesValue();
                        	
                        	// 2 deprecated tags that can't be part of the data model after we note them here
                        	
                            if (Arrays.equals(tag.bytes, TagConstants.BUFFER_LENGTH_TAG)) { // EE - Don't use in hash (don't add to digest input)
                                s_logger.warn("Deprecated tag: {} with value: {}", Hex.encodeHexString(tag.bytes), Hex.encodeHexString(value));
                            } else if (Arrays.equals(tag.bytes, TagConstants.DEPRECATED_AUTHENTICATION_KEY_MAP)) { // 3D - Don't use in hash (don't add to digest input)
                                s_logger.warn("Deprecated tag: {} with value: {}", Hex.encodeHexString(tag.bytes), Hex.encodeHexString(value));
                                m_tagList.add(tag); // TODO: Re-visit this strategy
                                signedContentOutputStream.write(APDUUtils.getTLV(tag.bytes, value));     
                            } else if (Arrays.equals(tag.bytes, TagConstants.FASC_N_TAG)) {
  
                            	m_fASCN = value;
                                m_content.put(tag, value);
                                m_tagList.add(tag);
                                if (m_fASCN != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.FASC_N_TAG, m_fASCN));

                            } else if (Arrays.equals(tag.bytes, TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG)) {

                                m_organizationalIdentifier = value;
                                m_content.put(tag, value);
                                m_tagList.add(tag);
                                if (m_organizationalIdentifier != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG, m_organizationalIdentifier));

                            } else if (Arrays.equals(tag.bytes, TagConstants.DUNS_TAG)) {

                                m_dUNS = value;
                                m_content.put(tag, value);
                                m_tagList.add(tag);
                                if (m_dUNS != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.DUNS_TAG, m_dUNS));

                            } else if (Arrays.equals(tag.bytes, TagConstants.GUID_TAG)) {

                                m_gUID = value;
                                m_content.put(tag, value);
                                m_tagList.add(tag);
                                if (m_gUID != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.GUID_TAG, m_gUID));

                            } else if (Arrays.equals(tag.bytes, TagConstants.CHUID_EXPIRATION_DATE_TAG)) {

                                String s = new String(value);
                                m_content.put(tag, value);
                                Date date = new SimpleDateFormat("yyyyMMdd").parse(s);
                                m_expirationDate = date;
                                m_tagList.add(tag);
                                if (m_expirationDate != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.CHUID_EXPIRATION_DATE_TAG, value));

                            } else if (Arrays.equals(tag.bytes, TagConstants.CARDHOLDER_UUID_TAG)) {

                                m_cardholderUUID = value;
                                m_content.put(tag, value);
                                m_tagList.add(tag);
                                if(m_cardholderUUID != null) {
                                    signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.CARDHOLDER_UUID_TAG, value));
                                }

                            } else if (Arrays.equals(tag.bytes, TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG)) {

                                issuerAsymmetricSignature = value;
                                m_content.put(tag, value);
                                m_tagList.add(tag);
                                if(issuerAsymmetricSignature != null) {                                
                                	//Decode the ContentInfo and get SignedData object.
                                    ByteArrayInputStream bIn = new ByteArrayInputStream(issuerAsymmetricSignature);
                                    ASN1InputStream aIn = new ASN1InputStream(bIn);
                                    // Set the ContentInfo structure in super class
                                    setContentInfo(ContentInfo.getInstance(aIn.readObject()));
                                    // Set the CMSSignedData object
                                    setAsymmetricSignature(new CMSSignedData(getContentInfo()));

                                    Store<X509CertificateHolder> certs = getAsymmetricSignature().getCertificates();
                                    signers = getAsymmetricSignature().getSignerInfos();

                                    for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
                                        signer = i.next();
                                        // Get signer cert
                                        Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
                                        Iterator<X509CertificateHolder> certIt = certCollection.iterator();
                                        if (certIt.hasNext()) {
                                            X509CertificateHolder certHolder = certIt.next();

                                            // Note that setSignerCert internally increments the cert bag counter. 
                                            // Using the getter, consumers can quickly determine if there were more
                                            // than one cert in PKCS7 cert bag and throw an exception.
                                            X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
                                            setSignerCert(cert);
                                            setHasOwnSignerCert(true);
                                            // Hang the CHUID signer cert here so that any test runner
                                            // consumer can access it.                        
                                            setChuidSignerCert(cert);
                                        }
                                    }
                                }

                            } else if (Arrays.equals(tag.bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {
                            	ecAdded = true;
                            	m_content.put(tag, value);
                                m_errorDetectionCode = true;
                            	m_tagList.add(tag);
                                signedContentOutputStream.write(APDUUtils.getTLV(tag.bytes, value));
                            } else {
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tag.bytes), Hex.encodeHexString(value));
                                // Unexpected tags (for future) - we could simply ignore
                                m_tagList.add(tag);
                                signedContentOutputStream.write(APDUUtils.getTLV(tag.bytes, value));
                            }
                        }
                    }
                }
            }

            containerOutputStream.write(signedContentOutputStream.toByteArray());
              
            // Append signature to full container output
            if(issuerAsymmetricSignature != null)
            	containerOutputStream.write(APDUUtils.getTLV(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG, issuerAsymmetricSignature));
            
            // Append EC if in the original
            if(ecAdded) {
            	containerOutputStream.write(TagConstants.ERROR_DETECTION_CODE_TAG);
            	containerOutputStream.write((byte) 0x00);
            }
            
            setSigned(true);
            setSignedContent(signedContentOutputStream.toByteArray());
            // Grab signed digest
            setSignedAttrsDigest(signers);
            // Precompute digest but don't compare -- let consumers do that
            setComputedDigest(signer, getSignedContent());

            m_chuidContainer = containerOutputStream.toByteArray();

        } catch (Exception ex) {
            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }

        if(m_fASCN == null || m_gUID == null || m_expirationDate == null || m_chuidContainer == null) {
            return false;
        }

        return true;
    }
}

