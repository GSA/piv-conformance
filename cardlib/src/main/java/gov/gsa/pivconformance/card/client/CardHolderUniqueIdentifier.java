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
    private CMSSignedData m_issuerAsymmetricSignature;
    private boolean m_errorDetectionCode;
    private ContentInfo m_contentInfo;
    X509Certificate m_signingCertificate;
    private byte[] m_signedContent;
    private byte[] m_chuidContainer;

    // TODO: Cache this 
    //HashMap<BerTag, byte[]> m_content;

    /**
     * CardCapabilityContainer class constructor, initializes all the class fields.
     */
    public CardHolderUniqueIdentifier() {
        m_bufferLength = null;
        m_fASCN = null;
        m_organizationalIdentifier = null;
        m_dUNS = null;
        m_gUID = null;
        m_expirationDate = null;
        m_cardholderUUID = null;
        m_issuerAsymmetricSignature = null;
        m_errorDetectionCode = false;
        m_contentInfo = null;
        m_signingCertificate = null;
        m_signedContent = null;
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
     * Returns the signing certificate in X509Certificate object
     *
     * @return X509Certificate object containing the signing certificate
     */
    public X509Certificate getSignerCert() {
        return m_signingCertificate;
    }

    /**
     *
     * Sets the signing certificate
     *
     * @param signingCertificate X509Certificate object containing the signing certificate
     */
    public void setSignerCert(X509Certificate signingCertificate) {
        m_signingCertificate = signingCertificate;
    }

    /**
     *
     * Returns ContentInfo object
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
     * Returns CMSSignedData object containing Issuer Asymmetric Signature value
     *
     * @return CMSSignedData object containing Issuer Asymmetric Signature value
     */
    public CMSSignedData getIssuerAsymmetricSignature() {
        return m_issuerAsymmetricSignature;
    }

    /**
     *
     * Sets the CMSSignedData object containing Issuer Asymmetric Signature value
     *
     * @param issuerAsymmetricSignature CMSSignedData object containing Issuer Asymmetric Signature value
     */
    public void setIssuerAsymmetricSignature(CMSSignedData issuerAsymmetricSignature) {
        m_issuerAsymmetricSignature = issuerAsymmetricSignature;
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
                                super.m_tagList.add(tag); // TODO: Re-visit this strategy
                                signedContentOutputStream.write(APDUUtils.getTLV(tag.bytes, value));     
                            } else if (Arrays.equals(tag.bytes, TagConstants.FASC_N_TAG)) {
  
                            	m_fASCN = value;
                                m_content.put(tag, value);
                                super.m_tagList.add(tag);
                                if (m_fASCN != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.FASC_N_TAG, m_fASCN));

                            } else if (Arrays.equals(tag.bytes, TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG)) {

                                m_organizationalIdentifier = value;
                                m_content.put(tag, value);
                                super.m_tagList.add(tag);
                                if (m_organizationalIdentifier != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG, m_organizationalIdentifier));

                            } else if (Arrays.equals(tag.bytes, TagConstants.DUNS_TAG)) {

                                m_dUNS = value;
                                m_content.put(tag, value);
                                super.m_tagList.add(tag);
                                if (m_dUNS != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.DUNS_TAG, m_dUNS));

                            } else if (Arrays.equals(tag.bytes, TagConstants.GUID_TAG)) {

                                m_gUID = value;
                                m_content.put(tag, value);
                                super.m_tagList.add(tag);
                                if (m_gUID != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.GUID_TAG, m_gUID));

                            } else if (Arrays.equals(tag.bytes, TagConstants.CHUID_EXPIRATION_DATE_TAG)) {

                                String s = new String(value);
                                m_content.put(tag, value);
                                Date date = new SimpleDateFormat("yyyyMMdd").parse(s);
                                m_expirationDate = date;
                                super.m_tagList.add(tag);
                                if (m_expirationDate != null)
                                	signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.CHUID_EXPIRATION_DATE_TAG, value));

                            } else if (Arrays.equals(tag.bytes, TagConstants.CARDHOLDER_UUID_TAG)) {

                                m_cardholderUUID = value;
                                m_content.put(tag, value);
                                super.m_tagList.add(tag);
                                if(m_cardholderUUID != null) {
                                    signedContentOutputStream.write(APDUUtils.getTLV(TagConstants.CARDHOLDER_UUID_TAG, value));
                                }

                            } else if (Arrays.equals(tag.bytes, TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG)) {

                                issuerAsymmetricSignature = value;
                                m_content.put(tag, value);
                                super.m_tagList.add(tag);
                                if(issuerAsymmetricSignature != null) {
                                    //Decode the ContentInfo and get SignedData object.
                                    ByteArrayInputStream bIn = new ByteArrayInputStream(issuerAsymmetricSignature);
                                    ASN1InputStream aIn = new ASN1InputStream(bIn);
                                    m_contentInfo = ContentInfo.getInstance(aIn.readObject());
                                    m_issuerAsymmetricSignature = new CMSSignedData(m_contentInfo);
                                    
                                    try {
                                        Security.addProvider(new BouncyCastleProvider());
                                    } catch (Exception e) {
                                        s_logger.error("Unable to add provider for signature verification: {}" , e.getMessage());
                                        return false;
                                    }
                                    Store<X509CertificateHolder> certs = m_issuerAsymmetricSignature.getCertificates();
                                    signers = m_issuerAsymmetricSignature.getSignerInfos();

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
                                            super.setSignerCert(cert);
                                            // Hang the CHUID signer cert here so that any test runner
                                            // consumer can access it.                        
                                            super.setChuidSignerCert(cert);
                                        }
                                    }
                                }

                            } else if (Arrays.equals(tag.bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {
                            	ecAdded = true;
                            	m_content.put(tag, value);
                                m_errorDetectionCode = true;
                            	super.m_tagList.add(tag);
                                signedContentOutputStream.write(APDUUtils.getTLV(tag.bytes, value));
                            } else {
                                s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tag.bytes), Hex.encodeHexString(value));
                                // Unexpected tags (for future) - we could simply ignore
                                super.m_tagList.add(tag);
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
            
            super.setSigned(true);
            this.setSignedContent(signedContentOutputStream.toByteArray());
            // Grab signed digest
            this.setSignedAttrsDigest(signers);
            // Precompute digest but don't compare -- let consumers do that
            this.setComputedDigest(signer);

            m_chuidContainer = this.getSignedContent();

        } catch (Exception ex) {
            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }

        if(m_fASCN == null || m_gUID == null || m_expirationDate == null ||
                m_issuerAsymmetricSignature == null) {
            return false;
        }

        return true;
    }
    
	/**
	 * Gets the precomputed message digest for the content
	 * 
	 * @return bytes in the digest
	 */
    	
	public byte[] getSignedAttrsDigest() {
		return super.getSignedAttrsDigest();
	}
    
	/**
	 * Extracts and sets the message digest algorithm and message digest in the signed attributes
	 * 
	 * @param the SignerInformationStore in the CMS
	 * 
	 */	
	private void setSignedAttrsDigest(SignerInformationStore signers) {
    	if (m_issuerAsymmetricSignature != null) {
			if (signers != null) {
				AttributeTable at = null;
				MessageDigest md = null;
				// Temporarily nest these until unit test passes
				for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
					SignerInformation signer = i.next();
					AlgorithmIdentifier aid = signer.getDigestAlgorithmID(); 
		            try {
						md = MessageDigest.getInstance(aid.getAlgorithm().toString(), "BC");
						// Set digest name for later signature verification
						super.setDigestAlgorithmName(md.getAlgorithm());
						s_logger.debug("Digest Algorithm is " + super.getDigestAlgorithmName());
					} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
						s_logger.error("Could not instantiate Digest Algorithm " + aid.getAlgorithm().toString());
						e.printStackTrace();
					} catch (Exception e1) {
						// TODO handle 
						e1.printStackTrace();
					}

					at = signer.getSignedAttributes();	
					if (at != null) {
						Attribute a = at.get(CMSAttributes.messageDigest);
						if (a != null) {
							DEROctetString dos = (DEROctetString) a.getAttrValues().getObjectAt(0);
							if (dos != null) {
								byte[] digest = dos.getOctets();
								if (digest != null) {
									// Set message digest extracted from signed attributes
									super.setSignedAttrsDigest(digest);
									s_logger.debug("Signed attribute digest: " + Hex.encodeHexString(digest));
								} else {
									s_logger.error("Failed to compute digest");
								}
							} else {
								s_logger.error("Failed to decode octets");
							}
						} else {
							s_logger.error("Null messageDigest attribute");
						}
					} else {
						s_logger.error("Null signed attribute set");
					}
				} // End for
			} else {
				s_logger.error("Null SignerInfos");
			}
    	}
    }
	
    /**
     * Computes and sets the digest
     * 
     * @param the SignerInfo of the content signer
     * 
     * @returns the bytes of the digest
     */

	private void setComputedDigest(SignerInformation signer) {
		if (m_issuerAsymmetricSignature != null) {
			try {
				AttributeTable at = signer.getSignedAttributes();	
				if (at != null) {
					Attribute a = at.get(CMSAttributes.messageDigest);
					if (a != null) {
						byte[] contentBytes = this.getSignedContent();

						if (contentBytes != null) {
							s_logger.debug("Content bytes: " + Hex.encodeHexString(contentBytes));
							String aName = MessageDigestUtils.getDigestName(new ASN1ObjectIdentifier(signer.getDigestAlgOID()));
							MessageDigest md = MessageDigest.getInstance(aName, "BC");
							md.update(contentBytes);
							byte[] digest = md.digest();
							if (digest != null) {
								super.setComputedDigest(digest);
								s_logger.debug("Computed digest: " + Hex.encodeHexString(digest));
							} else {
								s_logger.error("Failed to digest content");
							}
						} else {
							s_logger.error("Null contentBytes");
						}
					} else {
						s_logger.error("Null messageDigest attribute");
					}
				} else {
					s_logger.error("Null signed attribute set");
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

    /**
     *
     * Verifies the signature on the Card Holder Unique Identifier object.  No signing certificate parameter is needed because it is included in the SignedData
     *
     * @return True if signature successfully verified, false otherwise
     */
    public boolean verifySignature() {
        boolean rv_result = false;

        s_logger.debug("m_signedContent HEX value: {} ", Hex.encodeHexString(m_signedContent));

        try {
        	//TODO: Need to be replaced with digest alg from the digestAlgorithms attribute
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            md.update(m_signedContent);

            byte[] digest = md.digest();

            s_logger.debug("message digest value: {} ", Hex.encodeHexString(digest));
        } catch (Exception ex) {
            s_logger.error("Error calculating hash value: {}", ex.getMessage());
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

            if (m_issuerAsymmetricSignature.isDetachedSignature()) {
                CMSProcessable procesableContentBytes = new CMSProcessableByteArray(m_signedContent);
                s = new CMSSignedData(procesableContentBytes, m_contentInfo);
            }

            Store<X509CertificateHolder> certs = s.getCertificates();
            SignerInformationStore signers = s.getSignerInfos();
            String ct = s.getSignedContent().getContentType().toString();

            for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
                SignerInformation signer = i.next();
                X509Certificate signerCert = null;

                Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
                Iterator<X509CertificateHolder> certIt = certCollection.iterator();
                if (certIt.hasNext()) {
                    X509CertificateHolder certHolder = certIt.next();
                    signerCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
                }

                if(signerCert == null)
                    s_logger.error("Unable to find signing certificate for {}", APDUConstants.oidNameMAP.get(super.getOID()));

                try {
                    if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCert))) {
                        rv_result = true;
                    }
                } catch (CMSSignerDigestMismatchException e) {
                    s_logger.error("Message digest attribute value does not match calculated value for {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
                } catch (OperatorCreationException | CMSException e) {
                    s_logger.error("Error verifying signature on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
                }
            }
        } catch (CMSException | CertificateException ex) {
            s_logger.error("Error verifying signature on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
            return false;
        }

        return rv_result;
    }
}
