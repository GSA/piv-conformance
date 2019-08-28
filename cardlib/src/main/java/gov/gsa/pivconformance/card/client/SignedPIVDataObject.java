/**
 * 
 */
package gov.gsa.pivconformance.card.client;

import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Bob.Fontana
 *
 */
public class SignedPIVDataObject extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PIVDataObject.class);
    private CMSSignedData m_asymmetricSignature;
    private ContentInfo m_contentInfo;
    //private X509Certificate m_signingCertificate;
    // The raw data over which the message digest shall be computed
    private byte[] m_signedContent;
    // The effective signing cert.
	private X509Certificate m_signerCert;
	// This is always here (via DataModelSingleton) and is the default used by a consumer if m_hasOwnSignerCert is false
	private X509Certificate m_chuidSignerCert;
	// This will be zero or one, and reflects the number of certs in this object
	private int m_signerCertCount;
	// This will be true *only* when this object has its own cert
	private boolean m_hasOwnSignerCert;
	// Prefetch
	private byte[] m_signedAttrsDigest;
	private byte[] m_computedDigest;
	private String m_digestAlgorithmName;

	public SignedPIVDataObject() {
		super();
		// TODO: Add code to pull the CHUID signing cert as standard signed PIV data object processing
		m_signerCert = null;
		m_signerCertCount = 0;
		m_hasOwnSignerCert = false;
		m_signedAttrsDigest = null;
		m_computedDigest = null;
		m_digestAlgorithmName = null;
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
        return (m_signerCert != null) ? m_signerCert : m_chuidSignerCert;
    }

    /**
     *
     * Sets the signing certificate
     *
     * @param signingCertificate X509Certificate object containing the signing certificate
     */
    public void setSignerCert(X509Certificate signerCert) {
        m_signerCert = signerCert;
    }

	/**
	 *
	 * Returns the CHUID signer certificate of the card for this signed object
	 *
	 * @return X509Certificate object containing the CHUID signer cert for this card
	 */
	public X509Certificate getChuidSignerCert() {
		return DataModelSingleton.getInstance().getChuidSignerCert();
	}

	/**
	 *
	 * Sets the CHUID signing certificate for this object in the event it doesn't have its own
	 * signing cert (which is probably almost always).
	 *
	 * @param cert X509Certificate object containing the CHUID signing certificate
	 */
	public void setChuidSignerCert(X509Certificate cert) {
		DataModelSingleton.getInstance().setChuidSignerCert(cert);
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
	 * Returns the number of certs found in this object
	 *
	 * @return number of certs found in this object
	 */
	public int getCertCount() {
		return m_signerCertCount;
	}

	/**
	 * Gets the signed attributes message digest extracted from SignerInfo
	 * 
	 * @return bytes in the digest
	 */

	public byte[] getSignedAttrsDigest() {
		return m_signedAttrsDigest;
	}

	/**
	 * Sets the message digest in the signed attributes
	 * 
	 * @param the bytes of the digest
	 * 
	 */	
	public void setSignedAttrsDigest(byte[] digest) {
		m_signedAttrsDigest = digest;
	}

	/**
	 *
	 * Gets the message digest algorithm name extracted from the signer information
	 *
	 * @return the message digest algorithm name extracted from the signer information
	 */
	public String getDigestAlgorithmName() {
		return m_digestAlgorithmName;
	}

	/**
	 *
	 * Sets the message digest algorithm name extracted from the signer information of
	 * the associated CMS.
	 *
	 * @param errorDetectionCode True if error Error Detection Code is present, false otherwise
	 */
	public void setDigestAlgorithmName(String name) {
		m_digestAlgorithmName = name;
	}   

	public byte[] getComputedDigest() {
		return m_computedDigest;
	}

	/**
	 * Sets the computed digest of the object
	 * 
	 * @param the bytes of the digest
	 * 
	 * @returns the bytes of the digest
	 */

	private void setComputedDigest(byte[] digest) {
		m_computedDigest = digest;
	}

    /**
     *
     * Returns CMSSignedData object containing Asymmetric Signature value
     *
     * @return CMSSignedData object containing Asymmetric Signature value
     */
    public CMSSignedData getAsymmetricSignature() {
        return m_asymmetricSignature;
    }

    /**
     *
     * Sets the CMSSignedData object containing Asymmetric Signature value
     *
     * @param asymmetricSignature CMSSignedData object containing Asymmetric Signature value
     */
    public void setAsymmetricSignature(CMSSignedData asymmetricSignature) {
        m_asymmetricSignature = asymmetricSignature;
    }

    /**
     * Extracts and sets the message digest in the signed attributes
     * 
     * @param the SignerInformationStore in the CMS
     * 
     */	
    public void setSignedAttrsDigest(SignerInformationStore signers) {

    	if (signers != null) {
    		AttributeTable at;				
    		// Temporarily nest these until unit test passes
    		for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
    			SignerInformation signer = i.next();
    			at = signer.getSignedAttributes();	
    			if (at != null) {
    				Attribute a = at.get(CMSAttributes.messageDigest); // messageDigest
    				if (a != null) {
    					DEROctetString dos = (DEROctetString) a.getAttrValues().getObjectAt(0);
    					if (dos != null) {
    						byte[] digest = dos.getOctets();
    						if (digest != null) {
    							m_computedDigest = digest;
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

    /**
     * Computes a digest of the content in this object and stores it
     * 
     * @param the SignerInfo of the content signer
     * @param the content to compute the digest over
     * t
     */

	public void setComputedDigest(SignerInformation signer, byte[] content) {
		if (content != null) {
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
								setComputedDigest(digest);
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
	 * Sets a flag indicating that this object has an embedded content signer cert.
	 * 
	 * @param hasOwnSignerCert boolean value indicating if this object has its own embedded signer cert
	 */

	public void setHasOwnSignerCert(boolean hasOwnSignerCert) {
		m_hasOwnSignerCert = hasOwnSignerCert;
	}

	/**
	 * Returns boolean value indicating if this object has its own embedded signer cert
	 *
	 * @return Boolean value indicating if this object has its own embedded signer cert
	 */
	public boolean getHasOwnSignerCert() {
		return m_hasOwnSignerCert;
	}


	/**
	 * Indicates whether this object has an embedded content signer cert 
	 *
	 */

	public boolean hasOwnSignerCert() {
		return m_signerCertCount > 0;
	}

    /**
     *
     * Verifies the signature on the object.
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

            if (m_asymmetricSignature.isDetachedSignature()) {
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
