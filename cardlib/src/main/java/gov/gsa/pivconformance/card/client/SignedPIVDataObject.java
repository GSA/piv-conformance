/**
 * 
 */
package gov.gsa.pivconformance.card.client;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
//import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
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
 * Subclass to handle signed data objects
 */
public class SignedPIVDataObject extends PIVDataObject {
	// slf4j will thunk this through to an appropriately configured logging library
	private static final Logger s_logger = LoggerFactory.getLogger(PIVDataObject.class);
	private CMSSignedData m_asymmetricSignature;
	private ContentInfo m_contentInfo;
	// private X509Certificate m_signingCertificate;
	// The raw data over which the message digest shall be computed
	private byte[] m_signedContent;
	// The effective signing cert.
	private X509Certificate m_signerCert;
	// This will be zero or one, and reflects the number of certs in this object
	private int m_signerCertCount;
	// This will be true *only* when this object has its own cert
	private boolean m_hasOwnSignerCert;
	// Prefetch
	private byte[] m_signedAttrsDigest;
	private byte[] m_computedDigest;
	private String m_signatureAlgorithmName;
	private String m_digestAlgorithmName;
	private String m_encryptionAlgorithmName;
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public SignedPIVDataObject() {
		super();
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
		return (m_signerCert != null) ? m_signerCert : getChuidSignerCert();
	}

	/**
	 *
	 * Sets the signing certificate
	 *
	 * @param signingCertificate X509Certificate object containing the signing
	 *                           certificate
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
		// Cache if not already cached
		if (DataModelSingleton.getInstance().getChuidSignerCert() == null) {
			CardHolderUniqueIdentifier o = (CardHolderUniqueIdentifier) new PIVDataObject(
					APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
			o.decode(); // Caches it
		}
		return DataModelSingleton.getInstance().getChuidSignerCert();
	}

	/**
	 *
	 * Sets the CHUID signing certificate for this object in the event it doesn't
	 * have its own signing cert (which is probably almost always).
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
	 * Sets the extracted message digest in the signed attributes
	 * 
	 * @param the bytes of the digest
	 * 
	 */
	public void setSignedAttrsDigest(byte[] digest) {
		m_signedAttrsDigest = digest;
	}

	/**
	 * Gets the computed message digest of the signed objects's content
	 * 
	 * @return the computed message digest of the object's content
	 */

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
	 * @return the signer signature algorithm name
	 */
	public String getSignatureAlgorithmName() {
		return m_signatureAlgorithmName;
	}

	/**
	 * @param m_signatureAlgorithmName the m_signatureAlgorithmName to set
	 */
	public void setSignatureAlgorithmName(String m_signatureAlgorithmName) {
		this.m_signatureAlgorithmName = m_signatureAlgorithmName;
	}

	/**
	 *
	 * Gets the message digest algorithm name extracted from the signer information
	 *
	 * @return the message digest algorithm name extracted from the signer
	 *         information
	 */
	public String getDigestAlgorithmName() {
		return m_digestAlgorithmName;
	}

	/**
	 *
	 * Sets the message digest algorithm name extracted from the signer information
	 * of the associated CMS.
	 *
	 * @param errorDetectionCode True if error Error Detection Code is present,
	 *                           false otherwise
	 */
	public void setDigestAlgorithmName(String name) {
		m_digestAlgorithmName = name;
	}

	/**
	 *
	 * Sets the message Encryption algorithm name extracted from the signer
	 * information of the associated CMS.
	 *
	 * @param errorDetectionCode True if error Error Detection Code is present,
	 *                           false otherwise
	 */
	public void setEncryptionAlgorithmName(String name) {
		m_encryptionAlgorithmName = name;
	}

	/**
	 *
	 * Gets the message Encryption algorithm name extracted from the signer
	 * information
	 *
	 * @return the message Encryption algorithm name extracted from the signer
	 *         information
	 */
	public String getEncryptionAlgorithmName() {
		return m_encryptionAlgorithmName;
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
	 * @param asymmetricSignature CMSSignedData object containing Asymmetric
	 *                            Signature value
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
								m_signedAttrsDigest = digest;
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
	 * Computes a digest of the received content in this object and stores it
	 * 
	 * @param the SignerInfo of the content signer
	 * @param the content to compute the digest over t
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
							String aName = MessageDigestUtils
									.getDigestName(new ASN1ObjectIdentifier(signer.getDigestAlgOID()));
							MessageDigest md = MessageDigest.getInstance(aName, "BC");
							md.update(contentBytes);
							byte[] digest = md.digest();
							if (digest != null) {
								setComputedDigest(digest);
								s_logger.debug("Computed digest: {} ", Hex.encodeHexString(digest));
							} else {
								s_logger.error("Failed to digest content");
							}
						} else {
							String msg = "Null contentBytes";
							s_logger.error(msg);
							throw new CardClientException(msg);
						}
					} else {
						String msg = "Null messageDigest attribute";
						s_logger.error(msg);
						throw new CardClientException(msg);
					}
				} else {
					String msg = "Null signed attribute set";
					s_logger.error(msg);
					throw new CardClientException(msg);
				}
			} catch (Exception e) {
				String msg = e.getMessage();
				s_logger.error(msg);
				e.printStackTrace();
			}
		}
	}

	/**
	 * Sets a flag indicating that this object has an embedded content signer cert.
	 * 
	 * @param hasOwnSignerCert boolean value indicating if this object has its own
	 *                         embedded signer cert
	 */

	public void setHasOwnSignerCert(boolean hasOwnSignerCert) {
		m_hasOwnSignerCert = hasOwnSignerCert;
	}

	/**
	 * Returns boolean value indicating if this object has its own embedded signer
	 * cert
	 *
	 * @return Boolean value indicating if this object has its own embedded signer
	 *         cert
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

        CMSSignedData s;
        try {
            s = new CMSSignedData(m_contentInfo);

            if (m_asymmetricSignature.isDetachedSignature()) {
                CMSProcessable procesableContentBytes = new CMSProcessableByteArray(m_signedContent);
                s = new CMSSignedData(procesableContentBytes, m_contentInfo);
            }
            
            SignerInformationStore signers = s.getSignerInfos();
            if (signers.size() != 1) {
            	s_logger.error("There were {} signers", signers.size());
            	return rv_result;
            }
            Store<X509CertificateHolder> certs = s.getCertificates();
            Set<AlgorithmIdentifier> digAlgSet = s.getDigestAlgorithmIDs();
            Iterator<AlgorithmIdentifier> dai = digAlgSet.iterator();
            
            ArrayList<String> allowedDigestAlgOids = new ArrayList<String>();
            allowedDigestAlgOids.add("2.16.840.1.101.3.4.2.1");
            allowedDigestAlgOids.add("2.16.840.1.101.3.4.2.2");
        	String daOid = null;

        	while (dai.hasNext()) {
            	// Check against allowed signing algorithms
            	AlgorithmIdentifier ai = dai.next();
            	daOid = ai.getAlgorithm().getId();
            	if (!allowedDigestAlgOids.contains(daOid)) {
            		s_logger.error("Unsupported digest algorithm for PIV/PIV-I: {}", daOid);
            		return rv_result; 
            	}
            	break; // TODO: Should we handle multiple?
            }
            
            for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
                SignerInformation signer = i.next();
        		signer = new _SignerInformation(signer);

				/*
				 * RFC 5250 5.4
				 * 
				 * The result of the message digest calculation process depends on whether the
				 * signedAttrs field is present. When the field is absent, the result is just
				 * the message digest of the content as described above. When the field is
				 * present, however, the result is the message digest of the complete DER
				 * encoding of the SignedAttrs value contained in the signedAttrs field.
				 */
                Attribute md = null;
                Attribute ct = null;
                AttributeTable at = signer.getSignedAttributes();
                ASN1EncodableVector av = at.toASN1EncodableVector();

                s_logger.debug("There are {} signed attributes", at.size());
				// Message digest
				if (at.get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.4")) == null) {
					s_logger.error("Required messageDigest attribute is missing");
					return rv_result;
				}
              
				// Content type
				if (at.get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.3")) == null) {
					s_logger.error("Required contentType attribute is missing");
					return rv_result;
				}

				// Ensure there is a content signer certificate
                X509Certificate signerCert = getChuidSignerCert();

                if (signerCert == null) {
                    s_logger.error("Unable to find CHUID signer certificate for {}", APDUConstants.oidNameMAP.get(super.getOID()));
                   return rv_result;
                }

                Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
                Iterator<X509CertificateHolder> certIt = certCollection.iterator();
                if (certIt.hasNext()) {
                    X509CertificateHolder certHolder = certIt.next();
                    signerCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
                    // Housekeeping
                    if (signerCert != null)
                    	setSignerCert(signerCert);
                }

                rv_result = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCert));
            }
        } catch (CertificateException e) {
            s_logger.error("Error verifying signature on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
        } catch (CMSException e) {
        	s_logger.error("CMS exception while verifying signature on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
		} catch (OperatorCreationException e) {
        	s_logger.error("Operator exception while verifying signature on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
		}

        return rv_result;
    }
	
	private class _SignerInformation extends SignerInformation {
		protected _SignerInformation(SignerInformation baseSignerInfo) {
			super(baseSignerInfo);
		}
		
		@Override
		public byte[] getEncodedSignedAttributes() throws IOException {
			return signedAttributeSet.getEncoded(ASN1Encoding.DL);
		}
	}
}
