package gov.gsa.pivconformance.cardlib.card.client;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.cardlib.card.client.Algorithm;
import gov.gsa.pivconformance.cardlib.card.client.SignedPIVDataObject;
import gov.gsa.pivconformance.cardlib.tlv.BerTag;
import gov.gsa.pivconformance.cardlib.tlv.BerTlv;
import gov.gsa.pivconformance.cardlib.tlv.BerTlvParser;
import gov.gsa.pivconformance.cardlib.tlv.BerTlvs;
import gov.gsa.pivconformance.cardlib.tlv.CCTTlvLogger;
import gov.gsa.pivconformance.cardlib.tlv.TagConstants;

import org.apache.commons.codec.binary.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;
import java.util.*;
import java.text.SimpleDateFormat;

/**
 *
 * Encapsulates a Card Holder Unique Identifier data object as defined by
 * SP800-73-4 Part 2 Appendix A Table 9
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
	private final ArtifactWriter m_x509ArtifactCache;

	// TODO: Cache this
	// HashMap<BerTag, byte[]> m_content;

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
		m_x509ArtifactCache = new ArtifactWriter("x509-artifacts");
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
	 * @param organizationalIdentifier Byte array containing Organizational
	 *                                 Identifier value
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
	 * Sets Expiration Date value
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
	@Override
	public boolean getErrorDetectionCode() {
		return m_errorDetectionCode;
	}

	/**
	 * Converts an encoded GUID byte array to its representative string
	 *
	 */
	public static String guid2str(byte[] guid) {
		String guidStr = null;
		StringBuilder sb = new StringBuilder();
		String s = Hex.encodeHexString(guid);
		guidStr = s.replaceFirst( "([0-9a-fA-F]{8})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]+)", "$1-$2-$3-$4-$5" );
		return guidStr;
	}
	/**
	 * Converts a 200-bit raw FASC-N byte array to a string of digits
	 *
	 * @param raw bytes of the FASC-N from the card
	 * @return a string of 32 FASC-N digits or null if an encoding error is
	 *         encountered
	 */

	public static String cook(byte[] raw) {

		String bitstr = "";
		// Convert each hex digit to 8 0's and 1's and concatenate to into a string
		for (byte b : raw) {
			bitstr += String.format("%8s", Integer.toBinaryString((int) b & 0xff)).replace(' ', '0');
		}
		// Create a bit array to read 5 bits at a time.
		byte[] bits = bitstr.getBytes();
		int length, value, bctr, pctr;
		String digits = "";
		for (length = bits.length, value = 0, bctr = 0, pctr = 0; bctr < length - 5; bctr++) {
			// If this bit is a parity bit, process the value and reset the next digit value
			if ((bctr + 1) % 5 == 0) {
				// Check parity
				if (((pctr % 2) == 0) && bits[bctr] != (byte) '1') {
					s_logger.error("Parity OFF error at b[{}]", bctr);
					return null;
				} else if (((pctr % 2) == 1) && bits[bctr] != (byte) '0') {
					s_logger.error("Parity ON error at b[{}]", bctr);
					return null;
				}

				// Digit or whitespace? Sentinels, field separators, LRC, are > 9
				if (value < 10) {
					digits += Integer.toString(value);
				} else {
					s_logger.trace("Whitespace char {} ended at bit[{}]",
							Integer.toBinaryString(value & 0xff).replace(' ', '0'), bctr);
				}
				// Ready for next digit
				value = 0;
				pctr = 0;
			} else {
				if ((bits[bctr] & 1) == 1) {
					pctr++; // Increment parity count
					// The bits of each digit are encoded in reverse order
					value |= (1 << (bctr % 5));
				}
			}
		}

		return digits.length() == 32 ? digits : null;
	}

	/**
	 *
	 * Sets if error Error Detection Code is present
	 *
	 * @param errorDetectionCode True if error Error Detection Code is present,
	 *                           false otherwise
	 */
	@Override
	public void setErrorDetectionCode(boolean errorDetectionCode) {
		m_errorDetectionCode = errorDetectionCode;
	}

	/**
	 *
	 * Decode function that decodes Card Holder Unique Identifier object retrieved
	 * from the card and populates various class fields.
	 *
	 * @return True if decode was successful, false otherwise
	 */
	@Override
	public boolean decode() {

		SignerInformationStore signers = null;
		SignerInformation signer = null;

		try {
			byte[] rawBytes = this.getBytes();

			s_logger.trace("rawBytes: {}", Hex.encodeHexString(rawBytes));

			if (rawBytes == null) {
				s_logger.error("No buffer to decode for {}.", APDUConstants.oidNameMap.get(super.getOID()));
				return false;
			}

			BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
			BerTlvs outer = tlvp.parse(rawBytes);

			if (outer == null) {
				s_logger.error("Error parsing {}, unable to parse TLV value.",
						APDUConstants.oidNameMap.get(super.getOID()));
				return false;
			}

			boolean ecAdded = false;
			ByteArrayOutputStream signedContentOutputStream = new ByteArrayOutputStream();
			ByteArrayOutputStream containerOutputStream = new ByteArrayOutputStream();
			byte[] issuerAsymmetricSignature = null;
			setContainerName("CardHolderUniqueIdentifier");
			List<BerTlv> values = outer.getList();
			for (BerTlv tlv : values) {
				if (tlv.isPrimitive()) {
					s_logger.trace("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes),
							Hex.encodeHexString(tlv.getBytesValue()));

					BerTlvs outer2 = tlvp.parse(tlv.getBytesValue());

					if (outer2 == null) {
						s_logger.error("Error parsing {}, unable to parse TLV value.",
								APDUConstants.oidNameMap.get(super.getOID()));
						return false;
					}

					List<BerTlv> values2 = outer2.getList();
					for (BerTlv tlv2 : values2) {
						if (tlv2.isPrimitive()) {
							s_logger.trace("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes),
									Hex.encodeHexString(tlv2.getBytesValue()));
						} else {

							BerTag tag = tlv2.getTag();
							byte[] value = tlv2.getBytesValue();

							// 2 deprecated tags that can't be part of the data model after we note them
							// here

							if (Arrays.equals(tag.bytes, TagConstants.BUFFER_LENGTH_TAG)) { // EE - Don't use in hash
																							// (don't add to digest
																							// input)
								s_logger.warn("Deprecated tag: {} with value: {}", Hex.encodeHexString(tag.bytes),
										Hex.encodeHexString(value));
							} else if (Arrays.equals(tag.bytes, TagConstants.DEPRECATED_AUTHENTICATION_KEY_MAP)) { // 3D - Dont' use in hash (don't add to digest input)
								s_logger.warn("Deprecated tag: {} with value: {}", Hex.encodeHexString(tag.bytes),
										Hex.encodeHexString(value));
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
									signedContentOutputStream.write(APDUUtils.getTLV(
											TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG, m_organizationalIdentifier));

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
									signedContentOutputStream
											.write(APDUUtils.getTLV(TagConstants.CHUID_EXPIRATION_DATE_TAG, value));

							} else if (Arrays.equals(tag.bytes, TagConstants.CARDHOLDER_UUID_TAG)) {

								m_cardholderUUID = value;
								m_content.put(tag, value);
								m_tagList.add(tag);
								if (m_cardholderUUID != null) {
									signedContentOutputStream
											.write(APDUUtils.getTLV(TagConstants.CARDHOLDER_UUID_TAG, value));
								}

							} else if (Arrays.equals(tag.bytes, TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG)) {

								issuerAsymmetricSignature = value;
								m_content.put(tag, value);
								m_tagList.add(tag);
								if (issuerAsymmetricSignature != null) {
									// Decode the ContentInfo and get SignedData object.
									ByteArrayInputStream bIn = new ByteArrayInputStream(issuerAsymmetricSignature);
									ASN1InputStream aIn = new ASN1InputStream(bIn);
									// Set the ContentInfo structure in super class
									setContentInfo(ContentInfo.getInstance(aIn.readObject()));
									aIn.close();
									// Set the CMSSignedData object
									CMSSignedData signedData = new CMSSignedData(getContentInfo());
									setAsymmetricSignature(signedData);
									setDigestAlgorithms(signedData.getDigestAlgorithmIDs());

									Store<X509CertificateHolder> certs = getAsymmetricSignature().getCertificates();
									signers = getAsymmetricSignature().getSignerInfos();

									for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i
											.hasNext();) {
										signer = i.next();
										setDigestAlgorithmName(
												Algorithm.digAlgOidToNameMap.get(signer.getDigestAlgOID()));
										setEncryptionAlgorithmName(
												Algorithm.encAlgOidToNameMap.get(signer.getEncryptionAlgOID()));
										// String encOid = signer.getEncryptionAlgOID();
										// Get signer cert
										@SuppressWarnings("unchecked")
										Collection<X509CertificateHolder> certCollection = certs
												.getMatches(signer.getSID());
										Iterator<X509CertificateHolder> certIt = certCollection.iterator();
										if (certIt.hasNext()) {
											X509CertificateHolder certHolder = certIt.next();
											// Note that setSignerCert internally increments a counter. If there are
											// more than one
											// cert in PKCS7 cert bags then the consumer class should throw an
											// exception.
											X509Certificate signerCert = new JcaX509CertificateConverter().getCertificate(certHolder);
											if (signerCert != null) {
												setSignerCert(signerCert);
												setHasOwnSignerCert(true);
												// Extract signer's signature algorithm name and hang on to it.
												setSignatureAlgorithmName(signerCert.getSigAlgName());
												// Hang the CHUID signer cert here so that any test runner
												// consumer can access it.
												setChuidSignerCert(signerCert);
												m_x509ArtifactCache.saveObject("x509-artifacts", APDUConstants.getFileNameForOid(getOID()) + ".cer", signerCert.getEncoded());
											} else {
												s_logger.error("Can't extract signer certificate");
											}
										}
									}
								}
							} else if (Arrays.equals(tag.bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {
								ecAdded = true;
								m_content.put(tag, value);
								m_errorDetectionCode = true;
								m_tagList.add(tag);
							} else {
								s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tag.bytes),
										Hex.encodeHexString(value));
								// Unexpected tags (for future) - we could simply ignore
								m_tagList.add(tag);
								signedContentOutputStream.write(APDUUtils.getTLV(tag.bytes, value));
							}
						}
					}
				}
			}

			// Write all tags except signature to the container buffer (noting the signature
			// and error detection code
			// may still need to be appended).
			containerOutputStream.write(signedContentOutputStream.toByteArray());

			// Append signature to full container output
			if (issuerAsymmetricSignature != null)
				containerOutputStream.write(
						APDUUtils.getTLV(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG, issuerAsymmetricSignature));

			// Append EC if in the original
			if (ecAdded) {
				containerOutputStream.write(TagConstants.ERROR_DETECTION_CODE_TAG);
				signedContentOutputStream.write(TagConstants.ERROR_DETECTION_CODE_TAG);
				containerOutputStream.write((byte) 0x00);
				signedContentOutputStream.write((byte) 0x00);
			}

			setSigned(true);
			setSignedContent(signedContentOutputStream.toByteArray());
			// Grab signed digest
			setSignedAttrsDigest(signers);
			// Precompute digest but don't compare -- let consumers do that
			setComputedDigest(signer, getSignedContent());

			m_chuidContainer = containerOutputStream.toByteArray();

		} catch (Exception ex) {
			s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMap.get(super.getOID()), ex.getMessage());
		}

		if (m_fASCN == null || m_gUID == null || m_expirationDate == null || m_chuidContainer == null) {
			return false;
		}

		dump(this.getClass());
		return true;
	}
}
