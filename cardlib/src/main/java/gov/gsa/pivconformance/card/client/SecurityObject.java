package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;

import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.cms.ContentInfo;

/**
 *
 * Encapsulates a Security Object data object as defined by SP800-73-4 Part 2
 * Appendix A Table 12
 *
 */
public class SecurityObject extends SignedPIVDataObject {
	// slf4j will thunk this through to an appropriately configured logging library
	private static final Logger s_logger = LoggerFactory.getLogger(SecurityObject.class);
	private byte[] m_mapping;
	private byte[] m_so;
	private HashMap<Integer, String> m_containerIDList;
	HashMap<String, byte[]> m_mapOfDataElements;
	HashMap<Integer, byte[]> m_dghList;
	private boolean m_errorDetectionCode;

	/**
	 * SecurityObject class constructor, initializes all the class fields.
	 */
	public SecurityObject() {
		m_mapping = null;
		m_so = null;
		m_containerIDList = null;
		m_mapOfDataElements = null;
		m_dghList = null;
		m_errorDetectionCode = false;
		m_content = new HashMap<BerTag, byte[]>();
	}

	/**
	 * Returns boolean value indicating if error detection code is present
	 *
	 * @return Boolean value indicating if error detection code is present
	 */
	@Override
	public boolean getErrorDetectionCode() {

		return m_errorDetectionCode;
	}

	public HashMap<String, byte[]> getMapOfDataElements() {
		return m_mapOfDataElements;
	}

	public void setMapOfDataElements(HashMap<String, byte[]> mapOfDataElements) {
		m_mapOfDataElements = mapOfDataElements;
	}

	/**
	 *
	 * Returns byte array containing Mapping of DG to ContainerID
	 *
	 * @return Byte array containing Mapping of DG to ContainerID
	 */
	public byte[] getMapping() {
		return m_mapping;
	}

	/**
	 *
	 * Sets the Mapping of DG to ContainerID
	 *
	 * @param mapping Byte array containing Mapping of DG to ContainerID
	 */
	public void setMapping(byte[] mapping) {
		m_mapping = mapping;
	}

	/**
	 *
	 * Returns byte array containing security object
	 *
	 * @return Byte array containing security object value
	 */
	public byte[] getSecurityObject() {
		return m_so;
	}

	/**
	 *
	 * Sets the security object value
	 *
	 * @param so Byte array containing security object value
	 */
	public void setSecurtiyObject(byte[] so) {
		m_so = so;
	}

	/**
	 *
	 * Returns a map containing container ID list
	 *
	 * @return HashMap containing container ID list
	 */
	public HashMap<Integer, String> getContainerIDList() {
		return m_containerIDList;
	}

	/**
	 *
	 * Sets the Hash map with containing container ID list
	 *
	 * @param containerIDList HashMap containing container ID list
	 */
	public void setContainerIDList(HashMap<Integer, String> containerIDList) {
		m_containerIDList = containerIDList;
	}

	// XXX Move this

	/**
	 *
	 * Helper function to divide a byte array into n numer of chuncks
	 *
	 * @param source    Byte array to be divided
	 * @param chunksize Integer specifying number of chanks
	 * @return List of byte arrays
	 */
	public static List<byte[]> divideArray(byte[] source, int chunksize) {

		List<byte[]> result = new ArrayList<byte[]>();
		int start = 0;
		while (start < source.length) {
			int end = Math.min(source.length, start + chunksize);
			result.add(Arrays.copyOfRange(source, start, end));
			start += chunksize;
		}

		return result;
	}

	/**
	 *
	 * Decode function that decodes Security Object retrieved from the card and
	 * populates various class fields.
	 *
	 * @return True if decode was successful, false otherwise
	 */
	@Override
	public boolean decode() {
		SignerInformationStore signers = null;
		SignerInformation signer = null;
		boolean certFound = false;
		try {
			super.m_tagList.clear();
			byte[] rawBytes = this.getBytes();
			s_logger.trace("rawBytes: {}", Hex.encodeHexString(rawBytes));
			BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
			BerTlvs outer = tlvp.parse(rawBytes);
			List<BerTlv> outerTlvs = outer.getList();
			if (outerTlvs.size() == 1 && outerTlvs.get(0).isTag(new BerTag(0x53))) {
				byte[] tlvBuf = outerTlvs.get(0).getBytesValue();
				outer = tlvp.parse(tlvBuf);
			}
			for (BerTlv tlv : outer.getList()) {
				s_logger.trace("SecurityObject: processing tag {}", tlv.getTag().toString());
				byte[] tag = tlv.getTag().bytes;

				super.m_tagList.add(tlv.getTag());
				if (Arrays.equals(tag, TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG)) {
					m_mapping = tlv.getBytesValue();
					m_content.put(tlv.getTag(), m_mapping);

					if (m_mapping == null) {
						s_logger.error("Missing mapping of DG to contains IDs for {}.",
								APDUConstants.oidNameMap.get(super.getOID()));
						return false;
					}

					// Break the byte array into chunks of 3
					List<byte[]> idList = divideArray(m_mapping, 3);

					// Iterate over the resulting list to get container IDs for each
					for (byte[] b : idList) {
						if (m_containerIDList == null)
							m_containerIDList = new HashMap<Integer, String>();

						byte idByte = b[0];
						byte[] tg = Arrays.copyOfRange(b, 1, 3);
						int i = APDUUtils.bytesToInt(tg);
						String cc = APDUConstants.idMAP.get(i);

						int tmp = idByte;
						Integer id = tmp;
						// Add the container oid to the list will be easier to look up.
						m_containerIDList.put(id, cc);
					}
				} else if (Arrays.equals(tag, TagConstants.SECURITY_OBJECT_TAG)) {
					m_so = tlv.getBytesValue();

					if (m_so == null) {
						s_logger.error("Missing security object value for {}.",
								APDUConstants.oidNameMap.get(super.getOID()));
						return false;
					}
					
					m_content.put(tlv.getTag(), m_so);
					
					// Decode the ContentInfo and get SignedData object.
					ByteArrayInputStream bIn = new ByteArrayInputStream(m_so);
					ASN1InputStream aIn = new ASN1InputStream(bIn);

					// Set the ContentInfo structure in super class
					setContentInfo(ContentInfo.getInstance(aIn.readObject()));
					aIn.close();
					// Set the CMSSignedData object
					setAsymmetricSignature(new CMSSignedData(getContentInfo()));
					// This gets set in case hasOwnSignerCert() is false
					setSignedContent(m_so);
					// Indicate this object needs a signature verification
					setSigned(true);

					CMSSignedData cmsSignedData = getAsymmetricSignature();
					Store<X509CertificateHolder> certs = cmsSignedData.getCertificates();
					signers = cmsSignedData.getSignerInfos();

					for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
						signer = i.next();
						setDigestAlgorithmName(Algorithm.digAlgOidToNameMap.get(signer.getDigestAlgOID()));
						setEncryptionAlgorithmName(Algorithm.encAlgOidToNameMap.get(signer.getEncryptionAlgOID()));
						@SuppressWarnings("unchecked")
						Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
						Iterator<X509CertificateHolder> certIt = certCollection.iterator();
						if (certIt.hasNext()) {
							X509CertificateHolder certHolder = certIt.next();
							// Note that setSignerCert internally increments a counter. If there are more
							// than one
							// cert in PKCS7 cert bags then the consumer class should throw an exception.
							X509Certificate signerCert = new JcaX509CertificateConverter().setProvider("BC")
									.getCertificate(certHolder);
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

					// Grab last signed digest
					setSignedAttrsDigest(signers);
					// Precompute digest but don't compare -- let consumers do that so they can
					// throw their own
					// exception
					setComputedDigest(signer, m_so);

				} else {
					if (!Arrays.equals(tag, TagConstants.ERROR_DETECTION_CODE_TAG) && tlv.getBytesValue().length != 0) {
						s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv.getTag().bytes),
								Hex.encodeHexString(tlv.getBytesValue()));
					} else {
						m_errorDetectionCode = true;
					}
				}
			}
		} catch (Exception e) {
			s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMap.get(super.getOID()), e.getMessage(), e);
			return false;
		}

		String message = APDUConstants.oidNameMap.get(super.getOID()) + (certFound ? " had" : " did not have")
				+ " an embedded certificate";
		s_logger.trace(message);
		if (m_mapping == null || m_so == null)
			return false;

		dump(this.getClass());
		return true;
	}

	/**
	 *
	 * Verifies all included hashes
	 *
	 * @return True if all hashes match, false otherwise
	 */
	public boolean verifyHashes() {
		boolean rv_result = false;

		if (m_dghList == null) {
			if (m_mapOfDataElements == null) {
				s_logger.error("Missing list of objects to hash");
				return false;
			}
			CMSSignedData signedData = null;
			LDSSecurityObject ldsso = null;
			try {
				signedData = new CMSSignedData(m_so);
				ldsso = LDSSecurityObject.getInstance(signedData.getSignedContent().getContent());
			} catch (CMSException ex) {
				s_logger.error("Unable to create CMSSignedData object from Security Object data.");
			}

			if (ldsso != null) {
				DataGroupHash[] dghList = ldsso.getDatagroupHash();

				m_dghList = new HashMap<Integer, byte[]>();
				if (dghList != null) {
					for (DataGroupHash entry : dghList) {
						m_dghList.put(entry.getDataGroupNumber(), entry.getDataGroupHashValue().getOctets());
					}

					int dgIdx = 0;
					for (Map.Entry<Integer, byte[]> entry : m_dghList.entrySet()) {

						String oid = m_containerIDList.get(entry.getKey());
						s_logger.debug("Checking digest for {} (0x{})", APDUConstants.containerOidToNameMap.get(oid), Integer.toHexString(entry.getKey()));

						if (oid != null) {
							byte[] content = m_mapOfDataElements.get(oid);
							MessageDigest md = null;
							try {
								md = MessageDigest.getInstance(getDigestAlgorithmName(), "BC");
								if (md != null) {
									md.update(content);
									byte[] digest = md.digest();
									if (!Arrays.equals(entry.getValue(), digest)) {
										s_logger.error("Content: {}", Hex.encodeHexString(content));
										s_logger.error("Reference digest: {}", Hex.encodeHexString(entry.getValue()));
										s_logger.error("Computed digest:  {}", Hex.encodeHexString(digest));
									} else {
										dgIdx++;
									}
								}
							} catch (NoSuchAlgorithmException | java.security.NoSuchProviderException e) {
								s_logger.error("Error creating message digest: {}", e.getMessage());
							}
						} else {
							s_logger.error("Missing object to hash for id {}: ", entry.getKey());
						}
					}
					rv_result = (dgIdx == m_dghList.entrySet().size()) ? true : false;
				} else {
					s_logger.error("Data Group object was null");
				}
			} else {
				s_logger.error("LDSSecurityObject was null");
			}
		}

		return rv_result;
	}

	/**
	 * Verifies hash of a specific container identified by the container ID value
	 *
	 * @param id Container ID value
	 * @return True if hash value included in the security object for the specified
	 *         container matches hashed value of the container data.
	 */
	public boolean verifyHash(Integer id) {
		boolean rv_result = true;

		String oid = m_containerIDList.get(id);

		if (oid == null) {
			s_logger.error("Missing object to hash for ID {}: ", id);
			return false;
		}

		try {
			CMSSignedData s = new CMSSignedData(getContentInfo());

			if (m_dghList == null) {
				if (m_mapOfDataElements == null) {
					s_logger.error("Missing list of objects to hash");
					return false;
				}

				ASN1InputStream asn1is = new ASN1InputStream(new ByteArrayInputStream(s.getEncoded()));
				ASN1Sequence soSeq;
				soSeq = (ASN1Sequence) asn1is.readObject();
				asn1is.close();
				LDSSecurityObject ldsso = LDSSecurityObject.getInstance(soSeq);

				DataGroupHash[] dghList = ldsso.getDatagroupHash();

				m_dghList = new HashMap<Integer, byte[]>();
				for (DataGroupHash entry : dghList) {
					m_dghList.put(entry.getDataGroupNumber(), entry.getDataGroupHashValue().getOctets());
				}
			}

			byte[] bytesToHash = m_mapOfDataElements.get(oid);

			String aName = getDigestAlgorithmName();
			SignerInformationStore signers = s.getSignerInfos();
			for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
				SignerInformation signer = i.next();
				aName = signer.getDigestAlgOID();
				break;
			}

			MessageDigest md = MessageDigest.getInstance(aName);
			md.update(bytesToHash);
			byte[] digest = md.digest();

			if (!Arrays.equals(m_dghList.get(id), digest)) {
				rv_result = false;
			}

		} catch (Exception ex) {
			s_logger.error("Error verifying hash for ID: {}", id);
		}

		return rv_result;
	}

	/**
	 * Returns true if a specified container identified by the oid is covered by one
	 * of the hashes in the map.
	 *
	 * @param oid String identifying container to look up
	 * @return True if specified container is covered by one of the hashes in the
	 *         map, false otherwise
	 */
	public boolean hashIncluded(String oid) {

		boolean rv = false;

		if (m_containerIDList.containsValue(oid))
			rv = true;

		return rv;
	}

}
