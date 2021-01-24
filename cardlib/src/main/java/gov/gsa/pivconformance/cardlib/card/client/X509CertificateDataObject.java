package gov.gsa.pivconformance.cardlib.card.client;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.cardlib.tlv.*;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.util.zip.GZIPInputStream;

/**
 *
 * Encapsulates data object that store as defined by SP800-73-4 Part 2 Appendix
 * A Table 8
 *
 */
public class X509CertificateDataObject extends PIVDataObject {
	// slf4j will thunk this through to an appropriately configured logging library
	private static final Logger s_logger = LoggerFactory.getLogger(X509CertificateDataObject.class);

	private X509Certificate m_cert;
	private byte[] m_rawCertBuf = null;
	private boolean m_compressed = false;
	private final ArtifactWriter m_x509ArtifactCache;


	/**
	 * CardCapabilityContainer class constructor, initializes all the class fields.
	 */
	public X509CertificateDataObject() {

		m_cert = null;
		m_rawCertBuf = null;
		setErrorDetectionCode(false);
		setErrorDetectionCodeHasData(false);
		setIsCompressed(false);
		m_content = new HashMap<BerTag, byte[]>();
		m_x509ArtifactCache = new ArtifactWriter("x509-artifacts");
	}

	/**
	 *
	 * Returns X509Certificate object containing the certificate in the PIV data
	 * object
	 *
	 * @return X509Certificate object containing the certificate in the PIV data
	 *         object
	 */
	public X509Certificate getCertificate() {
		return m_cert;
	}

	/**
	 *
	 * Decode function that decodes PIV data object object containing x509
	 * certificate retrieved from the card and populates various class fields.
	 *
	 * @return True if decode was successful, false otherwise
	 */
	@Override
	public boolean decode() {

		if (m_cert == null) {

			try {
				byte[] raw = super.getBytes();

				s_logger.trace("rawBytes: {}", Hex.encodeHexString(raw));

				BerTlvParser tp = new BerTlvParser(new CCTTlvLogger(X509CertificateDataObject.class));
				BerTlvs outer = tp.parse(raw);

				if (outer == null) {
					s_logger.error("Error parsing X.509 Certificate, unable to parse TLV value.");
					return false;
				}

				List<BerTlv> values = outer.getList();
				for (BerTlv tlv : values) {
					if (tlv.isPrimitive()) {
						s_logger.trace("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes),
								Hex.encodeHexString(tlv.getBytesValue()));

						BerTlvs outer2 = tp.parse(tlv.getBytesValue());

						if (outer2 == null) {
							s_logger.error("Error parsing X.509 Certificate, unable to parse TLV value.");
							return false;
						}

						List<BerTlv> values2 = outer2.getList();
						byte[] certInfoBuf = null;
						byte[] mSCUIDBuf = null;
						for (BerTlv tlv2 : values2) {
							if (tlv2.isPrimitive()) {
								s_logger.trace("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes),
										Hex.encodeHexString(tlv2.getBytesValue()));
							} else {
								super.m_tagList.add(tlv2.getTag());
								if (Arrays.equals(tlv2.getTag().bytes, TagConstants.CERTIFICATE_TAG)) {
									if (tlv2.hasRawValue()) {
										m_rawCertBuf = tlv2.getBytesValue();
										m_content.put(tlv2.getTag(), tlv2.getBytesValue());
										s_logger.trace("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes),
												Hex.encodeHexString(m_rawCertBuf));
									}

									String oid = getOID();
								}
								if (Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {
									setErrorDetectionCode(true);
									m_content.put(tlv2.getTag(), tlv2.getBytesValue());
									if (tlv2.getBytesValue().length > 0) {
										setErrorDetectionCodeHasData(true);
									}
								}

								if (Arrays.equals(tlv2.getTag().bytes, TagConstants.CERTINFO_TAG)) {
									certInfoBuf = tlv2.getBytesValue();
									m_content.put(tlv2.getTag(), tlv2.getBytesValue());
									s_logger.trace("Got cert info buffer: {}", Hex.encodeHexString(certInfoBuf));
									if (certInfoBuf != null && Arrays.equals(certInfoBuf, TagConstants.COMPRESSED_TAG)) {
										m_compressed = true;
									}
									s_logger.debug("Cert buffer is " + ((m_compressed) ? "compressed" : "uncompressed"));
								}
								if (Arrays.equals(tlv2.getTag().bytes, TagConstants.MSCUID_TAG)) {
									mSCUIDBuf = tlv2.getBytesValue();
									m_content.put(tlv2.getTag(), tlv2.getBytesValue());
									s_logger.trace("Got MSCUID buffer: {}", Hex.encodeHexString(mSCUIDBuf));
								}
							}
						}

						// Check to make sure certificate buffer is not null
						if (m_rawCertBuf == null || m_rawCertBuf.length == 0) {
							s_logger.error("Error parsing X.509 Certificate, unable to get certificate buffer.");
							return false;
						}
					} else {
						s_logger.trace("Object: {}", Hex.encodeHexString(tlv.getTag().bytes));
					}
				}
			} catch (Exception ex) {
				s_logger.error("Error parsing X.509 Certificate", ex);
				return false;
			}
		}
		super.setRequiresPin(true);

		InputStream certIS = null;
		if (m_compressed) {
			try {
				certIS = new GZIPInputStream(new ByteArrayInputStream(m_rawCertBuf));
			} catch (IOException e) {
				s_logger.error(e.getMessage() + " in GZIPInputStream()");
			}
		} else {
			certIS = new ByteArrayInputStream(m_rawCertBuf);
		}
		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X509");
			m_cert = (X509Certificate) cf.generateCertificate(certIS);
			s_logger.debug("Subject: {}", m_cert.getSubjectDN().toString());
			m_x509ArtifactCache.saveObject(
					"x509-artifacts", APDUConstants.getFileNameForOid(getOID()) + ".cer", m_cert.getEncoded());
		} catch (CertificateException e) {
			e.printStackTrace();
		}

		dump(this.getClass());
		return true;
	}

	public void setIsCompressed(boolean isCompressed) {
		m_compressed = isCompressed;
	}

	public boolean getIsCompressed() {
		return m_compressed;
	}
}
