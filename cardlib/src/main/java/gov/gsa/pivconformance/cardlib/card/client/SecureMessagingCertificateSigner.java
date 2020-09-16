package gov.gsa.pivconformance.cardlib.card.client;

import gov.gsa.pivconformance.cardlib.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.zip.GZIPInputStream;

/**
 *
 * Encapsulates a Card Holder Unique Identifier data object  as defined by SP800-73-4 Part 2 Appendix A Table 42
 *
 */
public class SecureMessagingCertificateSigner extends PIVDataObject {    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(SecureMessagingCertificateSigner.class);

    private X509Certificate m_pivAuthCert;
    private byte[] m_intermediateCVC;
    private boolean m_error_Detection_Code;

    /**
     * SecureMessagingCertificateSigner class constructor, initializes all the class fields.
     */
    public SecureMessagingCertificateSigner() {

        m_pivAuthCert = null;
        m_intermediateCVC = null;
        m_error_Detection_Code = false;
        m_content = new HashMap<BerTag, byte[]>();
    }

    /**
     *
     * Returns True if error Error Detection Code is present, false otherwise
     *
     * @return True if error Error Detection Code is present, false otherwise
     */
    @Override
	public boolean getErrorDetectionCode() {

        return m_error_Detection_Code;
    }

    /**
     *
     * Returns X509Certificate object containing X.509 Certificate for Content Signing
     *
     * @return X509Certificate object containing X.509 Certificate for Content Signing
     */
    public X509Certificate getCertificate() {
        return m_pivAuthCert;
    }

    /**
     *
     * Returns byte array with Intermediate CVC value
     *
     * @return Byte array containing Intermediate CVC value
     */
    public byte[] getIntermediateCVC() {
        return m_intermediateCVC;
    }

    /**
     *
     * Sets the Intermediate CVC value
     *
     * @param intermediateCVC Byte array containing Intermediate CVC value
     */
    public void setIntermediateCVC(byte[] intermediateCVC) {
        m_intermediateCVC = intermediateCVC;
    }

    /**
     *
     * Decode function that decodes Secure Messaging Certificate Signer object retrieved from the card and populates various class fields.
     *
     * @return True if decode was successful, false otherwise
     */
    @Override
	public boolean decode() {

        if(m_pivAuthCert == null){

            try{
                byte [] raw = super.getBytes();

                BerTlvParser tp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
                BerTlvs outer = tp.parse(raw);

                if(outer == null){
                    s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMap.get(super.getOID()));
                    return false;
                }

                List<BerTlv> values = outer.getList();
                for(BerTlv tlv : values) {
                    if(tlv.isPrimitive()) {
                        s_logger.trace("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                        BerTlvs outer2 = tp.parse(tlv.getBytesValue());

                        if(outer2 == null){
                            s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMap.get(super.getOID()));
                            return false;
                        }

                        List<BerTlv> values2 = outer2.getList();
                        byte[] rawCertBuf = null;
                        byte[] certInfoBuf = null;
                        for(BerTlv tlv2 : values2) {
                            if(tlv2.isPrimitive()) {
                                s_logger.trace("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            } else {
                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.CERTIFICATE_TAG)) {
                                    if (tlv2.hasRawValue()) {
                                        rawCertBuf = tlv2.getBytesValue();
                                        m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                    }
                                }
                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {
                                    if (tlv2.hasRawValue()) {
                                        m_error_Detection_Code = true;
                                        m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                    }
                                }
                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.CERTINFO_TAG)) {
                                    certInfoBuf = tlv2.getBytesValue();
                                    m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                }

                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.INTERMEDIATE_CVC_TAG)) {
                                    m_intermediateCVC = tlv2.getBytesValue();
                                    m_content.put(tlv2.getTag(), tlv2.getBytesValue());
                                }
                            }
                        }

                        InputStream certIS = null;
                        //Check if the certificate buffer is compressed
                        if(certInfoBuf != null && Arrays.equals(certInfoBuf, TagConstants.COMPRESSED_TAG)) {
                            certIS = new GZIPInputStream(new ByteArrayInputStream(rawCertBuf));
                        } else {
                            certIS = new ByteArrayInputStream(rawCertBuf);
                        }

                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        m_pivAuthCert = (X509Certificate)cf.generateCertificate(certIS);
                        s_logger.info(m_pivAuthCert.getSubjectDN().toString());
                    } else {
                        s_logger.info("Object: {}", Hex.encodeHexString(tlv.getTag().bytes));
                    }
                }
            }catch (Exception ex) {

                s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMap.get(super.getOID()), ex.getMessage());
                return false;
            }

            if (m_pivAuthCert == null)
                return false;
        }
        
        dump(this.getClass())
;
        return true;
    }
}
