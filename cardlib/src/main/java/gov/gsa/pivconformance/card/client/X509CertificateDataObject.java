package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import gov.gsa.pivconformance.tools.PIVRunner;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.util.zip.GZIPInputStream;

/**
 *
 * Encapsulates data object that store   as defined by SP800-73-4 Part 2 Appendix A Table 8
 *
 */
public class X509CertificateDataObject extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(X509CertificateDataObject.class);

    private X509Certificate m_pivAuthCert;
    private boolean m_error_Detection_Code;

    /**
     * CardCapabilityContainer class constructor, initializes all the class fields.
     */
    public X509CertificateDataObject() {

        m_pivAuthCert = null;
        m_error_Detection_Code = false;
    }

    /**
     * Returns boolean value indicating if error detection code is present
     *
     * @return Boolean value indicating if error detection code is present
     */
    public boolean getErrorDetectionCode() {

        return m_error_Detection_Code;
    }

    /**
     *
     * Returns X509Certificate object containing the certificate in the PIV data object
     *
     * @return X509Certificate object containing the certificate in the PIV data object
     */
    public X509Certificate getCertificate() {
        return m_pivAuthCert;
    }

    /**
     *
     * Decode function that decodes PIV data object object containing x509 certificate retrieved from the card and populates various class fields.
     *
     * @return True if decode was successful, false otherwise
     */
    public boolean decode() {

        if(m_pivAuthCert == null){

            try{
                byte [] raw = super.getBytes();

                s_logger.debug("rawBytes: {}", Hex.encodeHexString(raw));

                BerTlvParser tp = new BerTlvParser(new CCTTlvLogger(X509CertificateDataObject.class));
                BerTlvs outer = tp.parse(raw);

                if(outer == null){
                    s_logger.error("Error parsing X.509 Certificate, unable to parse TLV value.");
                    return false;
                }

                List<BerTlv> values = outer.getList();
                for(BerTlv tlv : values) {
                    if(tlv.isPrimitive()) {
                        s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                        BerTlvs outer2 = tp.parse(tlv.getBytesValue());

                        if(outer2 == null){
                            s_logger.error("Error parsing X.509 Certificate, unable to parse TLV value.");
                            return false;
                        }

                        List<BerTlv> values2 = outer2.getList();
                        byte[] rawCertBuf = null;
                        byte[] certInfoBuf = null;
                        byte[] mSCUIDBuf = null;
                        for(BerTlv tlv2 : values2) {
                            if(tlv2.isPrimitive()) {
                                s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            } else {
                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.CERTIFICATE_TAG)) {
                                    if (tlv2.hasRawValue()) {
                                        rawCertBuf = tlv2.getBytesValue();
                                        s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(rawCertBuf));
                                    }
                                }
                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {
                                    if (tlv2.hasRawValue()) {
                                        m_error_Detection_Code = true;
                                    }
                                }
                                                                
                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.CERTINFO_TAG)) {
                                    certInfoBuf = tlv2.getBytesValue();
                                    s_logger.info("Got cert info buffer: {}", Hex.encodeHexString(certInfoBuf));
                                }
                                
                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.MSCUID_TAG)) {
                                	mSCUIDBuf = tlv2.getBytesValue();
                                    s_logger.info("Got MSCUID buffer: {}", Hex.encodeHexString(mSCUIDBuf));
                                }
                            }
                        }

                        //Check to make sure certificate buffer is not null
                        if(rawCertBuf != null && rawCertBuf.length > 0) {
                            s_logger.error("Error parsing X.509 Certificate, unable to get certificate buffer.");
                            return false;
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

                s_logger.error("Error parsing X.509 Certificate: {}", ex.getMessage());
                return false;
            }

            if (m_pivAuthCert == null)
                return false;

        }
        return true;
    }
}
