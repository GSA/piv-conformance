package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPInputStream;

public class SecureMessagingCertificateSigner extends PIVDataObject {    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(SecureMessagingCertificateSigner.class);

    private X509Certificate m_pivAuthCert;
    private byte[] m_intermediateCVC;
    private boolean m_error_Detection_Code;

    public SecureMessagingCertificateSigner() {

        m_pivAuthCert = null;
        m_intermediateCVC = null;
        m_error_Detection_Code = false;
    }

    public boolean getErrorDetectionCode() {

        return m_error_Detection_Code;
    }

    public X509Certificate getCertificate() {
        return m_pivAuthCert;
    }

    public byte[] getIntermediateCVC() {
        return m_intermediateCVC;
    }

    public void setIntermediateCVC(byte[] intermediateCVC) {
        m_intermediateCVC = intermediateCVC;
    }

    public boolean decode() {

        if(m_pivAuthCert == null){

            try{
                byte [] raw = super.getBytes();

                BerTlvParser tp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
                BerTlvs outer = tp.parse(raw);

                if(outer == null){
                    s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMAP.get(super.getOID()));
                    return false;
                }

                List<BerTlv> values = outer.getList();
                for(BerTlv tlv : values) {
                    if(tlv.isPrimitive()) {
                        s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                        BerTlvs outer2 = tp.parse(tlv.getBytesValue());

                        if(outer2 == null){
                            s_logger.error("Error parsing {}, unable to parse TLV value.", APDUConstants.oidNameMAP.get(super.getOID()));
                            return false;
                        }

                        List<BerTlv> values2 = outer2.getList();
                        byte[] rawCertBuf = null;
                        byte[] certInfoBuf = null;
                        for(BerTlv tlv2 : values2) {
                            if(tlv2.isPrimitive()) {
                                s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            } else {
                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.CERTIFICATE_TAG)) {
                                    if (tlv2.hasRawValue()) {
                                        rawCertBuf = tlv2.getBytesValue();
                                    }
                                }
                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.ERROR_DETECTION_CODE_TAG)) {
                                    if (tlv2.hasRawValue()) {
                                        m_error_Detection_Code = true;
                                    }
                                }
                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.CERTINFO_TAG)) {
                                    certInfoBuf = tlv2.getBytesValue();
                                }

                                if(Arrays.equals(tlv2.getTag().bytes, TagConstants.INTERMEDIATE_CVC_TAG)) {
                                    m_intermediateCVC = tlv2.getBytesValue();
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

                        //Check to make sure certificate buffer is not null
                        if(certIS == null){
                            s_logger.error("Error parsing {}, unable to get certificate buffer.", APDUConstants.oidNameMAP.get(super.getOID()));
                            return false;
                        }

                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        m_pivAuthCert = (X509Certificate)cf.generateCertificate(certIS);
                        s_logger.info(m_pivAuthCert.getSubjectDN().toString());
                    } else {
                        s_logger.info("Object: {}", Hex.encodeHexString(tlv.getTag().bytes));
                    }
                }
            }catch (Exception ex) {

                s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
            }
        }
        return true;
    }


}
