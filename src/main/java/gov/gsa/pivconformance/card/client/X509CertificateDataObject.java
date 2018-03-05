package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import gov.gsa.pivconformance.tools.PIVRunner;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.util.zip.GZIPInputStream;

public class X509CertificateDataObject extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(X509CertificateDataObject.class);

    private X509Certificate m_pivAuthCert;

    public X509CertificateDataObject() {

        m_pivAuthCert = null;
    }

    public X509Certificate getCertificate() {

        if(m_pivAuthCert == null){

            try{
                byte [] raw = super.getBytes();

                BerTlvParser tp = new BerTlvParser(new CCTTlvLogger(PIVRunner.class));
                BerTlvs outer = tp.parse(raw);

                List<BerTlv> values = outer.getList();
                for(BerTlv tlv : values) {
                    if(tlv.isPrimitive()) {
                        s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                        BerTlvs outer2 = tp.parse(tlv.getBytesValue());

                        List<BerTlv> values2 = outer2.getList();
                        byte[] rawCertBuf = null;
                        byte[] certInfoBuf = null;
                        for(BerTlv tlv2 : values2) {
                            if(tlv2.isPrimitive()) {
                                s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(tlv2.getBytesValue()));
                            } else {
                                if(tlv2.getTag().bytes == TagConstants.CERTIFICATE_TAG) {
                                    if (tlv2.hasRawValue()) {
                                        rawCertBuf = tlv2.getBytesValue();
                                        s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv2.getTag().bytes), Hex.encodeHexString(rawCertBuf));
                                    }
                                }
                                if(tlv2.getTag().bytes == TagConstants.CERTINFO_TAG) {
                                    certInfoBuf = tlv2.getBytesValue();
                                    s_logger.info("Got cert info buffer: {}", Hex.encodeHexString(certInfoBuf));
                                }
                            }
                        }

                        InputStream certIS = null;
                        //Check if the certificate buffer is compressed
                        if(certInfoBuf != null && certInfoBuf == TagConstants.COMPRESSED_TAG) {
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
            }
        }


        return m_pivAuthCert;
    }
}
