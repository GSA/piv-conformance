package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.BerTlv;
import gov.gsa.pivconformance.tlv.BerTlvs;
import gov.gsa.pivconformance.tlv.BerTlvParser;
import gov.gsa.pivconformance.tlv.CCTTlvLogger;
import gov.gsa.pivconformance.tools.PIVRunner;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.List;
import java.io.ByteArrayInputStream;

public class X509CertificateForPIVAuthentication extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(X509CertificateForPIVAuthentication.class);

    private X509Certificate m_pivAuthCert;

    public X509CertificateForPIVAuthentication() {

        m_pivAuthCert = null;
    }

    public X509Certificate getCertificate() {

        if(m_pivAuthCert == null){

            try{
                byte [] raw = super.getBytes();

                s_logger.info("RAW CERT INFO: {}", Hex.encodeHexString(raw));

                BerTlvParser tp = new BerTlvParser(new CCTTlvLogger(PIVRunner.class));
                BerTlvs outer = tp.parse(raw);
                List<BerTlv> values = outer.getList();
                for(BerTlv tlv : values) {
                    if(tlv.isPrimitive()) {
                        s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));

                        //BerTlvs values3 = tp.parse(tlv.getBytesValue());
                        BerTlv outer2 = tp.parseConstructed(tlv.getBytesValue());
                        List<BerTlv> values2 = outer2.getValues();
                        for(BerTlv tlv2 : values) {
                            if(tlv.isPrimitive()) {
                                s_logger.info("Tag {}: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));
                            }
                        }

                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        X509Certificate m_pivAuthCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(tlv.getBytesValue()));
                    } else {
                        s_logger.info("Object: {}", Hex.encodeHexString(tlv.getTag().bytes));
                    }
                }
            }catch (Exception ex) {

                s_logger.error("Error parsing X.509 Certificate for PIV Authentication object: {}", ex.getMessage());
            }
        }


        return m_pivAuthCert;
    }
}
