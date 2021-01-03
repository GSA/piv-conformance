package gov.gsa.pivconformance.conformancelib.utilities;

import gov.gsa.pivconformance.conformancelib.tests.ConformanceTestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import static gov.gsa.pivconformance.conformancelib.utilities.TestRunLogController.pathFixup;
import static org.junit.jupiter.api.Assertions.fail;

public class ValidatorHelper {
    private static Logger s_logger = LoggerFactory.getLogger(ValidatorHelper.class);
    public enum PolicyOID {
        ID_FPKI_CERTPCY_PIVI_HARDWARE("2.16.840.1.101.3.2.1.3.18"),
        ID_FPKI_COMMON_HARDWARE("2.16.840.1.101.3.2.1.3.7"),
        ID_FPKI_COMMON_POLICY("2.16.840.1.101.3.2.1.3.6"),
        ID_FPKI_CERTPCY_BASICASSURANCE("2.16.840.1.101.3.2.1.3.2"),
        TEST_ID_FPKI_COMMON_CARDAUTH("2.16.840.1.101.3.2.1.48.13"),
        TEST_ID_FPKI_COMMON_AUTHENTICATION("2.16.840.1.101.3.2.1.48.11"),
        TEST_ID_FPKI_COMMON_HARDWARE("2.16.840.1.101.3.2.1.48.9"),
        TEST_ID_FPKI_CERTPCY_MEDIUMHARDWARE("2.16.840.1.101.3.2.1.48.4");

        private final String value;

        PolicyOID(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * Gets a file from the specified resource for the specified class.
     *
     * @param fileName the basename of the resource file
     * @return InputStream to the open resource or null if an en exception thrown
     * @throws ConformanceTestException if any error occurs
     */
    public static InputStream getStreamFromResourceFile(String fileName) throws ConformanceTestException {
        s_logger.debug("getStreamFromResourceFile:" + fileName);
        FileInputStream inputStream = null;
        String msg = null;

        try {
            String path = pathFixup(fileName);
            s_logger.debug("Opening [" + path + "]");
            inputStream = new FileInputStream(path);
        } catch (Exception e) {
            msg = "Exception [" + e.getMessage() + "] while accessing " + fileName;
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }

        return inputStream;
    }

    /**
     * Gets the trust anchor associated with the end-entity certificate based on Subject CN
     * @param keyStore keyStore object previously opened
     * @param eeCert end-entity certificate
     * @return X509Certificate of the trust anchor
     */

    public static X509Certificate getTrustAnchorForGivenCertificate(KeyStore keyStore, X509Certificate eeCert) throws ConformanceTestException {
        if (keyStore == null) {
            s_logger.error("getTrustAnchorForGivenCertificate: keyStore is null");
            return null;
        }
        if (eeCert == null) {
            s_logger.error("getTrustAnchorForGivenCertificate: eeCert is null");
            return null;
        }
        s_logger.debug("getTrustAnchorForGivenCertificate:" + eeCert.getSubjectDN().getName());
        String alias = null;
        X509Certificate trustAnchorCert = null;
        String subjectName = eeCert.getSubjectDN().getName();
        if (subjectName.contains("ICAM")) {
            if (subjectName.contains("PIV-I")) {
                alias = "icam test card piv-i root ca";
            } else {
                alias = "icam test card piv root ca";
            }
        } else {
            alias = "federal common policy ca";
        }

        try {
            trustAnchorCert = getCertFromKeyStore(keyStore, alias);
            if (trustAnchorCert == null) {
                String msg = "Couldn't get trust anchor from keyStore: " + alias;
                s_logger.error(msg);
                throw new ConformanceTestException(msg);
            }
        } catch (ConformanceTestException e) {
            throw e;
        } catch (Exception e) {
            String msg = "getTrustAnchorForGivenCertificate: " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }
        s_logger.debug("Trust anchor: " + trustAnchorCert.getSubjectDN().getName());
        return trustAnchorCert;
    }

    /**
     * Get a certificate from the specified keystore using the given alias
     * @param ks keytore object
     * @param alias certificate alias
     * @return X509Certificate object of the given certificate or null
     */

    public static X509Certificate getCertFromKeyStore(KeyStore ks, String alias) throws ConformanceTestException {
        if (ks == null) {
            s_logger.error("getCertFromKeyStore: ks is null");
            return null;
        }
        if (alias == null) {
            s_logger.error("getCertFromKeyStore: alias is null");
            return null;
        }

        s_logger.debug("getCertFromKeyStore: " + alias);
        try {
            if (ks.containsAlias(alias)) {
                return (X509Certificate) ks.getCertificate(alias);
            } else {
                String msg = "getCertFromKeyStore: Couldn't find cert with alias [" + alias + "]";
                s_logger.error(msg);
                throw new ConformanceTestException(msg);
            }
        } catch (Exception e) {
            String message = e.getMessage();
            s_logger.error("getCertFromKeyStore: " + message);
            throw new ConformanceTestException(message);
        }
    }
}
