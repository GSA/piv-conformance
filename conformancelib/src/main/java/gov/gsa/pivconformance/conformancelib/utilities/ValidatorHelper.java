package gov.gsa.pivconformance.conformancelib.utilities;

import gov.gsa.pivconformance.conformancelib.tests.ConformanceTestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static gov.gsa.pivconformance.conformancelib.utilities.TestRunLogController.pathFixup;
import static org.junit.jupiter.api.Assertions.fail;

public class ValidatorHelper {
    private static final Logger s_logger = LoggerFactory.getLogger(ValidatorHelper.class);
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

    public static X509Certificate getX509CertificateFromPath(String fullPathName) throws ConformanceTestException {
        String v_fullPathName = TestRunLogController.pathFixup(fullPathName);
        s_logger.debug("getX509CertificateFromPath(" + v_fullPathName + ")");
        X509Certificate rv = null;
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Path path = Paths.get(v_fullPathName);
            byte[] certBytes = Files.readAllBytes(path);
            ByteArrayInputStream bis = new ByteArrayInputStream(certBytes);
            final Collection<? extends Certificate> certs = certFactory.generateCertificates(bis);
            rv = (X509Certificate) certs.toArray()[0];
        } catch (Exception e) {
            String msg = "getX509CertificateFromPath exception: " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }
        return rv;
    }

    /**
     * Read properties from a file
     * @param fileName Property file name
     * @return Properties object
     * @throws Exception
     * @throws ConformanceTestException if an error occurs
     */
    public static Properties readPropertiesFile(String fileName) throws ConformanceTestException {
        Properties properties = null;
        String path = pathFixup(System.getProperty("user.dir") + File.separator + fileName);
        s_logger.debug("Opening properties file " + path);
        try {
            InputStream is = new FileInputStream(path);
            properties = new Properties();
            properties.load(is);
            is.close();
            s_logger.debug("Loaded properties from " + path);
        } catch (Exception e) {
            String msg = "readPropertiesFile exception: " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }

        return properties;
    }

    /**
     * Gets a file from the specified resource for the specified class.
     *
     * @param fileName the basename of the resource file
     * @return InputStream to the open resource or null if an en exception thrown
     * @throws ConformanceTestException if any error occurs
     */
    public static InputStream getStreamFromResourceFile(String fileName) throws ConformanceTestException {
        FileInputStream inputStream = null;
        String path = pathFixup(fileName);
        try {
            s_logger.debug("Getting stream from resource file " + path);
            inputStream = new FileInputStream(path);
        } catch (Exception e) {
            String msg = "getStreamFromResourceFile exception: " + e.getMessage() + " while accessing " + path;
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
     * @throws ConformanceTestException
     */

    public static X509Certificate getTrustAnchorForGivenCertificate(KeyStore keyStore, X509Certificate eeCert) throws ConformanceTestException {
        if (keyStore == null) {
            s_logger.error("keyStore is null");
            return null;
        }
        if (eeCert == null) {
            s_logger.error("eeCert is null");
            return null;
        }
        s_logger.debug("Getting trust anchor for EE certificate " + eeCert.getSubjectDN().getName());
        String alias = null;
        X509Certificate trustAnchorCert = null;
        String subjectName = eeCert.getSubjectDN().getName();
        String notBefore = eeCert.getNotBefore().toString();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd h:m");

        if (subjectName.contains("ICAM")) {
            if (subjectName.contains("PIV-I")) {
                alias = "icam test card piv-i root ca";
            } else {
                alias = "icam test card piv root ca";
            }
        } else {
            alias = "federal common policy ca g2";
        }

        try {
            trustAnchorCert = getCertFromKeyStore(keyStore, alias);
            if (trustAnchorCert == null) {
                String msg = "Couldn't find keyStore trust anchor for " + alias;
                s_logger.error(msg);
                throw new ConformanceTestException(msg);
            }
        } catch (ConformanceTestException e) {
            throw e;
        } catch (Exception e) {
            String msg = "getTrustAnchorForGivenCertificate exception: " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }
        s_logger.debug("Trust anchor is " + trustAnchorCert.getSubjectDN().getName());
        return trustAnchorCert;
    }

    /**
     * Get a certificate from the specified keystore using the given alias
     * @param keyStore keytore object
     * @param alias certificate alias
     * @return X509Certificate object of the given certificate or null
     */

    public static X509Certificate getCertFromKeyStore(KeyStore keyStore, String alias) throws ConformanceTestException {
        if (keyStore == null) {
            s_logger.error("keyStore is null");
            return null;
        }
        if (alias == null) {
            s_logger.error("alias is null");
            return null;
        }

        s_logger.debug("Getting '" + alias + "' from keystore");
        try {
            if (keyStore.containsAlias(alias)) {
                return (X509Certificate) keyStore.getCertificate(alias);
            } else {
                String msg = "Couldn't find cert with alias '" + alias + "'";
                s_logger.error(msg);
                throw new ConformanceTestException(msg);
            }
        } catch (Exception e) {
            String msg = e.getMessage();
            s_logger.error("getCertFromKeyStore exception: " + msg);
            throw new ConformanceTestException(msg);
        }
    }

    /**
     * Scrubs a common name of special characters that would otherwise be illegal
     * or ambiguous in a file name.
     * @param name the name to be scrubbed
     * @return a clean name
     */

    public static String scrubName(String name) {
        return name
                .replace("CN=", "")
                .replace("OU=", "")
                .replace("O=", "")
                .replace("C=", "")
                .replaceFirst(", .*$", "")
                .replace(" ", "_")
                .replaceAll("[^A-Za-z0-9.-]", "_")
                .toLowerCase();
    }
}
