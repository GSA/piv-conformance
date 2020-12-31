package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.conformancelib.utilities.Validator;
import gov.gsa.pivconformance.conformancelib.utilities.ValidatorHelper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.fail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URL;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

public class ValidatorTest {
    static Logger s_logger = LoggerFactory.getLogger(ValidatorTest.class);

    final Path certsDir = Path.of("", "x509-certs/valid");
    private static Validator m_validator;

    static {
        try {
            m_validator = new Validator();
        } catch (ConformanceTestException e) {
            e.printStackTrace();
        }
    }

    @Tag("PKI")
    @DisplayName("Certificate Path Validation Control")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("positiveCaseCertProvider")
    void testControl(String oid, String endEntityCertFile, TestReporter reporter) {
        System.out.println("3a " + System.getProperty("user.dir") + File.separator + "**");
    }

    @Tag("PD_VAL")
    @DisplayName("Certificate Path Validation Sun")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("positiveCaseCertProvider")
    void testIsValid_Sun(String oid, String endEntityCertFile, TestReporter reporter) {
        s_logger.debug("3b " + System.getProperty("user.dir") + File.separator + "**");
        try {
            m_validator = new Validator("Sun");
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            BufferedInputStream fis = (BufferedInputStream) ValidatorHelper.getFileFromResourceAsStream(ValidatorTest.class, "x509-certs/valid" + File.separator + endEntityCertFile);
            X509Certificate eeCert = (X509Certificate) fac.generateCertificate(fis);
            X509Certificate trustAnchorCert = getTrustAnchorForGivenCertificate(certsDir, eeCert);
            System.out.print("Validating " + eeCert.getSubjectDN().getName());
            boolean result = m_validator.isValid(eeCert, oid, trustAnchorCert); //(eeCert, oid, trustAnchorCert;
            
            s_logger.debug("validator.isValid(): " + result);
            reporter.publishEntry(oid, String.valueOf(result));
            Assertions.assertTrue(result, "Failed for eeCert " + eeCert);
        } catch (Exception e) {
            s_logger.debug(e.getMessage());
            e.printStackTrace();
        }
    }
    @Tag("PD_VAL")
    @DisplayName("Certificate Path Validation BouncyCastle")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("positiveCaseCertProvider")
    void testIsValid_BouncyCastle(String oid, String endEntityCertFile, TestReporter reporter) {
        final Path certsDir = Path.of("", "x509-certs/valid");
        s_logger.debug("3c " + System.getProperty("user.dir") + File.separator + "**");
        try {
            m_validator = new Validator("BC");
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            BufferedInputStream fis = (BufferedInputStream) ValidatorHelper.getFileFromResourceAsStream(ValidatorTest.class, "x509-certs/valid" + File.separator + endEntityCertFile);
            X509Certificate eeCert = (X509Certificate) fac.generateCertificate(fis);
            X509Certificate trustAnchorCert = getTrustAnchorForGivenCertificate(certsDir, eeCert);
            System.out.print("Validating " + eeCert.getSubjectDN().getName());
            boolean result = m_validator.isValid(eeCert, oid, trustAnchorCert); //(eeCert, oid, trustAnchorCert;
            s_logger.debug("validator.isValid(): " + result);
            reporter.publishEntry(oid, String.valueOf(result));
            Assertions.assertTrue(result, "Failed for eeCert " + eeCert);
        } catch (Exception e) {
            s_logger.debug(e.getMessage());
            e.printStackTrace();
        }
    }

    private static Stream<Arguments> positiveCaseCertProvider() throws ConformanceTestException {
        final String policyFileName = "x509-certs/valid/policy.xml";
        String estr = null;
        s_logger.debug("user.dir: " + System.getProperty("user.dir") + File.separator + policyFileName);
        try {
            String userDirFile = new URL(System.getProperty("user.dir") + File.separator + policyFileName).getFile();
            s_logger.debug("userDirFile: " + userDirFile);
            String userDirPath = new URL(System.getProperty("user.dir") + File.separator + policyFileName).getPath();
            s_logger.debug("userDirPath: " + userDirPath);
            Module module  = ValidatorTest.class.getModule();
            if (module != null) {
                s_logger.debug("4. " + String.valueOf(module));
                s_logger.debug("5. " + module.getName());
                s_logger.debug("6. " + String.valueOf(module.isNamed()));
                s_logger.debug("7. " + String.valueOf(module.getDescriptor()));

                InputStream inputStream = ValidatorHelper.getFileFromResourceAsStream(new ValidatorTest().getClass(), policyFileName);
                Properties properties = new Properties();
                properties.loadFromXML(inputStream);
                List<Arguments> argumentsList = new ArrayList<>();
                properties.forEach((Object filename, Object oid) -> {
                    String filenameStr = String.valueOf(filename).trim();
                    String oidStr = String.valueOf(oid).trim();
                    argumentsList.add(Arguments.of(oidStr, filenameStr));
                });
                return argumentsList.stream();
            } else {
                estr = "Module for '" + ValidatorTest.class.getClass() + "' not found reading the policy.xml file.";
            }
        } catch (Exception e) {
            estr = e.getMessage();
            s_logger.error("Exception '" + estr + "' while reading the policy.xml file.");
        }
        throw new ConformanceTestException(estr);
    }

    public static X509Certificate getCertFromKeyStore(KeyStore ks, String alias) {
        try {
            if (ks.containsAlias(alias)) {
                return (X509Certificate) ks.getCertificate(alias);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    private static X509Certificate getTrustAnchorForGivenCertificate(Path certsDir, X509Certificate eeCert)  {
        String trustCA = null;
        X509Certificate trustAnchorCert = null;
        try {
            if (eeCert.getSubjectDN().getName().contains("ICAM")) {
                trustCA = "icam test card root ca";
            } else {
                trustCA = "federal common policy ca";
            }
        } catch (Exception e) {
            fail("Exception reading the certificate.");
        }
        trustAnchorCert = getCertFromKeyStore(m_validator.getKeyStore(), trustCA);
        s_logger.debug("Trust anchor: " + trustAnchorCert.getSubjectDN().getName());
        return trustAnchorCert;
    }
}
