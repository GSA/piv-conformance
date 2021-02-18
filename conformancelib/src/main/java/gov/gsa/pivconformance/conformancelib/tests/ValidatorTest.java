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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

import static gov.gsa.pivconformance.conformancelib.utilities.TestRunLogController.pathFixup;
import static gov.gsa.pivconformance.conformancelib.utilities.ValidatorHelper.getTrustAnchorForGivenCertificate;

public class ValidatorTest {
    static Logger s_logger = LoggerFactory.getLogger(ValidatorTest.class);
    private static Validator m_validator;

    static {
        try {
            m_validator = new Validator();
        } catch (ConformanceTestException e) {
            e.printStackTrace();
        }
    }

    @Tag("PD_VAL")
    @DisplayName("Certificate Path Validation Control")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("positiveCaseCertProvider")
    void testControl(String oid, String endEntityCertFile, TestReporter reporter) {
        s_logger.debug("testControl oid: " + oid);
        s_logger.debug("testControl endEntityCertFile: " + endEntityCertFile);
        s_logger.debug("testControl reporter: " + reporter.toString());
    }

    @Tag("Sun")
    @DisplayName("Certificate Path Validation Sun")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("positiveCaseCertProvider")
    void testIsValid_Sun(String oid, String endEntityCertFile, TestReporter reporter) {
        s_logger.debug("testIsValid_Sun oid: " + oid);
        s_logger.debug("testIsValid_Sun endEntityCertFile: " + endEntityCertFile);
        s_logger.debug("testIsValid_Sun reporter: " + reporter.toString());
        try {
            m_validator = new Validator("Sun");
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            InputStream fis = ValidatorHelper.getStreamFromResourceFile(System.getProperty("user.dir") + File.separator + "x509-certs/valid" + File.separator + endEntityCertFile);
            X509Certificate eeCert = (X509Certificate) fac.generateCertificate(fis);
            X509Certificate trustAnchorCert = getTrustAnchorForGivenCertificate(m_validator.getKeyStore(), eeCert, null);
            s_logger.debug("Validating " + eeCert.getSubjectDN().getName());
            boolean result = m_validator.isValid(eeCert, oid, trustAnchorCert); //(eeCert, oid, trustAnchorCert;
            
            s_logger.debug("m_validator.isValid(): " + result);
            reporter.publishEntry(oid, String.valueOf(result));
            Assertions.assertTrue(result, "Failed for eeCert " + eeCert);
        } catch (Exception e) {
            s_logger.debug(e.getMessage());
            e.printStackTrace();
        }
    }
    @Tag("BC")
    @DisplayName("Certificate Path Validation BouncyCastle")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("positiveCaseCertProvider")
    void testIsValid_BouncyCastle(String oid, String endEntityCertFile, TestReporter reporter) {
        final Path certsDir = Path.of("", "x509-certs/valid");
        s_logger.debug("testIsValid_BouncyCastle oid: " + oid);
        s_logger.debug("testIsValid_BouncyCastle endEntityCertFile: " + endEntityCertFile);
        s_logger.debug("testIsValid_BouncyCastle reporter: " + reporter.toString());
        try {
            m_validator = new Validator("BC");
            s_logger.debug("m_validator: " + m_validator.toString());
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            InputStream fis = ValidatorHelper.getStreamFromResourceFile(System.getProperty("user.dir") + File.separator + "x509-certs/valid" + File.separator + endEntityCertFile);
            X509Certificate eeCert = (X509Certificate) fac.generateCertificate(fis);
            X509Certificate trustAnchorCert = getTrustAnchorForGivenCertificate(m_validator.getKeyStore(), eeCert, null);
            s_logger.debug("Validating " + eeCert.getSubjectDN().getName());
            boolean result = m_validator.isValid(eeCert, oid, trustAnchorCert); //(eeCert, oid, trustAnchorCert;
            s_logger.debug("m_validator.isValid(): " + result);
            reporter.publishEntry(oid, String.valueOf(result));
            Assertions.assertTrue(result, "Failed for eeCert " + eeCert);
        } catch (Exception e) {
            s_logger.debug(e.getMessage());
            e.printStackTrace();
        }
    }

    private static Stream<Arguments> positiveCaseCertProvider() throws ConformanceTestException {
        final String policyFileName = "x509-certs/valid/policy.xml";
        String estr = pathFixup(System.getProperty("user.dir") + File.separator + policyFileName);
        s_logger.debug(estr);
        try {
//            String userDirFile = new URL(System.getProperty("user.dir") + File.separator + policyFileName).getFile();
//            s_logger.debug("userDirFile: " + userDirFile);
//            String userDirPath = new URL(System.getProperty("user.dir") + File.separator + policyFileName).getPath();
//            s_logger.debug("userDirPath: " + userDirPath);

            InputStream inputStream = ValidatorHelper.getStreamFromResourceFile(estr);
            Properties properties = new Properties();
            properties.loadFromXML(inputStream);
            List<Arguments> argumentsList = new ArrayList<>();
            properties.forEach((Object filename, Object oid) -> {
                String filenameStr = String.valueOf(filename).trim();
                String oidStr = String.valueOf(oid).trim();
                argumentsList.add(Arguments.of(oidStr, filenameStr));
            });
            return argumentsList.stream();
        } catch (Exception e) {
            estr = e.getMessage();
            s_logger.error("Exception '" + estr + "' while reading the policy.xml file.");
        }
        throw new ConformanceTestException(estr);
    }

}
