package gov.gsa.pivconformance.conformancelib.test;

import gov.gsa.pivconformance.conformancelib.utilities.PathValidator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.fail;

class PathValidatorTest {
    private static final Path trustAnchor = Path.of("", "src/test/resources/trustAnchor");
    private PathValidator validator = new PathValidator();

    @DisplayName("Certificate Path Validation")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}, trustCA = {2}")
    @MethodSource("positiveCaseCertProvider")
    public void testIsValid(String oid, String eeCert, String trustCA, TestReporter reporter) {
        final Path certsDir = Path.of("", "src/test/resources/x509-certs/PositiveCases");
        File eeCertFile = certsDir.resolve(eeCert).toFile();
        File trustAnchorFile = trustAnchor.resolve(trustCA).toFile();

        boolean result = validator.isValid(eeCertFile, oid, trustAnchorFile);

        reporter.publishEntry(oid, String.valueOf(result));
        Assertions.assertTrue(result, "Failed for eeCert " + eeCert);
    }

    private static Stream<Arguments> positiveCaseCertProvider() {
        final Path certsDir = Path.of("", "src/test/resources/x509-certs/PositiveCases");
        String propertiesFile = certsDir + "/" + "policy.xml";
        try {
            InputStream inputStream = new BufferedInputStream(new FileInputStream(propertiesFile));
            Properties properties = new Properties();
            properties.loadFromXML(inputStream);
            List<Arguments> argumentsList = new ArrayList<>();
            properties.forEach((Object filename, Object oid) -> {
                String filenameStr = String.valueOf(filename).trim();
                String oidStr = String.valueOf(oid).trim();
                String trustCA = getTrustCAforGivenCertificate(certsDir, filenameStr);
                argumentsList.add(Arguments.of(oidStr, filenameStr, trustCA));
            });
            return argumentsList.stream();
        } catch (Exception e) {
            fail("Exception reading the policy.xml file.");
            return null;
        }
    }

    private static String getTrustCAforGivenCertificate(Path certsDir, String filenameStr)  {
        try {
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            File eeCertFile = certsDir.resolve(filenameStr.trim()).toFile();
            X509Certificate eeCert = (X509Certificate)
                    fac.generateCertificate(new FileInputStream(eeCertFile));

            String trustCA = "U.S_Government_Common_Policy.cer";
            if (eeCert.getSubjectDN().getName().contains("ICAM")) {
                trustCA = "ICAM_Test_Card_Root_CA.cer";
            }
            return trustCA;
        } catch (Exception e) {
            fail("Exception reading the certificate.");
        }
        return null;
    }
}
