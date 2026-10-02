package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.conformancelib.utilities.Validator;
import gov.gsa.pivconformance.conformancelib.utilities.ValidatorHelper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

import static gov.gsa.pivconformance.conformancelib.utilities.ValidatorHelper.getTrustAnchorForGivenCertificate;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    @Tag("ExternalCertificateFixture")
    @DisplayName("Certificate Path Validation Sun")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("positiveCaseCertProvider")
    void testIsValid_Sun(String oid, String endEntityCertFile, TestReporter reporter) throws Exception {
        s_logger.debug("testIsValid_Sun oid: " + oid);
        s_logger.debug("testIsValid_Sun endEntityCertFile: " + endEntityCertFile);
        s_logger.debug("testIsValid_Sun reporter: " + reporter.toString());
        m_validator = new Validator("SunRsaSign");
        m_validator.setProvider("SunRsaSign");
        m_validator.setCertPathBuilder("SUN");
        assertEquals("SunRsaSign", m_validator.getProvider());
        assertEquals("SUN", m_validator.getCertPathBuilder().getProvider().getName());
        try (ValidatorHelper.OpenedResource fixture = ValidatorHelper.openExternalFile(
                certificateFixturePath(endEntityCertFile));
             InputStream fis = fixture.stream()) {
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            X509Certificate eeCert = (X509Certificate) fac.generateCertificate(fis);
            X509Certificate trustAnchorCert = getTrustAnchorForGivenCertificate(m_validator.getKeyStore(), eeCert, null);
            s_logger.debug("Validating " + eeCert.getSubjectDN().getName());
            boolean result = m_validator.isValid(eeCert, oid, trustAnchorCert); //(eeCert, oid, trustAnchorCert;
            
            s_logger.debug("m_validator.isValid(): " + result);
            reporter.publishEntry(oid, String.valueOf(result));
            assertTrue(result, "Failed for eeCert " + eeCert);
        }
    }
    @Tag("BC")
    @Tag("ExternalCertificateFixture")
    @DisplayName("Certificate Path Validation BouncyCastle")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("positiveCaseCertProvider")
    void testIsValid_BouncyCastle(String oid, String endEntityCertFile, TestReporter reporter) throws Exception {
        s_logger.debug("testIsValid_BouncyCastle oid: " + oid);
        s_logger.debug("testIsValid_BouncyCastle endEntityCertFile: " + endEntityCertFile);
        s_logger.debug("testIsValid_BouncyCastle reporter: " + reporter.toString());
        m_validator = new Validator("BC");
        m_validator.setProvider("BC");
        m_validator.setCertPathBuilder("BC");
        assertEquals("BC", m_validator.getProvider());
        assertEquals("BC", m_validator.getCertPathBuilder().getProvider().getName());
        try (ValidatorHelper.OpenedResource fixture = ValidatorHelper.openExternalFile(
                certificateFixturePath(endEntityCertFile));
             InputStream fis = fixture.stream()) {
            s_logger.debug("m_validator: " + m_validator.toString());
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            X509Certificate eeCert = (X509Certificate) fac.generateCertificate(fis);
            X509Certificate trustAnchorCert = getTrustAnchorForGivenCertificate(m_validator.getKeyStore(), eeCert, null);
            s_logger.debug("Validating " + eeCert.getSubjectDN().getName());
            boolean result = m_validator.isValid(eeCert, oid, trustAnchorCert); //(eeCert, oid, trustAnchorCert;
            s_logger.debug("m_validator.isValid(): " + result);
            reporter.publishEntry(oid, String.valueOf(result));
            assertTrue(result, "Failed for eeCert " + eeCert);
        }
    }

    @Test
    @Tag("Sun")
    @DisplayName("Packaged validation resources load without relying on the working directory")
    void testPackagedValidationResources() throws Exception {
        try (ValidatorHelper.OpenedResource resource =
                     ValidatorHelper.openDefaultResource("x509-certs/valid/policy.xml");
             InputStream policy = resource.stream()) {
            Properties properties = new Properties();
            properties.loadFromXML(policy);
            assertEquals(12, properties.size());
            assertEquals(ValidatorHelper.ResourceSource.CLASSPATH, resource.source());
        }
        Validator validator = new Validator("SunRsaSign");
        assertNotNull(validator.getKeyStore());
    }

    @Test
    @Tag("Sun")
    @DisplayName("An explicit readable external file is used")
    void testExplicitExternalFile(@TempDir Path temporaryDirectory) throws Exception {
        Path externalFile = temporaryDirectory.resolve("external.properties");
        Files.writeString(externalFile, "source=external", StandardCharsets.UTF_8);
        try (ValidatorHelper.OpenedResource resource =
                     ValidatorHelper.openExternalFile(externalFile.toString())) {
            assertEquals(ValidatorHelper.ResourceSource.EXTERNAL_FILE, resource.source());
            assertEquals("source=external", new String(resource.stream().readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    @Test
    @Tag("Sun")
    @DisplayName("A readable external default takes precedence over the same-named bundled resource")
    void testReadableExternalDefaultTakesPrecedenceOverBundledResource() throws Exception {
        String resourceName = "pdval.properties";
        String externalContents = "source=external-default\n";
        try (ValidatorHelper.OpenedResource bundledResource =
                     ValidatorHelper.openBundledResource(resourceName)) {
            assertEquals(ValidatorHelper.ResourceSource.CLASSPATH, bundledResource.source());
            assertNotEquals(externalContents,
                    new String(bundledResource.stream().readAllBytes(), StandardCharsets.UTF_8));
        }

        Path externalDefault = Path.of(resourceName).toAbsolutePath().normalize();
        assertFalse(Files.exists(externalDefault),
                "The isolated test working directory must not already contain the external default");
        try {
            Files.writeString(externalDefault, externalContents, StandardCharsets.UTF_8);
            try (ValidatorHelper.OpenedResource selectedResource =
                         ValidatorHelper.openDefaultResource(resourceName)) {
                assertEquals(ValidatorHelper.ResourceSource.EXTERNAL_FILE, selectedResource.source());
                assertEquals(externalDefault.toString(), selectedResource.location());
                assertEquals(externalContents,
                        new String(selectedResource.stream().readAllBytes(), StandardCharsets.UTF_8));
            }
        } finally {
            Files.deleteIfExists(externalDefault);
        }
    }

    @Test
    @Tag("Sun")
    @DisplayName("An explicit missing external file fails closed")
    void testMissingExplicitExternalFile(@TempDir Path temporaryDirectory) {
        assertThrows(ConformanceTestException.class,
                () -> ValidatorHelper.openExternalFile(temporaryDirectory.resolve("missing.properties").toString()));
    }

    @Test
    @Tag("Sun")
    @DisplayName("A bundled default resource loads from the classpath")
    void testBundledDefaultResource() throws Exception {
        try (ValidatorHelper.OpenedResource resource = ValidatorHelper.openDefaultResource("pdval.properties")) {
            assertEquals(ValidatorHelper.ResourceSource.CLASSPATH, resource.source());
            assertTrue(resource.stream().readAllBytes().length > 0);
        }
    }

    @Test
    @Tag("Sun")
    @DisplayName("Bundled defaults do not depend on the repository working directory")
    void testBundledDefaultOutsideRepositoryWorkingDirectory() throws Exception {
        assertTrue(Path.of("").toAbsolutePath().normalize().toString().contains("build"));
        try (ValidatorHelper.OpenedResource resource =
                     ValidatorHelper.openDefaultResource("x509-certs/valid/policy.xml")) {
            assertEquals(ValidatorHelper.ResourceSource.CLASSPATH, resource.source());
        }
    }

    @Test
    @Tag("Sun")
    @DisplayName("A missing explicit file never resolves to a same-named bundled file")
    void testMissingExplicitFileDoesNotUseBundledResource(@TempDir Path temporaryDirectory) throws Exception {
        Path missingExternal = temporaryDirectory.resolve("pdval.properties");
        assertThrows(ConformanceTestException.class,
                () -> ValidatorHelper.openExternalFile(missingExternal.toString()));
        try (ValidatorHelper.OpenedResource resource = ValidatorHelper.openBundledResource("pdval.properties")) {
            assertEquals(ValidatorHelper.ResourceSource.CLASSPATH, resource.source());
        }
    }

    @Test
    @Tag("Sun")
    @DisplayName("Classpath resource names use platform-independent separators")
    void testClasspathSeparatorNormalization() throws Exception {
        try (ValidatorHelper.OpenedResource resource =
                     ValidatorHelper.openBundledResource("x509-certs\\valid\\policy.xml")) {
            assertEquals("x509-certs/valid/policy.xml", resource.location());
        }
    }

    private static Stream<Arguments> positiveCaseCertProvider() throws ConformanceTestException {
        final String policyFileName = "x509-certs/valid/policy.xml";
        String estr = policyFileName;
        s_logger.debug(estr);
        try {
            Properties properties = new Properties();
            try (ValidatorHelper.OpenedResource resource = ValidatorHelper.openDefaultResource(estr);
                 InputStream inputStream = resource.stream()) {
                properties.loadFromXML(inputStream);
            }
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

    private static String certificateFixturePath(String endEntityCertFile) {
        String fixtureDirectory = System.getProperty("cct.certificateFixtureDir");
        if (fixtureDirectory == null || fixtureDirectory.isBlank()) {
            throw new IllegalStateException("cct.certificateFixtureDir was not configured by certificateFixtureTest");
        }
        return Path.of(fixtureDirectory, endEntityCertFile).toString();
    }

}
