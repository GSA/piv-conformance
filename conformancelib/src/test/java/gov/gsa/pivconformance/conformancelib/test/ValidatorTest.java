package gov.gsa.pivconformance.conformancelib.test;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import gov.gsa.pivconformance.conformancelib.utilities.Validator;

import java.io.*;
import java.nio.file.Path;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.fail;

public class ValidatorTest {
    private static final Path trustAnchor = Path.of("", "x509-certs");
    private KeyStore m_keystore = getKeyStore();
    private static Validator m_validator = new Validator();

    private KeyStore getKeyStore() {

        InputStream is = Validator.getFileFromResourceAsStream(ValidatorTest.class, "x509-certs/cacerts.keystore");
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(is, "changeit".toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return ks;
    }

    @DisplayName("Certificate Path Validation")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("positiveCaseCertProvider")
    public void testIsValid(String oid, String endEntityCertFile, TestReporter reporter) {
        final Path certsDir = Path.of("", "x509-certs/valid");
        try {
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            BufferedInputStream fis = (BufferedInputStream) Validator.getFileFromResourceAsStream(ValidatorTest.class, "x509-certs/valid" + File.separator + endEntityCertFile);
            X509Certificate eeCert = (X509Certificate) fac.generateCertificate(fis);
            X509Certificate trustAnchorCert = getTrustAnchorForGivenCertificate(certsDir, eeCert);
            System.out.println("Setting BC option");
            m_validator.setCpb("BC");
            System.out.print("Validating " + eeCert.getSubjectDN().getName());
            boolean result = m_validator.isValid(eeCert, oid, trustAnchorCert); //(eeCert, oid, trustAnchorCert;
            
            System.out.println("validator.isValid(): " + result);
            reporter.publishEntry(oid, String.valueOf(result));
            Assertions.assertTrue(result, "Failed for eeCert " + eeCert);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }

    private static Stream<Arguments> positiveCaseCertProvider() {
        final String policyFileName = "x509-certs/valid/policy.xml";
        try {
            ValidatorTest app = new ValidatorTest();
            InputStream inputStream = Validator.getFileFromResourceAsStream(app.getClass(), policyFileName);
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
            fail("Exception reading the policy.xml file.");
            return null;
        }
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
        System.out.println("Trust anchor: " + trustAnchorCert.getSubjectDN().getName());
        return trustAnchorCert;
    }
}
