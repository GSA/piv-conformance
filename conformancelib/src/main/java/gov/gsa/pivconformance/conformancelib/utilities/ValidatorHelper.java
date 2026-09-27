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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.fail;

public class ValidatorHelper {

    private static final Logger s_logger = LoggerFactory.getLogger(ValidatorHelper.class);

    public enum ResourceSource {
        EXTERNAL_FILE,
        CLASSPATH
    }

    /**
     * An opened resource together with the non-secret source selected for it.
     */
    public record OpenedResource(InputStream stream, ResourceSource source, String location)
            implements AutoCloseable {
        @Override
        public void close() throws IOException {
            stream.close();
        }
    }

    /**
     * Properties loaded through the documented default-resource boundary.
     */
    public record LoadedProperties(Properties properties, ResourceSource source, String location) {
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
    public static LoadedProperties readDefaultProperties(String fileName) throws ConformanceTestException {
        try (OpenedResource resource = openDefaultResource(fileName)) {
            Properties properties = new Properties();
            properties.load(resource.stream());
            s_logger.info("Loaded default properties from {} {}", resource.source(), resource.location());
            return new LoadedProperties(properties, resource.source(), resource.location());
        } catch (Exception e) {
            String msg = "readPropertiesFile exception: " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }
    }

    /**
     * Reads an explicitly supplied external properties file. Retained for API
     * compatibility; unlike the temporary migration implementation, it never
     * falls back to the classpath.
     */
    public static Properties readPropertiesFile(String fileName) throws ConformanceTestException {
        try (OpenedResource resource = openExternalFile(fileName)) {
            Properties properties = new Properties();
            properties.load(resource.stream());
            return properties;
        } catch (IOException e) {
            throw new ConformanceTestException("Unable to read explicit properties file " + fileName + ": "
                    + e.getMessage());
        }
    }

    /**
     * Opens an explicitly supplied filesystem path. Retained for API
     * compatibility and deliberately has no classpath fallback.
     */
    public static InputStream getStreamFromResourceFile(String fileName) throws ConformanceTestException {
        return openExternalFile(fileName).stream();
    }

    /**
     * Opens an explicitly supplied filesystem path. This method never falls
     * back to a bundled resource.
     *
     * @param fileName the basename of the resource file
     * @return InputStream to the open resource or null if an en exception thrown
     * @throws ConformanceTestException if any error occurs
     */
    public static OpenedResource openExternalFile(String fileName) throws ConformanceTestException {
        try {
            Path externalPath = Path.of(fileName).toAbsolutePath().normalize();
            if (!Files.isRegularFile(externalPath) || !Files.isReadable(externalPath)) {
                throw new FileNotFoundException(externalPath.toString());
            }
            s_logger.info("Using external resource {}", externalPath);
            return new OpenedResource(Files.newInputStream(externalPath), ResourceSource.EXTERNAL_FILE,
                    externalPath.toString());
        } catch (Exception e) {
            String msg = "Unable to open explicit external file " + fileName + ": " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }
    }

    /**
     * Opens a bundled classpath resource. Classpath identifiers are normalized
     * to '/' and never interpreted as filesystem paths.
     */
    public static OpenedResource openBundledResource(String resourceName) throws ConformanceTestException {
        try {
            String normalizedName = normalizeClasspathResourceName(resourceName);
            InputStream resourceStream = ValidatorHelper.class.getClassLoader().getResourceAsStream(normalizedName);
            if (resourceStream != null) {
                s_logger.info("Using bundled resource {}", normalizedName);
                return new OpenedResource(resourceStream, ResourceSource.CLASSPATH, normalizedName);
            }
            throw new FileNotFoundException(normalizedName);
        } catch (Exception e) {
            String msg = "Unable to open bundled resource " + resourceName + ": " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }
    }

    /**
	 * The single external-versus-bundled default boundary: an existing,
	 * readable path relative to the process working directory wins, followed by
	 * configured writable and installed application resource directories.
	 * Otherwise the same platform-independent classpath name is used. Explicit
	 * operator paths must use {@link #openExternalFile(String)} instead.
     */
	public static OpenedResource openDefaultResource(String resourceName) throws ConformanceTestException {
		Path externalPath = Path.of(resourceName).toAbsolutePath().normalize();
		if (Files.isRegularFile(externalPath) && Files.isReadable(externalPath)) {
			return openExternalFile(externalPath.toString());
		}
		String[] configuredDirectories = {
				System.getProperty("cct.data.dir"),
				System.getProperty("cct.resource.dir")
		};
		for (String configuredDirectory : configuredDirectories) {
			if (configuredDirectory != null && !configuredDirectory.isBlank()) {
				Path base = Path.of(configuredDirectory).toAbsolutePath().normalize();
				Path installedPath = base.resolve(resourceName).normalize();
				if (installedPath.startsWith(base) && Files.isRegularFile(installedPath)
						&& Files.isReadable(installedPath)) {
					return openExternalFile(installedPath.toString());
				}
			}
		}
		return openBundledResource(resourceName);
	}

    private static String normalizeClasspathResourceName(String resourceName) {
        String normalizedName = resourceName.replace('\\', '/');
        while (normalizedName.startsWith("/")) {
            normalizedName = normalizedName.substring(1);
        }
        return normalizedName;
    }

    /**
     * Gets the trust anchor associated with the end-entity certificate based on Subject CN
     * @param keyStore keyStore object previously opened
     * @param eeCert end-entity certificate
     * @return X509Certificate of the trust anchor
     * @throws ConformanceTestException
     */

    public static X509Certificate getTrustAnchorForGivenCertificate(KeyStore keyStore, X509Certificate eeCert, String defaultAlias) throws ConformanceTestException {
        if (keyStore == null) {
            s_logger.error("keyStore is null");
            return null;
        }
        String alias = null;
        X509Certificate trustAnchorCert = null;
        // If no default alias is set, use these hard coded bits
        if (defaultAlias == null) {
            if (eeCert == null) {
                s_logger.error("eeCert is null");
                return null;
            }
            s_logger.debug("Getting trust anchor for EE certificate " + eeCert.getSubjectDN().getName());

            String subjectName = eeCert.getSubjectDN().getName();

            if (subjectName.contains("ICAM")) {
                if (subjectName.contains("PIV-I")) {
                    alias = "icam test card piv-i root ca";
                } else {
                    alias = "icam test card piv root ca";
                }
            } else {
                // Some logic in here to arbitrarily use old Common Policy CA
                // for EE certs issued before Feb 1, 2021
                Date eeNotBefore = eeCert.getNotBefore();
                if (eeNotBefore != null) {
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
                    try {
                        Date earliestNewCaDate = sdf.parse("2021-02-01");
                        if (eeNotBefore.before(earliestNewCaDate)) {
                            alias = "federal common policy ca";
                        } else {
                            alias = "federal common policy ca g2";
                        }
                    } catch (ParseException e) {
                        s_logger.error(e.getMessage());
                        fail(e);
                    }
                }
            }
        } else {
            alias = defaultAlias;
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
        String[] names = name.split(",");
        String rv = name.replaceAll(",.*", ""); // failsafe
        for (String n : names) {
            String n1 = n.replaceAll("[ ]+", "_");
            if (n1.startsWith("CN=") || n1.startsWith("SERIALNUMBER=") | n1.startsWith("OU=")  | n1.startsWith("O=")) {
                rv =  n1.replaceAll("CN=", "")
                .replaceAll("SERIALNUMBER=", "")
                .replaceAll("OU=", "")
                .replaceAll("O=", "")
                .replaceAll("[^A-Za-z0-9\\.\\-]", "_")
                .replaceAll("_-_", "-")
                .replaceAll("__", "_")
                .toLowerCase();
            }
        }
        return rv;
    }

    /**
     * Generates a certificate's full file name given a resourceDir, subject, and issuer
     * @param resourceDir string representing the resource directory
     * @param subject X.509 certificate Subject
     * @param issuer X.509 certificate issuer
     * @return the full file name to the certificate file
     * @throws FileNotFoundException
     */

    public static String genCertFileName(String resourceDir, String subject, String issuer) throws FileNotFoundException {
        TestRunLogController trlc = TestRunLogController.getInstance();
        String identifier = "unknown";
        // It is only a guess as to whether this is a PIV-I or not. We just need one of the two
        // for our file name.
        if (trlc.getGuid() != null && trlc.getFascn() != null && trlc.getFascn().startsWith("99999999999999")) {
            // Use the GUID
            identifier = trlc.getGuid();
        } else if (trlc.getFascn() != null) {
            // Use the FASC-N
            identifier = trlc.getFascn();
        }
        Path dirPath = Path.of(resourceDir + File.separator + identifier);
        if (!Files.exists(dirPath)) {
            try {
                Files.createDirectory(dirPath);
            } catch (IOException e) {
                s_logger.error(e.getMessage());
            }
            if (!Files.exists(dirPath)) {
                s_logger.warn("Can't create " + dirPath);
				dirPath = Path.of(System.getProperty("cct.data.dir", System.getProperty("user.dir")))
						.toAbsolutePath().normalize();
            }
        }
        String fullName = dirPath + File.separator + subject;
        if (issuer != null)
            fullName += "_issued_by_" + issuer;

        int len = fullName.length();
        String rv = fullName.substring(0, (len >= 252) ? 252 : len) + ".cer";
        s_logger.debug("genCertFileName: " + rv);
        return rv;
    }
}
