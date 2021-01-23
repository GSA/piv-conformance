package gov.gsa.pivconformance.conformancelib.utilities;

import gov.gsa.pivconformance.conformancelib.tests.ConformanceTestException;
import org.apache.commons.cli.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import static gov.gsa.pivconformance.conformancelib.utilities.ValidatorHelper.getStreamFromResourceFile;

/**
 * Provides the API to validating a given end entity certificate for
 * a given certificate policy.
 */
public class Validator {
    private static final Logger s_logger = LoggerFactory.getLogger(Validator.class);
    private static final Options s_options = new Options();
    private static final String s_caFileName = "all.p7b";

    private String m_provider = "SunRsaSign";
    private CertPathBuilder m_cpb = null;
    private String m_caPathString = null;
    private String m_caFileName = null;
    private KeyStore m_keystore = null;

    static {
        Option eeCertFileOption = Option.builder("ee").hasArg(true).argName("ee").desc("end-entity certificate").build();
        Option taCertFileOption = Option.builder("ta").hasArg(true).argName("ta").desc("trust anchor certificate").build();
        Option oidsOption = Option.builder("oids").hasArg(true).argName("oids").desc("list of certificate policy oids").build();
        Option resourceOption = Option.builder("resourceDir").hasArg(true).argName("resourceDir").desc("base directory for resources and files").build();
        Option providerOption = Option.builder("provider").hasArg(true).argName("provider").desc("provider string (BC or Sun)").build();
        Option caPathOption = Option.builder("caPath").hasArg(true).argName("caPath").desc("CA directory or path").build();
        Option caFileOption = Option.builder("caFile").hasArg(true).argName("caFile").desc("File containing intermediate CA data").build();

        s_options.addOption(eeCertFileOption);
        s_options.addOption(taCertFileOption);
        s_options.addOption(oidsOption);
        s_options.addOption(resourceOption);
        s_options.addOption(providerOption);
        s_options.addOption(caPathOption);
        s_options.addOption(caFileOption);
    }

    /**
     *
     * @throws ConformanceTestException
     */
    public Validator() throws ConformanceTestException {
        reset("SunRsaSign", "x509-certs/cacerts.keystore", "changeit", s_caFileName);
    }

    /**
     *
     * @param provider
     * @throws ConformanceTestException
     */
    public Validator (String provider) throws ConformanceTestException {
        reset(provider, "x509-certs/cacerts.keystore", "changeit", null);
    }

    /**
     * @param provider
     * @param keyStoreName
     * @throws ConformanceTestException
     */
    public Validator (String provider, String keyStoreName, String password) throws ConformanceTestException {
        reset(provider, keyStoreName, password, null);
    }

    /**
     * Sets the validator's KeyStore to keyStoreName
     *
     * @param keyStoreName the path to the KeyStore file
     */
    public void setKeyStore(String keyStoreName, String password) throws ConformanceTestException {
        InputStream is = null;
        is = getStreamFromResourceFile(System.getProperty("user.dir") + File.separator + keyStoreName);
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(is, password.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            s_logger.error(e.getMessage());
            throw new ConformanceTestException(e.getMessage());
        }
        m_keystore = ks;
    }

    /**
     * Gets the validator's KeyStore
     * @return the KeyStore used by the validator
     */
    public KeyStore getKeyStore() {
        return m_keystore;
    }

    /**
     * Sets the provider for crypto and path validation.
     * @param providerString provider string
     * @throws NoSuchAlgorithmException
     */
    public void setCpb(String providerString) throws NoSuchProviderException, NoSuchAlgorithmException {
        setProvider(providerString);
        try {
            if (providerString.toLowerCase().compareTo("bc") == 0) {
                if (Security.getProvider("BC") == null)
                    Security.addProvider(new BouncyCastleProvider());
                s_logger.debug("Changing to " + providerString + " provider");
                m_cpb = CertPathBuilder.getInstance("PKIX", "BC");
             } else if (providerString.toLowerCase().startsWith("sun")) {
                s_logger.debug("Changing to " + providerString + " provider");
                if (Security.getProvider(providerString) == null) {
                    s_logger.error(providerString + " crypto provider is not registered");
                    throw new NoSuchProviderException();
                }
                m_cpb = CertPathBuilder.getInstance("PKIX");
            } else {
                s_logger.error("This application doesn't support the " + providerString + " provider");
                throw new NoSuchProviderException();
            }
        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            s_logger.error("setCpb(" + providerString + "): " + e.getMessage());
            throw e;
        }
    }

    /**
     * Sets the provider
     * @param provider provider string
     */
    public void setProvider(String provider) {
        m_provider = provider;
    }

    public String getProvider() {
        return m_provider;
    }
    public CertPathBuilder getCpb() {
        return m_cpb;
    }

    /**
     * Sets the monitor path
     * @param path path or directory containing the monitor data file
     */

    public void setCaPathString(String path) {
        m_caPathString = path;
    }

    /**
     * Gets the monitor URL
     * @return the monitor URL
     */

    public String getCaPathString() {
        return m_caPathString;
    }

    /**
     * Sets the monitor file name
     * @param fileName name of local file containing monitor data
     */
    public void setCaFileName(String fileName) {
        m_caFileName = fileName;
    }

    /**
     * Gets the intermediate CA file name
     * @return the name of the local file containing monitor data
     */
    public String getCaFileName() {
        return m_caFileName;
    }

    private static void PrintHelpAndExit(int exitCode) {
        new HelpFormatter().printHelp("CertDump <options>", s_options);
        System.exit(exitCode);
    }

    public static void main(String[] args) throws ConformanceTestException {
        CommandLineParser p = new DefaultParser();
        CommandLine cmd = null;
        File endEntityCertFile = null;
        File trustAnchorCertFile = null;
        String policyOids = null;
        Properties props = null;
        String provider = null;
        try {
            cmd = p.parse(s_options, args);
            s_logger.debug("Command line: " + args.toString());
        } catch (ParseException e) {
            s_logger.error("Failed to parse command line arguments", e);
            PrintHelpAndExit(1);
        }
        if(cmd.hasOption("help")) {
            PrintHelpAndExit(0);
        }
        if(cmd.hasOption("ee")) {
            endEntityCertFile = new File(cmd.getOptionValue("ee"));
            s_logger.info("endEntityCertFile: {}",  endEntityCertFile.getAbsolutePath());
        }
        if(cmd.hasOption("ta")) {
            trustAnchorCertFile = new File(cmd.getOptionValue("ta"));
            s_logger.info("trustAnchorEntityCertFile: {}",  trustAnchorCertFile.getAbsolutePath());
        }
        if(cmd.hasOption("oids")) {
            String oids = cmd.getOptionValue("oids");
            String oidArray[] = oids.split("[\\s]");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < oidArray.length; i++) {
                if (sb.length() != 0) sb.append("|");
                sb.append(oidArray[i]);
            }
            policyOids = sb.toString();
        }
        if(cmd.hasOption("resourceDir")) {
            String resourceDir = cmd.getOptionValue("resourceDir");
            if (resourceDir != null) {
                if (endEntityCertFile != null)
                    endEntityCertFile = new File(resourceDir + File.separator + cmd.getOptionValue("ee"));
                if (trustAnchorCertFile != null)
                    trustAnchorCertFile = new File(resourceDir + File.separator + cmd.getOptionValue("ta"));
            }
        }
        Validator v =  new Validator("SunRsaSign", "x509-certs/cacerts.keystore", "changeit");
        if(cmd.hasOption("provider")) {
            provider = cmd.getOptionValue("provider");
            try {
                v.setCpb(provider);
            } catch (Exception e) {
                s_logger.error(e.getMessage());
            }
        }
        if (cmd.hasOption("caPath")) {
            String caPath = cmd.getOptionValue("caPath");
            try {
                v.setCaPathString(caPath);
            } catch (Exception e) {
                s_logger.error(e.getMessage());
            }
        }
        if (cmd.hasOption("caFile")) {
            String caFile = cmd.getOptionValue("caFile");
            try {
                v.setCaFileName(caFile);
            } catch (Exception e) {
                s_logger.error(e.getMessage());
            }
        }
        v.isValid(endEntityCertFile, policyOids, trustAnchorCertFile);
    }

    /**
     * Determines whether the certificate in the given end entity certificate is valid for the specified policy OID(s).
     * @param endEndityCertFile name of file containing X.509 certificate of the end entity
     * @param policyOids comma-separated string of certificate policy OIDs
     * @param trustAnchorFile name of file containing X.509 certificate of the trust anchor
     * @return true if the certificate can be validated for the given policy, false if any error occurs
     */
    public boolean isValid(String endEndityCertFile, String policyOids, String trustAnchorFile) throws ConformanceTestException {
        File eeFile = new File(endEndityCertFile);
        File taFile = new File(trustAnchorFile);
        return isValid(eeFile, policyOids, taFile);
    }

    /**
     * Determines whether the certificate in the given end entity certificate is valid for the specified policy OID(s).
     * @param endEntityCertFile file object containing X.509 certificate of the end entity
     * @param policyOids comma-separated string of certificate policy OIDs
     * @param trustAnchorFile file object containing X.509 certificate of the trust anchor
     * @return true if the certificate can be validated for the given policy, false if any error occurs
     */
    public boolean isValid(File endEntityCertFile, String policyOids, File trustAnchorFile) throws ConformanceTestException {
        CertificateFactory fac;
        boolean rv = false;
        X509Certificate eeCert = null;
        X509Certificate trustAnchorCert = null;

        try {
            fac = CertificateFactory.getInstance("X509");
            eeCert = (X509Certificate) fac.generateCertificate(new FileInputStream(endEntityCertFile));
        } catch (CertificateException | IOException e) {
            String msg = endEntityCertFile.getName() + ": " + e.getMessage();
            System.out.println(msg);
            s_logger.error(msg);
            return rv;
        }

        try {
            fac = CertificateFactory.getInstance("X509");
            trustAnchorCert = (X509Certificate) fac.generateCertificate(new FileInputStream(trustAnchorFile));
            rv = isValid(eeCert, policyOids, trustAnchorCert);
        } catch (CertificateException | IOException e) {
            String msg = trustAnchorFile.getName() + ": " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException();
        }

        return rv;
    }


    /**
     * Determines if a valid certificate path can be built to the specified trust anchor using the given policy OIDs
     * @param eeCert end entity cert
     * @param policyOids comma-separated string of policy OIDs
     * @param trustAnchorCert
     * @return true if the certificate path was built, false if a path cannot be built
     */
    public boolean isValid(X509Certificate eeCert, String policyOids, X509Certificate trustAnchorCert) {
        // CertiPath monitor creates a CA bundle file which we can use for trust anchors
        try {
            List<X509Certificate> certList = new ArrayList<>();
            certList.add(eeCert);
            X509CertSelector eeCertSelector = new X509CertSelector();
            eeCertSelector.setCertificate(eeCert);
            eeCertSelector.setIssuer(eeCert.getIssuerX500Principal());
            eeCertSelector.setSubject(eeCert.getSubjectX500Principal());
            eeCertSelector.setSerialNumber(eeCert.getSerialNumber());
            eeCertSelector.setBasicConstraints(3);
            TrustAnchor trustAnchor = new TrustAnchor(trustAnchorCert, null);
            CertStore certStore = null;
            if (m_caFileName != null) {
                certStore = getCertStore(m_caPathString, m_caFileName);
            } else {
                certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
            }

            String[] allowedPolicies = policyOids.split("\\|");
            HashSet<String> policies = new HashSet<String>(Arrays.asList(allowedPolicies));

            PKIXBuilderParameters params = new PKIXBuilderParameters(getKeyStore(), eeCertSelector);
            params.addCertStore(certStore);
            params.setRevocationEnabled(true);
            params.setSigProvider(getProvider());
            params.setInitialPolicies(policies);
            params.setExplicitPolicyRequired(false);
            params.setPolicyMappingInhibited(false);

            System.setProperty("com.sun.security.enableAIAcaIssuers", String.valueOf(false));
            System.setProperty("com.sun.security.crl.timeout", String.valueOf(120));
            System.setProperty("ocsp.enable", String.valueOf(true));
            CertPathBuilderResult cpbResult = m_cpb.build(params);
            s_logger.debug("cpb.build() returned " + cpbResult.toString());
            CertPath certPath = cpbResult.getCertPath();
            s_logger.info("Build passed, path contents: " + certPath);
            return certPath != null;
        } catch (ConformanceTestException e) {
            s_logger.error("Check test artifacts");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CertPathBuilderException e) {
            e.printStackTrace();
        } catch (Exception ex) {
            s_logger.error("Path build failed: " + ex.getMessage());
        }
        return false;
    }
    /**
     * Loads a CMS-signed bundle of CA certs
     * @return
     */
    private CertStore getCertStore(String caPathString, String caFileName) throws ConformanceTestException {
        CertStore certStore = null;
        // Use the scheme to switch between HTTPS and FILE protocol
        if (caPathString != null && caPathString.toLowerCase().startsWith("https:")) {
            try {
                //setMonitorUrl(new URL(caPathString));
                TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                    // Stubs to accept all offered certs
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }};
                // Install the all-trusting trust manager
                final SSLContext sc = SSLContext.getInstance("SSL");
                sc.init(null, trustAllCerts, new java.security.SecureRandom());
                HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
                // Create all-trusting host name verifier
                HostnameVerifier allHostsValid = new HostnameVerifier() {
                    public boolean verify(String hostname, SSLSession session) {
                        return true;
                    }
                };

                HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
                URLConnection con = new URL(caPathString).openConnection();
                byte[] buf = con.getInputStream().readAllBytes();
                OutputStream outStream = new FileOutputStream(m_caFileName);
                outStream.write(buf, 0, buf.length);
                outStream.flush();
                outStream.close();
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                String msg = "Crypto failure connecting to " + caPathString + ": " + e.getMessage();
                s_logger.error(msg);
                throw new ConformanceTestException(msg);
            } catch (Exception e) {
                String msg = "IO problem connecting to " + caPathString + ": " + e.getMessage();
                s_logger.error(msg);
                throw new ConformanceTestException(msg);
            }
        } else if (caPathString != null && caPathString.toLowerCase().startsWith("file:///")) {
            m_caFileName = TestRunLogController.pathFixup((m_caPathString.replaceFirst("file:///", "") + "/") + m_caFileName);
        } else if (caPathString == null ) {
            s_logger.warn("m_caPathStringtring not initialized");
        } else {
            s_logger.warn("unsupported URL scheme");
        }

        s_logger.debug("Opening " + m_caFileName);

        try {
            FileInputStream fis = new FileInputStream(m_caFileName);
            if (fis != null) {
                // Instantiate a CertificateFactory for X.509
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                // Extract the certification path from the PKCS7 SignedData structure
                CertPath cp = cf.generateCertPath(fis, "PKCS7");
                List<X509Certificate> certs = (List<X509Certificate>) cp.getCertificates();
                int count = 0;
                for (X509Certificate c : certs) {
                    s_logger.debug(++count + ". " + c.getSubjectDN().getName());
                }
                List<X509Certificate> certList = new ArrayList<>();
                certList.addAll(certs);
                certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
            } else {
                s_logger.warn(s_caFileName + " was not found");
            }
        } catch (NoSuchAlgorithmException e) {
            String msg = "Crypto failure loading certs from " + m_caFileName + ": " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        } catch (Exception e) {
            String msg = "IO problem reading " + m_caFileName + ": " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }
        return certStore;
    }
    /**
     * Resets the object to the desired provider
     * @param provider Crypto and path builder provider
     * @throws ConformanceTestException
     */
    private void reset(String provider, String keyStoreName, String password, String certStoreName) throws ConformanceTestException {
        m_caFileName = s_caFileName;
        m_caPathString = null;
        m_cpb = null;
        m_keystore = null;
        try {
            setCpb(provider);
            setKeyStore(keyStoreName, password);
            setCaFileName(certStoreName);
        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            s_logger.error(e.getMessage());
            throw new ConformanceTestException(e.getMessage());
        }
    }
}
