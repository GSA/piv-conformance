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

import static gov.gsa.pivconformance.conformancelib.utilities.ValidatorHelper.*;

/**
 * Provides the API to validating a given end entity certificate for
 * a given certificate policy.In
 * October 2020 the Federal Government created a new FPKI Root CA
 * The new root is named the Federal Common Policy CA G2 (FCPCAG 2)
 * This new CA has issued new certificates to all CAs signed by the current
 * FCPCA This enables all current certificates issued by them to build a path to the new root
 * What will be impacted?
 * This change will affect all Federal agencies and will have an impact on the following services
 * o Personal Identity Verification ( credential authentication to the government networks
 * o Agency web applications implementing client authentication (e g PIV authentication)
 * o User digital signatures that leverage PIV or similar credentials
 * o Other applications leveraging the FCPCA as a root including Physical Access Control System (PACS) implementations
 * When will this change take place?
 * o Between now and May 2021 agencies will need to transition from using the old FCPCA as the root to the new FCPCG 2
 * o Last week of January 2021 the new intermediate CA certificates must be published in CA repositories
 * o February 2 2021 the FPKIMA team will migrate the FBCAG 4 to the FCPCAG 2 by publishing the cross certificate from the FCPCAG 2 to the FBCAG 4 and removing the cross certificates between the FBCAG 4 and the old FCPCA
 * o May 2021 the FPKIMA team will decommission the old FCPCA
 *
 */
public class Validator {
    private static final Logger s_logger = LoggerFactory.getLogger(Validator.class);
    private static final Options s_options = new Options();
    private static final String s_caFileName = "all.p7b";

    private String m_resourceDir = ".";
    private String m_eeFullCertPath = "";
    private String m_taFullCertPath = "";
    private String m_provider = "SunRsaSign";
    private CertPathBuilder m_cpb = null;
    private String m_caPathString = null;
    private String m_caFileName = null;
    private KeyStore m_keystore = null;
    private boolean m_downloadAia = true;

    public static final List<String> s_validCryptoProviders = new ArrayList<String>() {
        private static final long serialVersionUID = 1L;
        {
            add("SunRsaSign");
            add("BC");
        }
    };

    private static final HashMap<String, String> s_certPathBuilderProviders = new HashMap<String, String>() {
        private static final long serialVersionUID = 1L;
        {
            put("SunRsaSign", "SUN");
            put("BC", "BC");
        }
    };

    static {
        Option eeCertFileOption = Option.builder("ee").hasArg(true).argName("ee").desc("end-entity certificate").build();
        Option taCertFileOption = Option.builder("ta").hasArg(true).argName("ta").desc("trust anchor certificate").build();
        Option oidsOption = Option.builder("oids").hasArg(true).argName("oids").desc("list of certificate policy oids").build();
        Option resourceOption = Option.builder("resourceDir").hasArg(true).argName("resourceDir").desc("base directory for resources and files").build();
        Option providerOption = Option.builder("provider").hasArg(true).argName("provider").desc("provider string (BC or Sun)").build();
        Option caPathOption = Option.builder("caPath").hasArg(true).argName("caPath").desc("CA directory or path").build();
        Option caFileOption = Option.builder("caFile").hasArg(true).argName("caFile").desc("file containing intermediate CA data").build();
        Option downloadAiaOption = Option.builder("downloadAia").hasArg(true).argName("downloadAia").desc("download AIA as needed (Sun only)").build();

        s_options.addOption(eeCertFileOption);
        s_options.addOption(taCertFileOption);
        s_options.addOption(oidsOption);
        s_options.addOption(resourceOption);
        s_options.addOption(providerOption);
        s_options.addOption(caPathOption);
        s_options.addOption(caFileOption);
        s_options.addOption(downloadAiaOption);
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
     * Sets the validator's key store to keyStoreName
     *
     * The key store contains trust anchors and intermediate CA certs that are
     * unlikely to change in the short term.
     *
     * @param keyStorePath the path to the KeyStore file
     */
    public void setKeyStore(String keyStorePath, String password) throws ConformanceTestException {
        InputStream is = null;
        String targetPath = null;
        if (keyStorePath == null) {
            String msg = "No keystore file specified";
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }
        if (keyStorePath.startsWith(File.separator))
            targetPath = keyStorePath;
        else
            targetPath = getResourceDir() != null ? getResourceDir() + File.separator + keyStorePath : keyStorePath;

        is = getStreamFromResourceFile(targetPath);

        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(is, password.toCharArray());
            is.close();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            s_logger.error(e.getMessage());
            throw new ConformanceTestException(e.getMessage());
        }
        m_keystore = ks;
    }

    /**
     * Gets the validator's KeyStore
     *
     * The key store contains trust anchors and intermediate CA certs that are
     * unlikely to change in the short term.
     *
     * @return the KeyStore used by the validator
     */
    public KeyStore getKeyStore() {
        return m_keystore;
    }

    /**
     * Sets the provider for crypto and certificate path validation.
     * If providerString is "SunRsaSign" AIA downloading and timeouts is
     * available. If providerString is "BC" then the BouncyCastle
     * crypto libraries are used. If providerString is any other value
     * NoSuchProviderException is thrown.
     *
     * @param providerString provider string
     * @throws NoSuchProviderException NoSuchAlgorithmException
     */
    public void setCertPathBuilder(String providerString) throws NoSuchProviderException, NoSuchAlgorithmException, ConformanceTestException {
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
                String msg = ("This application doesn't support the " + providerString + " provider");
                s_logger.error(msg);
                throw new ConformanceTestException(msg);
            }
        } catch (NoSuchProviderException | NoSuchAlgorithmException | ConformanceTestException e) {
            String msg = "setCpb(" + providerString + "): " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }
    }

    /**
     * Sets the provider string which is used *later* as follows:
     *
     * If providerString is "SunRsaSign" AIA downloading and timeouts is
     * available. If providerString is "BC" then the BouncyCastle
     * crypto libraries will be used. If providerString is any other value
     * NoSuchProviderException is thrown.
     *
     * @param providerString provider string
     * @throws NoSuchProviderException
     */
    public void setProvider(String providerString) throws ConformanceTestException, NoSuchProviderException {
        if (!s_validCryptoProviders.contains(providerString)) {
            s_logger.error("Unsupported provider: " + providerString);
            throw new NoSuchProviderException();
        }
        m_provider = providerString;

        try {
            setCertPathBuilder(s_certPathBuilderProviders.get(providerString));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            String msg = e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }
    }

    public String getProvider() {
        return m_provider;
    }
    public CertPathBuilder getCpb() {
        return m_cpb;
    }

    /**
     * Sets the URL/directory name where intermediate certificate
     * bundles are found and used to augment the trust anchor
     * keystore.
     *
     * If caPath starts with "https://", the string is used as
     * a URL to download a file and caFile is used as the local
     * file's destination for downloading.
     *
     * If caPath starts with "file://", it is treated as a local directory
     * name to which caFile is appended to create a full path.
     *
     * @param path the URL/directory name
     */
    public void setCaPathString(String path) {
        m_caPathString = path;
    }


    /**
     * Gets the URL/directory name where intermediate certificate
     * bundles are found and used to augment the trust anchor
     * keystore.
     *
     * If caPath starts with "https://", the string is used as
     * a URL to download a file and caFile is used as the local
     * file's destination for downloading.
     *
     * If caPath starts with "file://", it is treated as a local directory
     * name to which caFile is appended to create a full path.
     *
     * @return the URL/directory name
     */
    public String getCaPathString() {
        return m_caPathString;
    }

    /**
     * Sets the local file name containing intermediate certificates
     * @param fileName name of local file containing intermediate certificates
     */
    public void setCaFileName(String fileName) {
        m_caFileName = fileName;
    }

    /**
     * Sets the local file name containing intermediate certificates
     * @return name of local file containing intermediate certificates
     */
    public String getCaFileName() {
        return m_caFileName;
    }

    private static void PrintHelpAndExit(int exitCode) {
        new HelpFormatter().printHelp("CertDump <options>", s_options);
        System.exit(exitCode);
    }

    /**
     * Indicates whether AIA in certs will be downloaded
     * @return true if CertPath engine will download certs (Sun only) false if not
     */
    public boolean getDownloadAia() {
        return m_downloadAia;
    }

    /**
     * Configure validator to download AIA
     * @param downloadAia flag true or false
     */
    public void setDownloadAia(boolean downloadAia) {
        if (m_provider.startsWith("BC")) {
            s_logger.warn("BouncyCastle provider doesn't support downloading AIA");
            return;
        }
        m_downloadAia = downloadAia;
    }

    /**
     * Gets the URL/directory name where resources are found. If
     * resourceDir starts with "https://" it will be fetched
     * using the HTTPS scheme. If resourceDir starts with "file://",
     * it is treated as a local directory name.
     * @return URL/directory where resources are found
     */
    public String getResourceDir() {
        return m_resourceDir;
    }

    /**
     * Sets the URL/directory name where AIA are found. If
     * caPath starts with "https://", the string is used as
     * a URL to AIA. If caPath starts with "file://", it is
     * treated as a local directory name.
     *
     * @param resourceDir the URL/directory name
     */
    public void setResourceDir(String resourceDir) {
        m_resourceDir = resourceDir;
    }

    /**
     * Gets the full path to the end-entity certificate to be validated
     * @return the path to the end-entity certificate
     */
    public String getEeFullCertPath() {
        return m_eeFullCertPath;
    }
    /**
     * Sets the full path to the end-entity certificate to be validated
     * @param eeFullCertPath path to the end-entity certificate
     */
    public void setEeFullCertPath(String eeFullCertPath) {
        m_eeFullCertPath = eeFullCertPath;
    }

    /**
     * Gets the full path to the trust anchor certificate
     * @return the path to the trust anchor certificate
     */
    public String getTaFullCertPath() {
        return m_taFullCertPath;
    }
    /**
     * Sets the full path to the trust anchor certificate to be validated
     * @param taFullCertPath path to the trust anchor certificate
     */
    public void setTaFullCertPath(String taFullCertPath) {
        m_taFullCertPath = taFullCertPath;
    }

    public static void main(String[] args) throws ConformanceTestException {
        CommandLineParser p = new DefaultParser();
        CommandLine cmd = null;
        File endEntityCertFile = null;
        File trustAnchorCertFile = null;
        String policyOids = null;
        StringBuilder cmdLine = new StringBuilder();
        String provider = null;
        try {
            for (String a : args) {
                if (cmdLine.length() > 0) cmdLine.append(" ");
                cmdLine.append(a);
            }
            s_logger.debug("Command line: " + cmdLine.toString());
            cmd = p.parse(s_options, args);
        } catch (ParseException e) {
            s_logger.error("Failed to parse command line arguments", e);
            PrintHelpAndExit(1);
        }
        if(cmd.hasOption("help")) {
            PrintHelpAndExit(0);
        }

        Validator v =  new Validator();

        if(cmd.hasOption("ee")) {
            v.setEeFullCertPath(cmd.getOptionValue("ee"));
            s_logger.info("endEntityCertFile: {}", v.getEeFullCertPath());
        }

        if(cmd.hasOption("ta")) {
            v.setTaFullCertPath(cmd.getOptionValue("ee"));
            s_logger.info("trustAnchorEntityCertFile: {}",  v.getTaFullCertPath());
        }

        if(cmd.hasOption("oids")) {
            String oids = cmd.getOptionValue("oids");
            String[] oidArray = oids.split("[\\s]");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < oidArray.length; i++) {
                if (sb.length() != 0) sb.append("|");
                sb.append(oidArray[i]);
            }
            policyOids = sb.toString();
        }

        if(cmd.hasOption("resourceDir")) {
            v.setResourceDir(cmd.getOptionValue("resourceDir"));
            s_logger.info("resourceDir: {}",  v.getResourceDir());
        }

        if(cmd.hasOption("provider")) {
            provider = cmd.getOptionValue("provider");
            try {
                v.setCertPathBuilder(provider);
            } catch (Exception e) {
                s_logger.error(e.getMessage());
            }
            s_logger.info("provider: {}",  v.getProvider());
        }

        if (cmd.hasOption("caPath")) {
            String caPath = cmd.getOptionValue("caPath");
            try {
                v.setCaPathString(caPath);
            } catch (Exception e) {
                s_logger.error(e.getMessage());
            }
            s_logger.info("caPath: {}",  v.getCaPathString());
        }

        if (cmd.hasOption("caFile")) {
            String caFile = cmd.getOptionValue("caFile");
            try {
                v.setCaFileName(caFile);
            } catch (Exception e) {
                s_logger.error(e.getMessage());
            }
            s_logger.info("caFile: {}",  v.getCaFileName());
        }

        if (cmd.hasOption("downloadAia")) {
            String downloadAia = cmd.getOptionValue("downloadAia");
            v.setDownloadAia(downloadAia.toLowerCase().matches("1|true"));
        }
        /*
         * 1. if trust anchor is supplied by caller then it becomes the params trust anchor.
         * 2. if trust anchor is not supplied by caller then the params trust anchor is selected
         *    from the key store based on name containing ICAM and PIV/PIV-I defaulting to common
         * 3. TODO: the new G2 common policy needs to be implemented
         * ------- end of trust anchor processing
         */
        String resourceDir = (v.getResourceDir() != null) ? v.getResourceDir() : ".";
        endEntityCertFile = new File(resourceDir + File.separator + v.getEeFullCertPath());
        if (trustAnchorCertFile == null) {
            KeyStore keyStore = v.getKeyStore();
            X509Certificate trustAnchor = getTrustAnchorForGivenCertificate(keyStore, getX509CertificateFromPath(v.getEeFullCertPath()));
            String tempName = null;
            try {
                File temp;
                temp = File.createTempFile("tmp",".cer", new File(System.getProperty("java.io.tmpdir")));
                tempName = temp.getCanonicalPath();
                OutputStream outStream = new FileOutputStream(temp);
                outStream.write(trustAnchor.getEncoded(), 0, trustAnchor.getEncoded().length);
                outStream.flush();
                outStream.close();
            } catch (IOException | CertificateEncodingException e) {
                e.printStackTrace();
            }
            trustAnchorCertFile = new File(tempName);
        }
        else
            trustAnchorCertFile = new File(resourceDir + File.separator + v.getTaFullCertPath());

        v.isValid(endEntityCertFile, policyOids, trustAnchorCertFile);
    }


    /**
     * Determines if a valid certificate path can be built to the specified trust anchor using the given policy OIDs
     * @param endEntityCertFile string with file name of end entity cert
     * @param policyOids comma-separated string of policy OIDs
     * @param trustAnchorFile string with file name of trust anchor cert
     * @return true if the certificate path was built, false if a path cannot be built
     * @throws NoSuchAlgorithmException
     * @throws CertStoreException
     * @throws CertPathBuilderException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     */
    public boolean isValid(String endEntityCertFile, String policyOids, String trustAnchorFile) throws ConformanceTestException {
        setEeFullCertPath(endEntityCertFile);
        setTaFullCertPath(endEntityCertFile);
        File eeFile = new File(endEntityCertFile);
        File taFile = new File(trustAnchorFile);
        return isValid(eeFile, policyOids, taFile);
    }

    /**
     * Determines if a valid certificate path can be built to the specified trust anchor using
     * the given policy OIDs. If trustAnchorCertFile is null, resourceDir + /x509-certs/cacerts.keystore
     * is consulted for the appropriate trust anchor.
     *
     * @param endEntityCertFile file containing end entity cert
     * @param policyOids comma-separated string of policy OIDs
     * @param trustAnchorCertFile file containing trust anchor cert
     * @return true if the certificate path was built, false if a path cannot be built
     * @throws NoSuchAlgorithmException
     * @throws CertStoreException
     * @throws CertPathBuilderException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     */
    public boolean isValid(File endEntityCertFile, String policyOids, File trustAnchorCertFile) throws ConformanceTestException {
        setEeFullCertPath(endEntityCertFile.getAbsolutePath());
        setTaFullCertPath(endEntityCertFile.getAbsolutePath());
        if (trustAnchorCertFile == null) {
            KeyStore keyStore = getKeyStore();
            X509Certificate trustAnchor = getTrustAnchorForGivenCertificate(keyStore, getX509CertificateFromPath(getEeFullCertPath()));
            String tempName = null;
            try {
                File temp;
                temp = File.createTempFile("tmp",".cer", new File(System.getProperty("java.io.tmpdir")));
                tempName = temp.getCanonicalPath();
                OutputStream outStream = new FileOutputStream(temp);
                outStream.write(trustAnchor.getEncoded(), 0, trustAnchor.getEncoded().length);
                outStream.flush();
                outStream.close();
            } catch (IOException | CertificateEncodingException e) {
                e.printStackTrace();
            }
            trustAnchorCertFile = new File(tempName);
        }

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
            fac = CertificateFactory.getInstance("X.509");
            trustAnchorCert = (X509Certificate) fac.generateCertificate(new FileInputStream(trustAnchorCertFile));
            rv = isValid(eeCert, policyOids, trustAnchorCert);
        } catch (CertificateException | IOException | NoSuchAlgorithmException | CertStoreException | CertPathBuilderException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            String msg = trustAnchorCertFile.getName() + ": " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException();
        }

        return rv;
    }


    /**
     * Determines if a valid certificate path can be built to the specified trust anchor using the given policy OIDs
     * @param eeCert X509Certificate end entity cert
     * @param policyOids comma-separated string of policy OIDs
     * @param trustAnchorCert X509Certificate trust anchor cert
     * @return true if the certificate path was built, false if a path cannot be built
     * @throws NoSuchAlgorithmException
     * @throws CertStoreException
     * @throws CertPathBuilderException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     */
    public boolean isValid(X509Certificate eeCert, String policyOids, X509Certificate trustAnchorCert) throws NoSuchAlgorithmException, CertStoreException, CertPathBuilderException, InvalidAlgorithmParameterException, NoSuchProviderException, ConformanceTestException {
        if (eeCert == null) {
            String msg = "End-entity cert must not be null";
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }

        X509Certificate v_eeCert = eeCert;
        X509Certificate v_trustAnchorCert = trustAnchorCert;
        if (v_trustAnchorCert == null) {
            KeyStore keyStore = getKeyStore();
            try {
                v_trustAnchorCert = getTrustAnchorForGivenCertificate(keyStore, v_eeCert);
            } catch (ConformanceTestException e) {
                e.printStackTrace();
            }
        }

        try {
            List<X509Certificate> certList = new ArrayList<>();
            certList.add(v_eeCert);

            TrustAnchor trustAnchor = new TrustAnchor(v_trustAnchorCert, null);
            Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
            trustAnchors.add(trustAnchor);

            CertStore certStore = null;
            if (getCaFileName() != null) {
                certStore = getCertStore(getCaPathString(), getCaFileName());
            } else {
                certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
            }

            Set<X509Certificate> certSet = (Set<X509Certificate>) certStore.getCertificates(null);
            certSet.add(v_eeCert);
            if (v_trustAnchorCert != null)
                certSet.add(v_trustAnchorCert);

            System.setProperty("com.sun.security.enableAIAcaIssuers", String.valueOf(getDownloadAia()));
            System.setProperty("com.sun.security.crl.timeout", String.valueOf(10));
            System.setProperty("ocsp.enable", String.valueOf(getDownloadAia()));

            String[] allowedPolicies = policyOids.split("\\|");
            HashSet<String> policies = new HashSet<String>(Arrays.asList(allowedPolicies));

            // Validate the cert for appropriate policy OID
            CertPath certPath = validateCertificate(v_eeCert, certSet, policies);
            if (certPath != null) {
                s_logger.debug("Build passed, path contents: " + certPath);
            }
            return certPath != null;
        } catch (ConformanceTestException e) {
            s_logger.error("Check test artifacts");
            e.printStackTrace();
        } catch (CertPathBuilderException | NoSuchAlgorithmException | NoSuchProviderException | CertStoreException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw e;
        }
        return false;
    }

    /**
     * Validates a certificate for a collection of CA certs and policy OIDs
     * @param certificate to be validated
     * @param additionalCerts certs to build a path with
     * @param policies policy OIDs, one of which must be valid in each certificate in the path
     * @return CertPath containing the certificates in the path if the certificate is valid for the path, false if any other condition occurs
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws CertPathBuilderException
     */
    private CertPath validateCertificate(X509Certificate certificate, Set<X509Certificate> additionalCerts, HashSet<String> policies) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, CertPathBuilderException{

        Set<X509Certificate> trustedRoots = new HashSet<X509Certificate>();
        Set<X509Certificate> intermediateCerts = new HashSet<X509Certificate>();

        // Random collection of CA and self-signed CA certs
        for (X509Certificate cert : additionalCerts) {
            if (cert != null) {// TODO: why would one of these be null?
                String subject = cert.getSubjectDN().getName();
                String issuer = cert.getIssuerDN().getName();
                s_logger.debug("Subject: " + subject);
                s_logger.debug("Issuer: " + issuer);
                if (subject.equals(issuer)) {
                    trustedRoots.add(cert);
                } else {
                    //intermediateCerts.add(cert);
                }
            }
        }

        // Configure trust anchor
        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
        for (X509Certificate root : trustedRoots) {
            trustAnchors.add(new TrustAnchor(root, null));
        }

        // Target is our EE cert
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(certificate);

        // Set up parameters
        PKIXParameters parameters = new PKIXBuilderParameters(trustAnchors, selector);
        parameters.setRevocationEnabled(false);
        CollectionCertStoreParameters csp = new CollectionCertStoreParameters(intermediateCerts);
        CertStore intermediateCertStore = CertStore.getInstance("Collection", csp, this.getProvider().equals("BC") ? "BC" : "SUN");
        parameters.addCertStore(intermediateCertStore);
        parameters.setRevocationEnabled(false);
        parameters.setSigProvider(getProvider());
        parameters.setInitialPolicies(policies);
        parameters.setExplicitPolicyRequired(false);
        parameters.setPolicyMappingInhibited(false);
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", this.getProvider().equals("BC") ? "BC" : "SUN");
        CertPathBuilderResult cpbResult = cpb.build(parameters);
        CertPath certPath = cpbResult.getCertPath();
        return certPath;
    }

    /**
     * Loads a CMS-signed bundle of CA certs
     * @return
     */
    private CertStore getCertStore(String caPathString, String caFileName) throws ConformanceTestException {
        CertStore certStore = null;
        String v_caFileName = caFileName;
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
                OutputStream outStream = new FileOutputStream(v_caFileName);
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
        } else if (caPathString != null && (caPathString.toLowerCase().startsWith("file:///") || caPathString.toLowerCase().startsWith("/") || caPathString.toLowerCase().startsWith("\\"))) {
            v_caFileName = TestRunLogController.pathFixup((caPathString.replaceFirst("file:///", "") + "/") + caFileName);
        } else if (caPathString == null ) {
            s_logger.warn("m_caPathString not initialized");
        } else {
            s_logger.warn("unsupported URL scheme");
        }

        s_logger.debug("Opening " + v_caFileName);

        try {
            FileInputStream fis = new FileInputStream(v_caFileName);
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
                s_logger.warn(v_caFileName + " was not found");
            }
        } catch (NoSuchAlgorithmException e) {
            String msg = "Crypto failure loading certs from " + v_caFileName + ": " + e.getMessage();
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        } catch (Exception e) {
            String msg = "IO problem reading " + v_caFileName + ": " + e.getMessage();
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
        m_resourceDir = ".";
        m_caFileName = s_caFileName;
        m_caPathString = null;
        m_cpb = null;
        m_keystore = null;
        m_downloadAia = false;
        m_resourceDir = ".";
        try {
            setProvider(provider);
            setCertPathBuilder(s_certPathBuilderProviders.get(provider));
            setKeyStore(keyStoreName, password);
            setCaFileName(certStoreName);
        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            s_logger.error(e.getMessage());
            throw new ConformanceTestException(e.getMessage());
        }
    }
}
