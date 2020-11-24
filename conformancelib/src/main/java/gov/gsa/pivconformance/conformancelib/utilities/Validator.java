package gov.gsa.pivconformance.conformancelib.utilities;

//import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * Provides the API to validating a given end entity certificate for
 * a given certificate policy.
 */
public class Validator {
    static Logger s_logger = LoggerFactory.getLogger(Validator.class);
    private static KeyStore m_keystore = null;
    private static final String m_monitorUrlString = "https://monitor.certipath.com/fpki/download/all/p7b";
    private static final String m_monitorFileName = "all.p7b";
    private static URL m_monitorUrl = null;

    public Validator() {
        setKeyStore("x509-certs/cacerts.keystore", "changeit");
    }

    /**
     * Sets the validator's KeyStore to keyStoreName
     *
     * @param keyStoreName the path to the KeyStore file
     */

    public void setKeyStore(String keyStoreName, String password) {
        InputStream is = Validator.getFileFromResourceAsStream(Validator.class, keyStoreName);
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(is, password.toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
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
     * Gets a file from the specified resource for the specified class.
     *
     * @param clazz    the class requesting its resource
     * @param fileName the basename of the resource file
     * @return InputStream to the open resource
     */
    public static InputStream getFileFromResourceAsStream(Class clazz, String fileName) {
        ClassLoader classLoader = clazz.getClassLoader();
        InputStream inputStream = null;
        try {
            inputStream = classLoader.getResourceAsStream(fileName);
        } catch (Exception e) {
            s_logger.error("Can't open '" + fileName + "': ", e.getMessage());
        }
        return inputStream;
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: Validator <end certificate filepath>  <trust anchor filepath> <Space delimited string of acceptable policy OIDs>");
        }

        File endEntityCertFile = new File(args[0]);
        File trustAnchorFile = new File(args[1]);
        StringBuilder sb = new StringBuilder();
        for (int i = 2; i < args.length; i++) {
            if (sb.length() != 0) sb.append("|");
        }
        String policyOids = sb.toString();
        isValid(endEntityCertFile, policyOids, trustAnchorFile);
    }

    public static boolean isValid(String endEndityCertFile, String policyOids, String trustAnchorFile) {
        File eeFile = new File(endEndityCertFile);
        File taFile = new File(trustAnchorFile);
        return isValid(eeFile, policyOids, taFile);
    }

    public static boolean isValid(File endEntityCertFile, String policyOids, File trustAnchorFile) {
        CertificateFactory fac;
        boolean rv = false;
        try {
            fac = CertificateFactory.getInstance("X509");
            X509Certificate eeCert = (X509Certificate) fac.generateCertificate(new FileInputStream(endEntityCertFile));
            X509Certificate trustAnchorCert = (X509Certificate) fac.generateCertificate(new FileInputStream(trustAnchorFile));
            return isValid(eeCert, policyOids, trustAnchorCert);
        } catch (CertificateException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return rv;
    }

    /**
     * Loads a CMS-signed bundle of CA certs
     * @param fileUrl
     * @return
     */
    private static boolean loadBundle(String fileUrl) {
        if (getMonitorUrl() != null)
            return true; // Cached

        boolean success = false;
        InputStream in = null;
        try {
            setMonitorUrl(new URL(m_monitorUrlString));
            TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
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
            URLConnection con = getMonitorUrl().openConnection();
            byte[] buf = con.getInputStream().readAllBytes();
            OutputStream outStream = new FileOutputStream(m_monitorFileName);
            outStream.write(buf, 0, buf.length);
            outStream.flush();
            outStream.close();
            success = true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (Exception e) {
            s_logger.warn(("Can't fetch " + getMonitorUrl() + ": " + e.getMessage()));
        }
        return success;
    }

    /**
     * Sets the
     * @param url
     */
    public static void setMonitorUrl(URL url) {
        m_monitorUrl = url;
    }

    /**
     * Gets the monitor URL
     * @return the monitor URL
     */
    public static URL getMonitorUrl() {
        return m_monitorUrl;
    }

    /**
     * Determines if a valid certificate path can be built to the specified trust anchor using the given policy OIDs
     * @param eeCert end entity cert
     * @param policyOids comma-separated string of policy OIDs
     * @param trustAnchorCert
     * @return true if the certificate path was built, false if a path cannot be built
     */
    public static boolean isValid(X509Certificate eeCert, String policyOids, X509Certificate trustAnchorCert) {
        // CertiPath monitor creates a CA bundle file which we can use for trust anchors
        try {
            List<X509Certificate> certList = new ArrayList<>();
            certList.add(eeCert);
            X509CertSelector eeCertSelector = new X509CertSelector();
            eeCertSelector.setCertificate(eeCert);
            TrustAnchor trustAnchor = new TrustAnchor(trustAnchorCert, null);

            Security.addProvider(new BouncyCastleProvider());

            // Create CertPathBuilder that implements the "PKIX" algorithm
            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", "BC");

            // ---------------------------------------------------------------------------------- //
            // Uncomment to use Bouncy Castle Provider - Requires FPKI Crawler's output file
            // This output file contains a series of issuing CA's trusted by a given trust anchor

            // Open an input stream to the bundle file
            //
            if (loadBundle(m_monitorUrlString)) {

                FileInputStream fis = new FileInputStream(m_monitorFileName);
                if (fis != null) {
                    // Instantiate a CertificateFactory for X.509
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    // Extract the certification path from the PKCS7 SignedData structure
                    CertPath cp = cf.generateCertPath(fis, "PKCS7");
                    List<X509Certificate> certs = (List<X509Certificate>) cp.getCertificates();
                    certList.addAll(certs);
                    cpb = CertPathBuilder.getInstance("PKIX");//, new BouncyCastleProvider());
                } else {
                    s_logger.warn(m_monitorUrlString + " was not found");
                }
            }
            //
            // ---------------------------------------------------------------------------------- //

            CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            trustAnchors.add(trustAnchor);
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, eeCertSelector);
            params.addCertStore(certStore);
            params.setRevocationEnabled(false);
            params.setMaxPathLength(10);
            params.setSigProvider("BC");
            // Defining required Policy OID
            HashSet<String> policies = new HashSet<>();
            String[] allowedPolicies = policyOids.split("|");
            policies = new HashSet<>(Arrays.asList(allowedPolicies));
            params.setInitialPolicies(policies);
            params.setExplicitPolicyRequired(true);
            params.setPolicyMappingInhibited(false);

            System.setProperty("com.sun.security.enableAIAcaIssuers", String.valueOf(true));
            CertPathBuilderResult cpbResult = cpb.build(params);
            CertPath certPath = cpbResult.getCertPath();
            s_logger.info("Build passed, path contents: " + certPath);
            return certPath != null;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
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
}
