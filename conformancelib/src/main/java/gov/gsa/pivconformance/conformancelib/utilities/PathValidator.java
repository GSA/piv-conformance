package gov.gsa.pivconformance.conformancelib.utilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PathValidator {
    static Logger s_logger = LoggerFactory.getLogger(PathValidator.class);

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println ("Usage: PathValidator <end certificate filepath> <Space delimited string of acceptable policy OIDs> <trust anchor filepath>");
        }

        File endEntityCertFile = new File("test.crt");
        File trustAnchorFile = new File("federal_common_policy_ca.cer");
        String policyOids = "2.16.840.1.101.3.2.1.3.18";
        new PathValidator().isValid(endEntityCertFile, policyOids, trustAnchorFile);
    }

    public boolean isValid(File endEntityCertFile, String policyOids, File trustAnchorFile) {
        try {
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            X509Certificate eeCert = (X509Certificate) fac.generateCertificate(new FileInputStream(endEntityCertFile));

            List<X509Certificate> certList = new ArrayList<>();
            certList.add(eeCert);
            X509CertSelector eeCertSelector = new X509CertSelector();
            eeCertSelector.setCertificate(eeCert);

            X509Certificate trustAnchorCert = (X509Certificate) fac.generateCertificate(new FileInputStream(trustAnchorFile));
            TrustAnchor trustAnchor = new TrustAnchor(trustAnchorCert, null);

            // create CertPathBuilder that implements the "PKIX" algorithm
            CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");

            // ---------------------------------------------------------------------------------- //
            // Uncomment to use Bouncy Castle Provider - Requires FPKI Crawler's output file
            // This output file contains a series of issuing CA's trusted by a given trust anchor

            // open an input stream to the file
            /*FileInputStream fis = new FileInputStream("C:\\Users\\Madhuri\\TopTal\\Dropbox\\Fontana Group - PKI project\\Test certificates\\all_from_common.p7b");
            // instantiate a CertificateFactory for X.509
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            // extract the certification path from
            // the PKCS7 SignedData structure
            CertPath cp = cf.generateCertPath(fis, "PKCS7");
            List<X509Certificate> certs = (List<X509Certificate>) cp.getCertificates();
            certList.addAll(certs);
            Security.addProvider(new BouncyCastleProvider());
            cpb = CertPathBuilder.getInstance("PKIX", new BouncyCastleProvider());*/
            // ---------------------------------------------------------------------------------- //


            // build certification path using specified parameters ("params")
            CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            trustAnchors.add(trustAnchor);
            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, eeCertSelector);
            params.addCertStore(certStore);
            params.setRevocationEnabled(false);
            params.setMaxPathLength(10);

            // Defining required Policy OID
            HashSet<String> policies = new HashSet<>();
            String[] allowedPolicies = policyOids.split(":");
            policies = new HashSet<>(Arrays.asList(allowedPolicies));
            params.setInitialPolicies(policies);
            params.setExplicitPolicyRequired(true);
            params.setPolicyMappingInhibited(false);

            System.setProperty("com.sun.security.enableAIAcaIssuers", String.valueOf(true));
            CertPathBuilderResult cpbResult = cpb.build(params);
            CertPath certPath = cpbResult.getCertPath();
            s_logger.info("Path Build passed, Path contents: " + certPath);
            return certPath != null;
        } catch (Exception ex) {
            s_logger.error("Path build failed: " + ex.getMessage());
        }
        return false;
    }
}
