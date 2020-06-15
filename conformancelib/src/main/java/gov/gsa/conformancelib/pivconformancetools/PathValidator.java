package gov.gsa.conformancelib.pivconformancetools;

import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import gov.gsa.conformancelib.utilities.Utils;

public class PathValidator {

	private static PKIXCertPathBuilderResult buildCertPath(X509Certificate eeCert, String trustAnchorAlias, String keystorePath, String keystorePass) 
			throws KeyStoreException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathBuilderException {
		PKIXCertPathBuilderResult result = null;
		KeyStore keyStore = Utils.loadKeyStore(keystorePath, keystorePass);
		X509Certificate commonPolicyCert = (X509Certificate) keyStore.getCertificate(trustAnchorAlias);
		X509CertSelector target = new X509CertSelector();
		target.setCertificate(eeCert);
		PKIXBuilderParameters params = new PKIXBuilderParameters(keyStore, target);
        // build the path
        CertPathBuilder builder = null;
        List list = new ArrayList();

        try {
	        list.add(commonPolicyCert);

	        // Now, add intermediate certs to the list
	        HashSet<X509Certificate> certs = Utils.getIntermediateCerts(keyStore);
	        list.addAll(certs);

	        HashSet<X509CRL> crls = Utils.getCRLsFromCerts(certs);
	        list.addAll(crls);

	        // Make parameters object
	        CollectionCertStoreParameters csParams = new CollectionCertStoreParameters(list);

	        // Set EE target
	        X509CertSelector endConstraints = new X509CertSelector();       
	        endConstraints.setCertificate(eeCert);
	        
	        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(commonPolicyCert, null)), endConstraints);

	        CertStore store = CertStore.getInstance("Collection", csParams, "BC");
	        buildParams.addCertStore(store);
	        buildParams.setDate(new Date());
	        builder = CertPathBuilder.getInstance("PKIX", "BC");
	        result = (PKIXCertPathBuilderResult) builder.build(buildParams);
	        CertPath path = result.getCertPath();			

	        @SuppressWarnings("unchecked")
			Iterator<Certificate>  it = (Iterator<Certificate>) path.getCertificates().iterator();
	        while (it.hasNext()) {
	            System.out.println(((X509Certificate)it.next()).getSubjectX500Principal());
	        }
	        
	        System.out.println(result.getTrustAnchor().getTrustedCert().getSubjectX500Principal());
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}
 
		return result;
	}

	public static void main(String args[]) throws Exception {
        // create certificates and CRLs
		java.security.Security.addProvider(new BouncyCastleProvider());
		String cwd = Utils.pathFixup(PathValidator.class.getProtectionDomain().getCodeSource().getLocation().getPath());
		System.out.println("Current directory is " + cwd);
		String keystorePath = args[0];
		String keystorePass = args[1];
		CertificateFactory eeCf = CertificateFactory.getInstance("X.509");
		FileInputStream in1 = new FileInputStream(args[2]);
		X509Certificate eeCert = (X509Certificate) eeCf.generateCertificate(in1);
		in1.close();

		PKIXCertPathBuilderResult cpbr = buildCertPath(eeCert, "federal common policy ca", keystorePath, keystorePass);
		if (cpbr != null) {
			List<List<X509Certificate>> certPath = Utils.getCompleteCertChain(cpbr);
			System.out.println(certPath.toString());
		}		
	}
}