package gov.gsa.conformancelib.utilities;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
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
import java.security.cert.CertificateException;
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
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PathValidator {

	public static CertPath buildCertPath(X509Certificate eeCert, String trustAnchorAlias, KeyStore ks,
			String certPolicyOid) {
		try {
			CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
			X509CertSelector eeCertSelector = new X509CertSelector();
			eeCertSelector.setSubject(eeCert.getSubjectX500Principal().getEncoded());

			List<X509Certificate> certList = new ArrayList<>();
			certList.add(eeCert);
			Enumeration<String> enumeration = ks.aliases();
			Set<TrustAnchor> trustAnchors = new HashSet<>();
			while (enumeration.hasMoreElements()) {
				String alias = enumeration.nextElement();
				X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
				String skidString = Hex.encodeHexString(CertUtils.getExtensionValue(certificate, Extension.subjectKeyIdentifier.toString()).getEncoded());

				if (!alias.equals(trustAnchorAlias) && !CertUtils.isCertificateSelfSigned(certificate)) {
					certList.add(certificate);
					String akidString = Hex.encodeHexString(CertUtils.getExtensionValue(certificate, Extension.authorityKeyIdentifier.toString()).getEncoded());

					System.out.println(skidString.substring(4) + " " + akidString.substring(8) + " " + alias + ": "  + certificate.getSubjectX500Principal()
					+ " Issuer: " + certificate.getIssuerX500Principal());
				} else {
					trustAnchors.add(new TrustAnchor(certificate, null));
					System.out.println(skidString.substring(4) + " " + alias + ": "  + certificate.getSubjectX500Principal()
					+ " Issuer: " + certificate.getIssuerX500Principal());
				}
			}

			CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList));
			PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, eeCertSelector);
			params.addCertStore(certStore);
			params.setRevocationEnabled(false);
			HashSet<String> policies = new HashSet<String>();
			policies.add(certPolicyOid);
			params.setInitialPolicies(policies);
			params.setExplicitPolicyRequired(true);
			params.setMaxPathLength(6);
			params.setDate(new Date());

			PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(params);

			return result.getCertPath();

		} catch (IOException | KeyStoreException | NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
			System.out.println("Can't build certificate chain: " + ex.getMessage());
		} catch (CertPathBuilderException ex) {
			System.out.println("Policy error: " + ex.getMessage());
		}
		return null;
	}

	public static boolean isCertficatePolicyPresent(String keyStorePath, String keyStorePass, String trustAnchorAlias, String eeCertFile, String certPolicyOid) throws Exception {
		// create certificates and CRLs
		java.security.Security.addProvider(new BouncyCastleProvider());
		String cwd = Utils.pathFixup(PathValidator.class.getProtectionDomain().getCodeSource().getLocation().getPath());
		System.out.println("Current directory is " + cwd);
		FileInputStream eeIs = new FileInputStream(eeCertFile);
		CertificateFactory eeCf = CertificateFactory.getInstance("X.509");
		X509Certificate eeCert = (X509Certificate) eeCf.generateCertificate(eeIs);
		eeIs.close();
		
		return isCertficatePolicyPresent(keyStorePath, keyStorePass, trustAnchorAlias, eeCert, certPolicyOid);
	}

	public static boolean isCertficatePolicyPresent(String keyStorePath, String keyStorePass, String trustAnchorAlias, X509Certificate eeCert, String certPolicyOid) {
		String cwd = Utils.pathFixup(PathValidator.class.getProtectionDomain().getCodeSource().getLocation().getPath());
		System.out.println("Current directory is " + cwd);
		boolean result = false;
		try {
			KeyStore keyStore = Utils.loadKeyStore(keyStorePath, keyStorePass);
			//List<X509Certificate> certList = CertUtils.getIssuerCerts(eeCert);
			CertPath certPath = buildCertPath(eeCert, trustAnchorAlias, keyStore, certPolicyOid);

			if (certPath != null) {
				@SuppressWarnings("unchecked")
				List<X509Certificate> certs = (List<X509Certificate>) certPath.getCertificates();
		
				Iterator<X509Certificate> it = certs.iterator();
				while (it.hasNext()) {
					System.out.println(((X509Certificate) it.next()).getSubjectX500Principal());
				}
				result = true;
			}
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;	
	}
	
	public static void main (String[] argv) {
		System.out.println("Argv[0]: " + argv[0]);
		System.out.println("Argv[1]: " + argv[1]);
		System.out.println("Argv[2]: " + argv[2]);
		System.out.println("Argv[3]: " + argv[3]);

		try {
			isCertficatePolicyPresent(argv[0], argv[1], argv[2], argv[3], "2.16.840.1.101.3.2.1.3.18");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}