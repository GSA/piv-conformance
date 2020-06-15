package gov.gsa.conformancelib.pivconformancetools;


import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.*;

import gov.gsa.conformancelib.utilities.Utils;

/**
 * Basic Example of generating and using a CRL.
 */
public class X509CRLExample
{
	private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week

	public static X509CRL createCRL(X509Certificate caCert, PrivateKey caKey, BigInteger revokedSerialNumber)
			throws Exception {
		Date now = new Date();
    	Principal issuerPrincipal = caCert.getSubjectX500Principal();
    	X500Name issuerName = new X500Name(issuerPrincipal.getName());
		X509v2CRLBuilder crlGen = new X509v2CRLBuilder(issuerName, now);
		AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(caKey.getEncoded());
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);

		crlGen.setNextUpdate(new Date(System.currentTimeMillis() + VALIDITY_PERIOD)); // one week)
		crlGen.addCRLEntry(revokedSerialNumber, now, CRLReason.privilegeWithdrawn);
		crlGen.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert));
		crlGen.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));

		X509CRLHolder holder = crlGen.build(sigGen);
	    final JcaX509CRLConverter jcaX509CRLConverter = new JcaX509CRLConverter();
	    final X509CRL x509CRL = jcaX509CRLConverter.getCRL(holder);
	    return x509CRL;
	}

	public static void main(String[] args)
			throws Exception
	{
		// create CA keys and certificate
		KeyPair              caPair = Utils.generateRSAKeyPair();
		X509Certificate      caCert = Utils.generateRootCert("Test Root CA", caPair);
		BigInteger           revokedSerialNumber = BigInteger.valueOf(2);

		// create a CRL revoking certificate number 2
		X509CRL	crl = createCRL(caCert, caPair.getPrivate(), revokedSerialNumber);

		// verify the CRL
		crl.verify(caCert.getPublicKey(), "BC");

		// check if the CRL revokes certificate number 2
		X509CRLEntry entry = crl.getRevokedCertificate(revokedSerialNumber);
		System.out.println("Revocation Details:");
		System.out.println("  Certificate number: " + entry.getSerialNumber());
		System.out.println("  Issuer            : " + crl.getIssuerX500Principal());

		if (entry.hasExtensions())
		{
			byte[]	ext = entry.getExtensionValue(X509Extensions.ReasonCode.getId());

			if (ext != null)
			{
				DEREnumerated	reasonCode = (DEREnumerated)X509ExtensionUtil.fromExtensionValue(ext);

				System.out.println("  Reason Code       : " + reasonCode.getValue());
			}
		}
	}
}
