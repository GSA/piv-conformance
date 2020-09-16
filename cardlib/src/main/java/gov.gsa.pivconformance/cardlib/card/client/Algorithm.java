/**
 * 
 */
package gov.gsa.pivconformance.cardlib.card.client;

import java.util.HashMap;
import java.util.Iterator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignedData;

/**
 * 
 * Helpers for converting algorithm OIDs to standard names used in PIV
 *
 */
public class Algorithm {
	
	public static final HashMap<String, String> sigAlgOidToNameMap = new HashMap<String, String>() {
		/**
		 * Signature
		 */
		private static final long serialVersionUID = 1L;

		{
			put("1.2.840.113549.1.1.1O", "SHA526withRSA"); // RSA-PKCS1.5 with SHA-256 and PSS padding
			put("1.2.840.113549.1.1.11", "RSASSA-PSS"); // RSA-PSS with SHA256
			put("1.2.840.10045.4.3.2", "SHA256withECDSA"); // SHA-256 with ECDSA
			put("1.2.840.10045.4.3.3", "SHA384withECDSA"); // SHA-384 with ECDSA
		}
	};
	
	public static final HashMap<String, String> digAlgOidToNameMap = new HashMap<String, String>() {
		/**
		 * Digest
		 */
		private static final long serialVersionUID = 1L;

		{
			put("2.16.840.1.101.3.4.2.1", "SHA256");
			put("2.16.840.1.101.3.4.2.2", "SHA384");
		}
	};
	public static final HashMap<String, String> encAlgOidToNameMap = new HashMap<String, String>() {
		/**
		 * Encryption
		 */
		private static final long serialVersionUID = 1L;

		{
			put("1.2.840.113549.1.1.1", "RSA");
			put("1.2.840.10045.2.1", "ECDSA");
		}
	};
	
	/**
	 * Indicates whether this signature block contains only digest algorithms in Table 3-2 of
	 * SP 800-78-4
	 * @param asymmetricSignature the signature to be checked
	 * @return true if the digest is in Table 3-2 and false if not
	 */
	
	public static boolean isDigestAlgInTable32(CMSSignedData asymmetricSignature) {
		Iterator<AlgorithmIdentifier> ih = asymmetricSignature.getDigestAlgorithmIDs().iterator();	
		while (ih.hasNext()) {
			AlgorithmIdentifier ai = ih.next();
			String digAlgOid = ai.getAlgorithm().getId();
			if (!Algorithm.digAlgOidToNameMap.containsKey(digAlgOid))
				return false;
		}
		return true;
	}
}
