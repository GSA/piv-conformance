/**
 * 
 */
package gov.gsa.conformancelib.utilities;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.slf4j.LoggerFactory;

/**
 * @author bf7450
 *
 */
public class CertUtils {
	private static final org.slf4j.Logger s_logger = LoggerFactory.getLogger(Utils.class);

    public static X509Certificate getIssuerCertFromBundle(URL location, byte[] subjectAkid) throws CertificateException, IOException {
    	String bundlePath = System.getProperty("java.io.tmpdir") + FilenameUtils.getName(location.getPath());
    	ASN1OctetString akidOctetString = ASN1OctetString.getInstance(subjectAkid);
    	AuthorityKeyIdentifier akid = AuthorityKeyIdentifier.getInstance(akidOctetString.getOctets());
    	X509Certificate issuerCert = null;
		try {
	    	ReadableByteChannel readableByteChannel = Channels.newChannel(location.openStream());
			@SuppressWarnings("resource")
			FileOutputStream fileOutputStream = new FileOutputStream(bundlePath);
			FileChannel fileChannel = fileOutputStream.getChannel();
			fileChannel.transferFrom(readableByteChannel, 0, Long.MAX_VALUE);
			fileChannel.close();
	    	List<X509Certificate> certs = loadCertsFromBundle(bundlePath);
			for (X509Certificate c : certs) {
				byte[] issuerSkid = c.getExtensionValue(Extension.subjectKeyIdentifier.getId());
				ASN1OctetString skidOctetString = ASN1OctetString.getInstance(issuerSkid);
				SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(skidOctetString.getOctets());

				if (Arrays.equals(skid.getKeyIdentifier(), akid.getKeyIdentifier())) {
					issuerCert = c;
					String certFilePath;
					certFilePath = System.getProperty("java.io.tmpdir") + Hex.encodeHexString(akid.getKeyIdentifier()) + ".cer";
					Path certPath = Paths.get(certFilePath);
					try {
						Files.write(certPath, c.getEncoded());
						s_logger.debug("Wrote certificate " + certFilePath);
					} catch (CertificateEncodingException | IOException e) {
						s_logger.error("Unable to write certificate", e);
						throw e;
					}

					break;
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}
		return issuerCert;
    }
    
    /**
     * Gets the issuer certificate of the CA that issued the given certificate
     * @param cert the certificate for which the issuer is being sought
     * @return the issuer certificate or null if not found
     * @throws Exception 
     */
	public static X509Certificate getIssuerCert(X509Certificate cert) throws Exception {

		X509Certificate caCert = null;
		byte issuerAkid[] = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
		
		try {
			String issuerUrl = getAiaUrl(cert);
			URL url = new URL(issuerUrl);
            if (url.getPath().toLowerCase().matches("^.*p7[bc]$")) {
            	s_logger.trace("Issuer cert is in a bundle");
            	caCert = getIssuerCertFromBundle(url, issuerAkid);
                if (caCert != null) {
                	s_logger.debug(caCert.toString());
                }
            } else {
            	s_logger.trace("Issuer cert is a cert");
            	String aiaPath = System.getProperty("java.io.tmpdir") + FilenameUtils.getName(url.getPath());
                caCert = loadCertFromFile(aiaPath);
                if (caCert != null) {
                	s_logger.debug(caCert.toString());
                }
            }
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		} 
		
		return caCert;
    }
	
	/**
	 * Gets the issuer cert for a given cert
	 * @param cert certificate to be parsed
	 * @return a list of certificates of the issuer CAs
	 */
	public static List<X509Certificate> getIssuerCerts(X509Certificate cert) {
		List<X509Certificate> rv = new ArrayList<X509Certificate>();
		X509Certificate caCert = null;
		boolean done = false;
		while (!done) {
			try {
				caCert = getIssuerCert(cert);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if (caCert != null) {
				if (!(caCert.getSubjectX500Principal().equals(caCert.getIssuerX500Principal()))) {
					rv.add(caCert);
				} else {
					done = true;
				}
				cert = caCert;
			} else {
				done = true;
				s_logger.error("Couldn't retrieve issuer cert");
			}
		}

		return rv;
	}
	
	/**
	 * Gets the X509 extension value for a given OID
	 * @param certificate to be parsed
	 * @param oid OID corresponding to the desired extension
	 * @return the value expressed as an ASN1Primitive
	 * @throws IOException
	 */ 
    private static ASN1Primitive getExtensionValue(X509Certificate certificate, String oid) throws IOException {
    	ASN1Primitive rv = null;
        byte[] bytes = certificate.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs;
		try {
			octs = (ASN1OctetString) aIn.readObject();
	        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
	        rv = aIn.readObject();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}
		return rv;
    }

    /**
     * Gets the URL corresponding to the AuthorityInformationAccess extension
     * @param cert the certificate to extract the AIA from
     * @return a string containing the URL
     * @throws IOException 
     */
    public static String getAiaUrl(X509Certificate cert) throws IOException {
    	ASN1Primitive obj;
    	String url = null;
    	try {
			if ((obj = getExtensionValue(cert, Extension.authorityInfoAccess.getId())) != null) {
				AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(obj);

				AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
				for (AccessDescription accessDescription : accessDescriptions) {
					if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
						GeneralName name = accessDescription.getAccessLocation();
						if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
							continue;
						}

						DERIA5String derStr = DERIA5String.getInstance((ASN1TaggedObject) name.toASN1Primitive(), false);
						url = derStr.getString();;
					}
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}
    	
    	return url;
    }
    
    /**
     * Determines whether a certificate is self-signed
     * @param cert to be checked
     * @return true if the certificate is self-signed
     */
	public static boolean isCertificateSelfSigned(X509Certificate cert) {
		boolean result = false;
        PublicKey key = cert.getPublicKey();
        try {
        	cert.verify(key);
        	result = true;
        } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
        	s_logger.error("Exception: " + e.getMessage());
        }
        return result;
	}
   
	/**
	 * Extracts all non- self-signed certificates from the given KeyStore
	 * 
	 * @param KeyStore object containing the certificates
	 * @return Set of X509Certificate
	 * @throws Exception 
	 */	
    public static HashSet<X509Certificate> getIntermediateCerts(KeyStore keyStore) throws Exception {
		HashSet<X509Certificate> result = new HashSet<X509Certificate>();
		Enumeration<String> aliases = null;
		try {
			aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
				if (!isCertificateSelfSigned(cert)) {
	            	result.add((X509Certificate) keyStore.getCertificate(alias));
				}
			}	
		} catch (Exception e) {
        	s_logger.error("Exception: " + e.getMessage());
        	throw e;
		}
		return result;
	}
 	
	/**
	 * Load an X509 certificate from the named file
	 * 
	 * @param path
	 * @return the X509Certificate
	 */	
	public static X509Certificate loadCertFromFile(String path) {
		X509Certificate result = null;
		FileInputStream in;
		s_logger.debug("Loading X509 certificate from file at " + path);

		try {
			in = new FileInputStream(path);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			result = (X509Certificate) cf.generateCertificate(in);
			byte[] issuerSkid = result.getExtensionValue(Extension.subjectKeyIdentifier.getId());
			ASN1OctetString skidOctetString = ASN1OctetString.getInstance(issuerSkid);
			SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(skidOctetString.getOctets());
			String certFilePath = System.getProperty("java.io.tmpdir") + Hex.encodeHexString(skid.getKeyIdentifier()) + ".cer";
			Path certPath = Paths.get(certFilePath);
			try {
				Files.write(certPath, result.getEncoded());
				s_logger.debug("Wrote certificate " + certFilePath);
			} catch (CertificateEncodingException | IOException e) {
				s_logger.error("Unable to write certificate", e);
				throw e;
			}
			in.close();
		} catch (CertificateException | IOException e) {
        	s_logger.error("Exception: " + e.getMessage());
		}

		return result;
	}
	
	/**
	 * Extracts X509 certificates from the PKCS7 object read from the given file system path 
	 * 
	 * @param path the location of the file
	 * @return a list of X509 certificates or null if none were extracted
	 * @throws CertificateException, IOException 
	 */
	public static List<X509Certificate> loadCertsFromBundle(String path) throws CertificateException, IOException {
		List<X509Certificate> rv = new ArrayList<X509Certificate>();
		FileInputStream in;
		s_logger.debug("Loading X509 certificates from file at " + path);
		try {
			in = new FileInputStream(path);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			@SuppressWarnings("unchecked")
			Iterator<Certificate> i = (Iterator<Certificate>) cf.generateCertificates(in).iterator();
			in.close();
			while (i.hasNext()) {
				X509Certificate cert = (X509Certificate)i.next();
				rv.add(cert);
			} 
		} catch (CertificateException | IOException e) {
        	s_logger.error("Exception: " + e.getMessage());
        	throw e;
		} catch (Exception e) {
        	s_logger.error("Unexpected exception: " + e.getMessage());
        	throw e;
		}
		
		return rv;
	}
}
