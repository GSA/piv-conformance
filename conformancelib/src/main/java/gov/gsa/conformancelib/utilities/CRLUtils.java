/**
 * 
 */
package gov.gsa.conformancelib.utilities;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashSet;

import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.LoggerFactory;

/**
 * Class of CRL handling utilities
 *
 */
public class CRLUtils {
	
	private static final org.slf4j.Logger s_logger = LoggerFactory.getLogger(Utils.class);
	/**
	 * Load an X509CRL from the named file
	 * 
	 * @param path
	 * @return the X509CRL
	 */
	public static X509CRL loadCRLFromFile(String path) {
		X509CRL result = null;
		FileInputStream in;
		s_logger.debug("Loading CRL from file at " + path);
		try {
			in = new FileInputStream(path);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			result = (X509CRL) cf.generateCRL(in);
			in.close();
		} catch (Exception e) {
        	s_logger.error("Exception: " + e.getMessage());
		}

		return result;
	}	
	/**
	 * Produces a set of CRLs from a certificates's CRL distribution points
	 * @param cert certificate to be parsed
	 * @return a collection of CRLs
	 */
	public static HashSet<X509CRL> getCRLsFromCertificate(X509Certificate cert) {
		HashSet<X509CRL> crls = new HashSet<X509CRL>();
        try
        {
        	byte[] crlDistributionPointDerEncodedArray = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());

            ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crlDistributionPointDerEncodedArray));
            ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
            DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;

            oAsnInStream.close();

            byte[] crldpExtOctets = dosCrlDP.getOctets();
            ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
            ASN1Primitive derObj2 = oAsnInStream2.readObject();
            CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);

            oAsnInStream2.close();

            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            	DistributionPointName dpn = dp.getDistributionPoint();
            	// Look for URIs in fullName
            	if (dpn != null) {
            		if (dpn.getType() == DistributionPointName.FULL_NAME) {
            			GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
            			// Look for an URI
            			for (int j = 0; j < genNames.length; j++) {
            				if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
            					String urlStr = DERIA5String.getInstance(genNames[j].getName()).getString();
            					try {
	            					if (urlStr.startsWith("http")) {
	            						URL url = new URL(urlStr);
		            					s_logger.debug("CRL URL: " + urlStr);
		            					String crlPath = System.getProperty("java.io.tmpdir") + File.separator + FilenameUtils.getName(url.getPath());
		            					ReadableByteChannel readableByteChannel = Channels.newChannel(url.openStream());
		            					@SuppressWarnings("resource")
										FileOutputStream fileOutputStream = new FileOutputStream(crlPath);
		            					FileChannel fileChannel = fileOutputStream.getChannel();
		            					fileChannel.transferFrom(readableByteChannel, 0, Long.MAX_VALUE);
		            					fileChannel.close();
		            					crls.add(loadCRLFromFile(crlPath));
	            					}
            					} catch (MalformedURLException e) {
            						s_logger.error("Exception " + e.getMessage());
            					}
            				}
            			}
            		}
            	}
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return crls;
    }

	@SuppressWarnings("null")
	public static HashSet<X509CRL> getCRLsFromCerts(HashSet<X509Certificate> certs) {
		HashSet<X509CRL> result = new HashSet<X509CRL>();
		for (X509Certificate cert : certs) {
			for (X509CRL crl : getCRLsFromCertificate(cert)) {
				if (crl != null) {	 
					if (!result.contains(crl)) {
						s_logger.debug("Issued to: " + cert.getSubjectDN().getName().toString());
						s_logger.debug("Issued by: " + cert.getIssuerDN().getName().toString());
						s_logger.debug("Adding " + crl.getIssuerDN().getName() + ", next update: " + crl.getThisUpdate());
						result.add(crl);
					} else {
						s_logger.debug("Already added " + crl.getIssuerDN().getName() + ", next update: " + crl.getThisUpdate());
					}
				}
			}
		}
		return result;
	}
}
