package gov.gsa.conformancelib.utilities;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.slf4j.LoggerFactory;

public class Utils
{
	private static final org.slf4j.Logger s_logger = LoggerFactory.getLogger(Utils.class);;

    /**
     * Returns a list of certificates in each chain identified in a PKIXCertPathBuilderResult object
     * @param pkixCertPath the results of the path builder build method
     * @return a list of certificates
     * @throws CertificateException
     */
	public static List<List<X509Certificate>> getCompleteCertChain(PKIXCertPathBuilderResult pkixCertPath)
            throws CertificateException {
        List<List<X509Certificate>> certificateList = new ArrayList<>();

        List<X509Certificate> certificatePath = new ArrayList<>();
        X509Certificate rootCaCert = pkixCertPath.getTrustAnchor().getTrustedCert();
		@SuppressWarnings("unchecked")
		Collection<X509Certificate> collection =  (Collection<X509Certificate>) pkixCertPath.getCertPath().getCertificates();
        certificatePath.addAll(collection);
        certificatePath.add(rootCaCert);

        int certificatesSize = certificatePath.size();
        if (1 == certificatesSize) {
            throw new CertificateException("Certificate Path insufficient size: must be at least 2");
        }
        for (int i = 0; i < certificatesSize; i++) {
            if (certificatesSize - 1 == i) {  //We've reached the root CA
                break;
            } else {
                List<X509Certificate> certTuple = new ArrayList<>(2);
                certTuple.add((X509Certificate)certificatePath.get(i));
                certTuple.add((X509Certificate)certificatePath.get(i+1));
                certificateList.add(certTuple);
            }
        }
        return certificateList;
    } 

	/**
	 * Extracts a set of TrustAnchor objects from a KeyStore
	 * @name getTrustAnchors
	 * @c
	 */
	
	/**
	 * Gets a set of self-signed from a given keyStore
	 * @param keyStore
	 * @return Set of TrustAnchor
	 */
	public static HashSet<TrustAnchor> getTrustAnchors(KeyStore keyStore) {
		
		HashSet<TrustAnchor> result = new HashSet<TrustAnchor>();

		Enumeration<String> aliases;
		try {
			aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
				if (CertUtils.isCertificateSelfSigned(cert)) {
	            	TrustAnchor ta = new TrustAnchor(cert, null);
	            	result.add(ta);
	            }
			}
		} catch (Exception e1) {
        	s_logger.error("Exception: " + e1.getMessage());
		}
		return result;
	}
	   
	/**
	 * Load a TrustAnchor object from a given keystore and password
	 * 
	 * @param keystorePath the location of the keystore 
	 * @param keystorePass the password to the keystore
	 * @return a TrustAnchor object
	 * @throws KeyStoreException
	 */
	public static KeyStore loadKeyStore(String keystorePath, String keystorePass) throws KeyStoreException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		s_logger.debug("Loading keystore from file at " + keystorePath);
		try (InputStream in = new FileInputStream(keystorePath)) {
			keyStore.load(in, keystorePass.toCharArray());
		} catch (CertificateException | NoSuchAlgorithmException | IOException e) {
        	s_logger.error("Exception: " + e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
		}

		return keyStore;
	}
	
	/**
	 * Corrects the path separators for a path.
	 * 
	 * @param inPath the path as read from a configuration file, etc.
	 * @return a path with the correct path separators for the local OS
	 */
 
	public static String pathFixup(String inPath) {
		boolean windowsOs = false;
		String osName = System.getProperty("os.name");

		if (osName.toLowerCase().contains("windows")) {
			windowsOs = true;
		}

		String outPath = inPath;
		if (windowsOs == true) {
			if (inPath.contains("/")) {
				outPath = inPath.replace("/", "\\");
			}
		} else if (inPath.contains("\\")) {
			outPath = inPath.replace("\\", "/");
		}

		return outPath;
	}	
	
//	/**
//     * Return a SecureRandom which produces the same value.
//     * 
//     * <b>This is for testing only!</b>
//     * @return a fixed random
//     */
//    public static SecureRandom createFixedRandom() {
//        return new FixedRand();
//    }
//    
    private static String	digits = "0123456789abcdef";
    
    /**
     * Return length many bytes of the passed in byte array as a hex string.
     * 
     * @param data the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data, int length)
    {
        StringBuffer	buf = new StringBuffer();
        
        for (int i = 0; i != length; i++) {
            int	v = data[i] & 0xff;
            
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        
        return buf.toString();
    }
    
    /**
     * Return the passed in byte array as a hex string.
     * 
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }
    
    /**
     * Create a key for use with AES.
     * 
     * @param bitLength
     * @param random
     * @return an AES key.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static SecretKey createKeyForAES(int bitLength, SecureRandom random)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
        
        generator.init(256, random);
        
        return generator.generateKey();
    }
    
    /**
     * Create an IV suitable for using with AES in CTR mode.
     * <p>
     * The IV will be composed of 4 bytes of message number,
     * 4 bytes of random data, and a counter of 8 bytes.
     * 
     * @param messageNumber the number of the message.
     * @param random a source of randomness
     * @return an initialised IvParameterSpec
     */
    public static IvParameterSpec createCtrIvForAES(int messageNumber, SecureRandom random) {
        byte[] ivBytes = new byte[16];
        
        // initially randomize
        
        random.nextBytes(ivBytes);
        
        // set the message number bytes
        
        ivBytes[0] = (byte)(messageNumber >> 24);
        ivBytes[1] = (byte)(messageNumber >> 16);
        ivBytes[2] = (byte)(messageNumber >> 8);
        ivBytes[3] = (byte)(messageNumber >> 0);
        
        // set the counter bytes to 1
        
        for (int i = 0; i != 7; i++) {
            ivBytes[8 + i] = 0;
        }
        
        ivBytes[15] = 1;
        
        return new IvParameterSpec(ivBytes);
    }
    
    /**
     * Convert a byte array of 8 bit characters into a String.
     * 
     * @param bytes the array containing the characters
     * @param length the number of bytes to process
     * @return a String representation of bytes
     */
    public static String toString(byte[] bytes, int length) {
        char[]	chars = new char[length];
        
        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char)(bytes[i] & 0xff);
        }
        
        return new String(chars);
    }
    
    /**
     * Convert a byte array of 8 bit characters into a String.
     * 
     * @param bytes the array containing the characters
     * @return a String representation of bytes
     */
    public static String toString(byte[] bytes) {
        return toString(bytes, bytes.length);
    }
    
    /**
     * Convert the passed in String to a byte array by
     * taking the bottom 8 bits of each character it contains.
     * 
     * @param string the string to be converted
     * @return a byte array representation
     */
    public static byte[] toByteArray(String string) {
        byte[]	bytes = new byte[string.length()];
        char[]  chars = string.toCharArray();
        
        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte)chars[i];
        }
        
        return bytes;
    }

    


}
