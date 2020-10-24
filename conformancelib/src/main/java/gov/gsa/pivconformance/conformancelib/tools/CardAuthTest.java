package gov.gsa.pivconformance.conformancelib.tools;

import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.IOException;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.cardlib.card.client.CardClientException;
import gov.gsa.pivconformance.cardlib.card.client.GeneralAuthenticateHelper;
import gov.gsa.pivconformance.cardlib.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.cardlib.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.conformancelib.configuration.CardInfoController;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.conformancelib.tests.ConformanceTestException;
import gov.gsa.pivconformance.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.cardlib.utils.PCSCUtils;

public class CardAuthTest {
	static Logger s_logger = LoggerFactory.getLogger(CardAuthTest.class);
	private static final Options s_options = new Options();
	
    static {
        s_options.addOption("h", "help", false, "Print this help and exit");
        s_options.addOption("", "listOids", false, "list container OIDs and exit");
        s_options.addOption("", "listReaders", false, "list connected readers and exit");
        s_options.addOption("a", "appPin", true, "PIV application PIN");
        s_options.addOption("l", "login", false, "Log in to PIV applet using PIV application PIN prior to attempting dump");
        s_options.addOption("", "defaultGetResponse", false, "Use default javax.scardio GET RESPONSE processing");
        s_options.addOption("", "reader", true, "Use the specified reader instead of the first one with a card");
        s_options.addOption("", "parseFile", true, "Decode a container stored in a file");
        s_options.addOption("", "printAlgs", false, "Print the public key algorithm for each cert specified");
    }

    private static void PrintHelpAndExit(int exitCode) {
        new HelpFormatter().printHelp("CardAuthTest <options>", s_options);
        System.exit(exitCode);
    }
    
    
    private static Certificate getBCCertificateFromJCECertificate(X509Certificate cert) {
		ASN1InputStream bcAis;
		try {
			bcAis = new ASN1InputStream(cert.getEncoded());
		} catch (CertificateEncodingException e) {
			s_logger.error("Unable to get encoded cert. Something's wrong.", e);
			return null;
		}
		ASN1Sequence certSeq = null;
		try {
			certSeq = (ASN1Sequence) bcAis.readObject(); bcAis.close();
		} catch (IOException e) {
			s_logger.error("Cert encoding would not round-trip", e);
			return null;
		}
		try {
			bcAis.close();
		} catch (IOException e) {
			s_logger.error("Failed to close ASN1 input stream", e);
			// muddle on... a leak won't matter in this tool
		}
		Certificate bcCert = Certificate.getInstance(certSeq);
		if(bcCert == null) {
			s_logger.error("Bouncy castle failed to decode certificate from java");
			return null;
		}
		return bcCert;
    	
    }
    
    private static String getPublicKeyAlgFromCertificate(X509Certificate containerCert) {
    	Certificate bcCert = getBCCertificateFromJCECertificate(containerCert);
		SubjectPublicKeyInfo spki = bcCert.getSubjectPublicKeyInfo();
		String pubKeyAlg = spki.getAlgorithm().getAlgorithm().toString();
		return pubKeyAlg;
    }
    
    @SuppressWarnings("unused")
	private static String getJCENameForOid(String oid) {
    	// XXX *** TODO: make this better and more complete
    	if(oid.equals("1.2.840.10045.2.1")) {
    		return "EC";
    	}
    	if(oid.contentEquals("1.2.840.113549.1.1.11")) {
    		return "SHA256withRSA";
    	}
    	return null;
    }

    private static String getSignatureAlgFromCertificate(X509Certificate containerCert) {
    	Certificate bcCert = getBCCertificateFromJCECertificate(containerCert);
		String sigAlg = bcCert.getSignatureAlgorithm().getAlgorithm().toString();
		return sigAlg;
    }
    
    private static X509Certificate getCertificateForContainer(String oid) {
    	CardSettingsSingleton css = CardSettingsSingleton.getInstance();
    	AbstractPIVApplication piv = css.getPivHandle();
    	if(piv == null) {
    		s_logger.error("Invalid PIV handle.");
    		return null;
    	}
	
		PIVDataObject obj = PIVDataObjectFactory.createDataObjectForOid(oid);
		if(obj == null) {
			s_logger.error("Unable to instantiate PIV data object for {}", oid);
			return null;
		}

		MiddlewareStatus result = piv.pivGetData(css.getCardHandle(), oid, obj);
		if(result != MiddlewareStatus.PIV_OK) {
			s_logger.error("pivGetData() returned {} for container {}", result, oid);
			return null;
		}
		X509CertificateDataObject certObj = null;
		try {
			certObj = (X509CertificateDataObject) obj;
		} catch(ClassCastException e) {
			s_logger.error("Unable to cast object for OID {} to an X509CertificateDataObject", oid, e);
			return null;
		}
		if(!certObj.decode()) {
			s_logger.error("Unable to decode object from card");
			return null;
		}
		return certObj.getCertificate();
    }
    
    // based on steps in section 9.2 of RFC 3447
    public static byte[] rsaPadDigestInfo(byte[] digest, int modlen) {
    	byte[] PS = new byte[modlen - digest.length - 3];
    	Arrays.fill(PS, (byte)0xff);
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	baos.write(0x00);
    	baos.write(0x01);
    	try {
			baos.write(PS);
			baos.write(0x00);
			baos.write(digest);
		} catch (IOException e) {
			s_logger.error("Unexpected error generating padded buffer", e);
			return null;
		}
    	return baos.toByteArray();
    	
    }
    
	public static void main(String[] args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	URL location = CardAuthTest.class.getProtectionDomain().getCodeSource().getLocation();
		s_logger.info("current binary directory: {}", location.getFile());
        CommandLineParser p = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = p.parse(s_options, args);
        } catch (ParseException e) {
            s_logger.error("Failed to parse command line arguments", e);
            PrintHelpAndExit(1);
        }
        if(cmd.hasOption("help")) {
            PrintHelpAndExit(0);
        }
        if(cmd.hasOption("listOids")) {
        	for(HashMap.Entry<String, Integer> entry: APDUConstants.oidToContainerIdMap.entrySet()) {
        		Map<String, String> names = APDUConstants.oidNameMap;
        		String oid = entry.getKey();
        		System.out.println(oid + ": " + names.get(oid) + "(Container ID 0x" + Integer.toHexString(entry.getValue()) + ")");
        	}
        	System.exit(0);
        }
        if(!cmd.hasOption("defaultGetResponse")) {
        	s_logger.info("Using cardlib GET RESPONSE instead of java default");
			System.setProperty("sun.security.smartcardio.t0GetResponse", "false");
			System.setProperty("sun.security.smartcardio.t1GetResponse", "false");
        } else {
        	s_logger.info("Using java's default GET RESPONSE handling");
        }
        PCSCUtils.ConfigureUserProperties();
        if(cmd.hasOption("listReaders")) {
        	List<CardTerminal> readers = new ArrayList<CardTerminal>();
        	List<String> readerNames = PCSCUtils.GetConnectedReaders();
        	if(readerNames.size() == 0) {
        		s_logger.error("No readers were connected");
        		System.exit(1);
        	}
        	for(String readerName : readerNames) {
        		readers.add(PCSCUtils.TerminalForReaderName(readerName));
        	}
        	int readerNum = 0;
        	for(CardTerminal reader : readers) {
        		readerNum++;
        		boolean cardInserted = false;
				try {
					cardInserted = reader.isCardPresent();
				} catch (CardException e) {
					s_logger.error("Caught exception querying {}", reader.getName(), e);
				}
        		System.out.println("[" + readerNum + "]: " + reader.getName() + " (" + (cardInserted ? "card present":"card not present") + ")" );
        	}
        	System.out.println(readerNum + " readers connected.");
        }
        String appPin = null;
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        if(cmd.hasOption("reader")) {
        	String readerName = cmd.getOptionValue("reader");
        	CardTerminal reader = PCSCUtils.TerminalForReaderName(readerName);
        	css.setTerminal(reader);
        } else {
        	String readerName = PCSCUtils.GetFirstReaderWithCardPresent();
        	if(readerName == null) {
        		s_logger.error("No connected reader contains a smart card. Insert a card and retry.");
        		System.exit(1);
        	}
        	s_logger.info("Using card in {}", readerName);
        	CardTerminal reader = PCSCUtils.TerminalForReaderName(readerName);
        	css.setTerminal(reader);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			s_logger.error("Failed to set up PIV applet connection.", e);
			System.exit(1);
		}
        if(cmd.hasOption("login")) {
        	if(cmd.hasOption("appPin")) {
        		appPin = cmd.getOptionValue("appPin");
        		css.setApplicationPin(appPin);
        	} else {
        		Console cons = System.console();
        		char[] passwd;
        		if (cons != null && (passwd = cons.readPassword("[Enter %s]", "PIV Application Pin")) != null) {
        			appPin = new String(passwd);
        			css.setApplicationPin(appPin);
        		}
        	}
        	try {
        		int retries = CardInfoController.getAppPinRetries();
        		if(retries < 2) {
        			s_logger.error("Fewer than two PIN retries remain. Cowardly refusing to test card.");
        			System.exit(1);
        		}
				CardUtils.authenticateInSingleton(false);
			} catch (ConformanceTestException e) {
				s_logger.error("Failed to authenticate to card.", e);
				System.exit(1);
			}
        }
        for(String containerOid : cmd.getArgList()) {
        	if(!APDUConstants.oidToContainerIdMap.containsKey(containerOid)) {
        		s_logger.error("{} is not a valid container OID for this test", containerOid);
        		continue;
        	}
        	X509Certificate containerCert = getCertificateForContainer(containerOid);
        	int containerId = APDUConstants.oidToContainerIdMap.get(containerOid);
        	String jceKeyAlg = containerCert.getPublicKey().getAlgorithm();
        	if(containerCert.getPublicKey() instanceof RSAPublicKey) {
        		try {
					CardUtils.authenticateInSingleton(false);
				} catch (ConformanceTestException e1) {
					s_logger.error("Unable to authenticate",e1);
					continue;
				}
        		RSAPublicKey pubKey = (RSAPublicKey) containerCert.getPublicKey();
				int modulusBitLen = pubKey.getModulus().bitLength();
				int modulusLen = 0;
				if(2047 <= modulusBitLen && modulusBitLen <= 2048) {
					modulusLen = 256;
				} else if(1023 <= modulusBitLen && modulusBitLen <= 1024) {
					modulusLen = 128;
				} else {
					// XXX *** check about others
					s_logger.error("Unsupported modulus size");
				}
				if(cmd.hasOption("printAlgs")) {
					s_logger.debug("Certificate from container {} has a public key with algorithm {}",
							containerOid, getPublicKeyAlgFromCertificate(containerCert));
					s_logger.debug("JCE key algorithm: {}", jceKeyAlg);
					s_logger.debug("Certificate from container {} was signed with algorithm {}",
							containerOid, getSignatureAlgFromCertificate(containerCert));
				}
				byte[] challenge = GeneralAuthenticateHelper.generateChallenge(modulusLen);
				//byte[] challenge = new byte[256];
				//Arrays.fill(challenge, (byte)0xF3);
				if(challenge == null) {
					s_logger.error("challenge could not be generated");
					continue;
				}
				// XXX *** for now, the digest we'll use in the challenge block is always sha256 for RSA. We likely need to change that.
				String digestOid = NISTObjectIdentifiers.id_sha256.toString();
				byte[] paddedChallenge = GeneralAuthenticateHelper.preparePKCS1Challenge(challenge, digestOid, modulusLen);
				s_logger.debug("padded challenge: {}", Hex.encodeHexString(paddedChallenge));
				byte[] template = GeneralAuthenticateHelper.generateRequest(jceKeyAlg, containerOid, paddedChallenge);
				ResponseAPDU resp = null;
				try {
					resp = GeneralAuthenticateHelper.sendRequest(css.getCardHandle(), 0x07, containerId, template);
				} catch (CardClientException e) {
					s_logger.error("Error during GeneralAuthenticateHelper.sendRequest()", e);
				}
				s_logger.debug("response was {}", Hex.encodeHexString(resp.getData()));
				byte[] cr = GeneralAuthenticateHelper.getChallengeResponseFromData(resp.getData());
				if(cr == null) {
					s_logger.error("Invalid challenge response buffer.");
					continue;
				}
				s_logger.info("parsed challenge response: {}", Hex.encodeHexString(cr));
				// XXX *** for now, the digest we'll use in the challenge block is always sha256 for RSA. We likely need to change that.
				boolean verified = GeneralAuthenticateHelper.verifyResponseSignature("sha256WithRSA", pubKey, cr, challenge);
				s_logger.info("verify returns: {}", verified);
        	}
        }

	}

}
