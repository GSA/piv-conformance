package gov.gsa.pivconformance.conformancelib.utilities;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.CardClientException;
import gov.gsa.pivconformance.cardlib.card.client.GeneralAuthenticateHelper;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.conformancelib.tests.ConformanceTestException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.ResponseAPDU;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class KeyValidationHelper {
	static Logger s_logger = LoggerFactory.getLogger(KeyValidationHelper.class);
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	public void validateKey(X509Certificate containerCert, String containerOid) throws ConformanceTestException {
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		CardUtils.reauthenticateInSingleton();
		if (!APDUConstants.oidToContainerIdMap.containsKey(containerOid)) {
			s_logger.error("{} is not a valid container OID for this test", containerOid);
			throw new ConformanceTestException("validateKey was passed container OID " + containerOid
					+ " for which there is no corresponding key container ID");
		}
		int containerId = APDUConstants.oidToContainerIdMap.get(containerOid);
		String jceKeyAlg = containerCert.getPublicKey().getAlgorithm();
		if (containerCert.getPublicKey() instanceof RSAPublicKey) {
			RSAPublicKey pubKey = (RSAPublicKey) containerCert.getPublicKey();
			int modulusBitLen = pubKey.getModulus().bitLength();
			int modulusLen = 0;
			if (2047 <= modulusBitLen && modulusBitLen <= 2048) {
				modulusLen = 256;
			} else if (1023 <= modulusBitLen && modulusBitLen <= 1024) {
				modulusLen = 128;
			} else {
				s_logger.error("KeyValidationHelper needs to be updated in order to process a " + modulusBitLen + " RSA modulus.");
				throw new ConformanceTestException("KeyValidationHelper needs to be updated in order to process a " + modulusBitLen + " RSA modulus.");
			}
			byte[] challenge = GeneralAuthenticateHelper.generateChallenge(modulusLen);
			// byte[] challenge = new byte[256];
			// Arrays.fill(challenge, (byte)0xF3);
			if (challenge == null) {
				s_logger.error("challenge could not be generated");
				throw new ConformanceTestException("No challenge could be generated for key validation");
			}
			// XXX *** for now, the digest we'll use in the challenge block is always sha256
			// for RSA. We likely need to change that.
			String digestOid = NISTObjectIdentifiers.id_sha256.toString();
			byte[] paddedChallenge = GeneralAuthenticateHelper.preparePKCS1Challenge(challenge, digestOid, modulusLen);
			if(paddedChallenge == null) {
				s_logger.error("Failed to digest and pad the challenge");
				throw new ConformanceTestException("Failed to digest and pad the challenge");
			}
			s_logger.debug("padded challenge: {}", Hex.encodeHexString(paddedChallenge));
			byte[] template = GeneralAuthenticateHelper.generateRequest(jceKeyAlg, containerOid, paddedChallenge);
			ResponseAPDU resp = null;
			try {
				resp = GeneralAuthenticateHelper.sendRequest(css.getCardHandle(), 0x07, containerId, template);
			} catch (CardClientException e) {
				s_logger.error("Error during GeneralAuthenticateHelper.sendRequest()", e);
				throw new ConformanceTestException("Sending APDU to card failed", e);
			}
			s_logger.debug("response was {}", Hex.encodeHexString(resp.getData()));
			byte[] cr = GeneralAuthenticateHelper.getChallengeResponseFromData(resp.getData());
			if (cr == null) {
				s_logger.error("Invalid challenge response buffer.");
				throw new ConformanceTestException("APDU with status word of " + Integer.toHexString(resp.getSW1()) + Integer.toHexString(resp.getSW2()) + " contained no response to challenge");
			}
			s_logger.info("parsed challenge response: {}", Hex.encodeHexString(cr));
			// XXX *** for now, the digest we'll use in the challenge block is always sha256
			// for RSA. We likely need to change that.
			boolean verified = GeneralAuthenticateHelper.verifyResponseSignature("sha256WithRSA", pubKey, cr, challenge);
			s_logger.info("verify returns: {}", verified);
			assertTrue(verified, "Unable to verify RSA signature over challenge");
		} else if (containerCert.getPublicKey() instanceof ECPublicKey) {
			boolean verified = false;
			//TODO: Get this fixed ASAP
			s_logger.error("ECPublicKey challenge not supported");
			throw new ConformanceTestException("ECPublicKey challenge not supported");
		}
	}
	
	public static KeyValidationHelper getInstance() {
		return INSTANCE;
	}
	private static final KeyValidationHelper INSTANCE = new KeyValidationHelper();
	private KeyValidationHelper() {
	}

}
