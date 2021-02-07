package gov.gsa.pivconformance.conformancelib.utilities;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.CardClientException;
import gov.gsa.pivconformance.cardlib.card.client.GeneralAuthenticateHelper;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.conformancelib.tests.ConformanceTestException;
import java.security.spec.ECPoint;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.ResponseAPDU;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class KeyValidationHelper {
	static Logger s_logger = LoggerFactory.getLogger(KeyValidationHelper.class);
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private final HashMap<String, ECNamedCurveParameterSpec> validCurves = new HashMap<>();

	public void validateKey(X509Certificate containerCert, String containerOid) throws ConformanceTestException {
		ResponseAPDU resp = null;
		byte[] template = null;
		byte[] challengeResponse = null;

		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		CardUtils.reauthenticateInSingleton();
		if (!APDUConstants.oidToContainerIdMap.containsKey(containerOid)) {
			s_logger.error("{} is not a valid container OID for this test", containerOid);
			throw new ConformanceTestException("validateKey was passed container OID " + containerOid
					+ " for which there is no corresponding key container ID");
		}
		int containerId = APDUConstants.oidToContainerIdMap.get(containerOid);
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
			template = GeneralAuthenticateHelper.generateRequest(containerOid, paddedChallenge);
			try {
				resp = GeneralAuthenticateHelper.sendRequest(css.getCardHandle(), 0x07, containerId, template);
			} catch (CardClientException e) {
				s_logger.error("Error during GeneralAuthenticateHelper.sendRequest()", e);
				throw new ConformanceTestException("Sending APDU to card failed", e);
			}
			s_logger.debug("response was {}", Hex.encodeHexString(resp.getData()));
			challengeResponse = GeneralAuthenticateHelper.getChallengeResponseFromData(resp.getData());
			if (challengeResponse == null) {
				s_logger.error("Invalid challenge response buffer.");
				throw new ConformanceTestException("APDU with status word of " + Integer.toHexString(resp.getSW1()) + Integer.toHexString(resp.getSW2()) + " contained no response to challenge");
			}
			s_logger.info("parsed challenge response: {}", Hex.encodeHexString(challengeResponse));
			// XXX *** for now, the digest we'll use in the challenge block is always sha256
			// for RSA. We likely need to change that.
			boolean verified = GeneralAuthenticateHelper.verifyResponseSignature(containerCert.getSigAlgName(), pubKey, challengeResponse, challenge);
			s_logger.info("verify returns: {}", verified);
			assertTrue(verified, "Unable to verify RSA signature over challenge");
		} else if (containerCert.getPublicKey() instanceof ECPublicKey) {
			boolean verified = false;
			ECPublicKey pubKey = (ECPublicKey)containerCert.getPublicKey();
			ECPoint point = pubKey.getW();
			assertFalse(point.equals(ECPoint.POINT_INFINITY), "Invalid Public key. EC Point is point at infinity");

			ECParameterSpec paramSpec = EC5Util.convertSpec(pubKey.getParams());
			try {
				paramSpec.getCurve().validatePoint(point.getAffineX(), point.getAffineY());
			}catch (IllegalArgumentException e){
				fail("Invalid public key");
			}

			Optional<Map.Entry<String, ECNamedCurveParameterSpec>> result = validCurves
					.entrySet()
					.stream()
					.filter( spec ->
							paramSpec.getN().equals(spec.getValue().getN()) &&
									paramSpec.getH().equals(spec.getValue().getH()) &&
									paramSpec.getCurve().equals(spec.getValue().getCurve()) &&
									paramSpec.getG().equals(spec.getValue().getG())
					)
					.findFirst();
			assertTrue(result.isPresent(), "Public key point is not on a supported curve");

			int digestLen = 0;
			byte cryptoMechanism = 0;
			switch (result.get().getKey()) {
				case "P-256":
					digestLen = 32;
					cryptoMechanism = 0x11;
					break;
				case "P-384":
					digestLen = 48;
					cryptoMechanism = 0x14;
					break;
				default:
					fail("Unsupported curve");
			}

			byte[] digest = GeneralAuthenticateHelper.generateChallenge(digestLen);
			if (digest == null) {
				s_logger.error("digest could not be generated");
				throw new ConformanceTestException("No digest could be generated for key validation");
			}

      template = GeneralAuthenticateHelper.generateRequest(containerOid, digest);

			try {
				resp = GeneralAuthenticateHelper.sendRequest(css.getCardHandle(), cryptoMechanism, containerId, template);
			} catch (CardClientException e) {
				s_logger.error("Error during GeneralAuthenticateHelper.sendRequest()", e);
				throw new ConformanceTestException("Sending APDU to card failed", e);
			}
			s_logger.debug("response was {}", Hex.encodeHexString(resp.getData()));

			challengeResponse = GeneralAuthenticateHelper.getChallengeResponseFromData(resp.getData());
			assertTrue(resp.getSW() == APDUConstants.SUCCESSFUL_EXEC, "Request failure");
			s_logger.info("Challenge response status: {}", String.format("0x%04X", resp.getSW()));

			if (challengeResponse == null) {
				s_logger.error("Invalid challenge response buffer.");
				throw new ConformanceTestException("APDU with status word of " + Integer.toHexString(resp.getSW1()) + Integer.toHexString(resp.getSW2()) + " contained no response to challenge");
			}
			s_logger.info("parsed challenge response: {}", Hex.encodeHexString(challengeResponse));

			// NoneWithECDSA tells the algorithm provider that we are doing a "raw" ecdsa and are simply providing it with a digest versus
			// the bytes that the digest is the hash of.
			verified = GeneralAuthenticateHelper.verifyResponseSignature("NoneWithECDSA", pubKey, challengeResponse, digest);
			s_logger.info("verify returns: {}", verified);
			assertTrue(verified, "Unable to verify ECDSA signature over challenge");
		}
	}
	
	public static KeyValidationHelper getInstance() {
		return INSTANCE;
	}
	private static final KeyValidationHelper INSTANCE = new KeyValidationHelper();
	private KeyValidationHelper() {

		validCurves.put("P-256", ECNamedCurveTable.getParameterSpec("P-256"));
		validCurves.put("P-384", ECNamedCurveTable.getParameterSpec("P-384"));
	}
}
