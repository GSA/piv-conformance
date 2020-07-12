package gov.gsa.pivconformance.card.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.BerTlv;
import gov.gsa.pivconformance.tlv.BerTlvBuilder;
import gov.gsa.pivconformance.tlv.BerTlvParser;
import gov.gsa.pivconformance.tlv.BerTlvs;
import gov.gsa.pivconformance.tlv.CCTTlvLogger;
import gov.gsa.pivconformance.utils.NullParameters;
import gov.gsa.pivconformance.utils.PCSCWrapper;

// Moving the general authenticate stuff that needs command
// chaining off to here, so it's not sitting in the wrapper
// able to easily break other stuff.
//
// Once we've worked out the kinks, we should split the chaining
// stuff back into the wrapper everything else uses and refactor
// this.

public class GeneralAuthenticateHelper {
	static Logger s_logger = LoggerFactory.getLogger(GeneralAuthenticateHelper.class);

	public static final byte[] DYNAMIC_AUTHENTICATION_TEMPLATE = { (byte) 0x7C };
	public static final byte[] GA_CHALLENGE = { (byte) 0x81 };
	public static final byte[] GA_RESPONSE = { (byte) 0x82 };
	public static final int APDU_MAX = 255;
	public static final int APDU_MAX_DATA = APDU_MAX - 5;

	public static byte[] generateRequest(String jceKeyType, String containerOid, byte[] paddedChallenge) {
		BerTlvBuilder b = new BerTlvBuilder();
		b.addEmpty(new BerTag(GA_RESPONSE));
		b.addBytes(new BerTag(GA_CHALLENGE), paddedChallenge);
		byte[] inner = b.buildArray();
		BerTlvBuilder templateBuilder = new BerTlvBuilder();
		templateBuilder.addBytes(new BerTag(DYNAMIC_AUTHENTICATION_TEMPLATE), inner);
		byte[] template = templateBuilder.buildArray();
		s_logger.debug("Generated challenge for {}: {}", containerOid, Hex.encodeHexString(template));
		return template;
	}

	public static ResponseAPDU sendRequest(CardHandle ch, int pivAlgId, int pivKeyId, byte[] request)
			throws CardClientException {
		CardChannel channel = ch.getCurrentChannel();
		s_logger.debug("sendRequest called for container {} alg {} request length {}", request.length);
		// here's where the chaining lands until it's worn better
		ByteArrayOutputStream ccBaos = new ByteArrayOutputStream();
		int currPos = 0;
		ccBaos.write(request.length <= APDU_MAX_DATA ? APDUConstants.COMMAND : APDUConstants.COMMAND_CC);
		ccBaos.write(APDUConstants.GENERAL_AUTHENTICATE);
		ccBaos.write(pivAlgId);
		ccBaos.write(pivKeyId);
		ccBaos.write(request.length <= APDU_MAX_DATA ? request.length : APDU_MAX_DATA);
		ccBaos.write(request, 0, request.length <= APDU_MAX_DATA ? request.length : APDU_MAX_DATA);
		if (request.length > APDU_MAX_DATA)
			currPos += APDU_MAX_DATA;
		CommandAPDU generalAuthApdu = new CommandAPDU(ccBaos.toByteArray());
		ResponseAPDU resp = null;

		try {
			PCSCWrapper pcsc = PCSCWrapper.getInstance();
			resp = pcsc.transmit(channel, generalAuthApdu);
		} catch (CardException e) {
			s_logger.error("Failed to transmit GENERAL AUTHENTICATE APDU to card", e);
			return null;
		}
		if (currPos < request.length - 1) {
			while (resp.getSW1() == 0x90 && resp.getSW2() == 0x00 && currPos < request.length - 1) {
				ccBaos.reset();
				ccBaos.write(
						request.length - currPos <= APDU_MAX_DATA ? APDUConstants.COMMAND : APDUConstants.COMMAND_CC);
				ccBaos.write(APDUConstants.GENERAL_AUTHENTICATE);
				ccBaos.write(pivAlgId);
				ccBaos.write(pivKeyId);
				ccBaos.write(request.length - currPos <= APDU_MAX_DATA ? request.length - currPos : APDU_MAX_DATA);
				ccBaos.write(request, currPos,
						request.length - currPos <= APDU_MAX_DATA ? request.length - currPos : APDU_MAX_DATA);
				if (request.length > APDU_MAX_DATA) {
					currPos += APDU_MAX_DATA;
				} else {
					currPos = request.length;
				}
				if (currPos >= request.length - 1)
					ccBaos.write((byte) 0x00); // Add Le
				try {
					CommandAPDU chainedGeneralAuthApdu = new CommandAPDU(ccBaos.toByteArray());
					PCSCWrapper pcsc = PCSCWrapper.getInstance();
					resp = pcsc.transmit(channel, chainedGeneralAuthApdu);
				} catch (CardException e) {
					s_logger.error("Failed to transmit GENERAL AUTHENTICATE APDU to card", e);
					return null;
				}
			}
		}
		if (resp.getSW1() != 0x90 && resp.getSW2() != 0x00) {
			s_logger.error("Got status code of {}{} for GENERAL AUTHENTICATE", Integer.toHexString(resp.getSW1()),
					Integer.toHexString(resp.getSW2()));
		}
		return resp;
	}

	// this should live in one of the data model classes
	public static byte[] getChallengeResponseFromData(byte[] apduData) {
		if (apduData == null || apduData.length == 0) {
			s_logger.error("null or empty APDU data was passed in.");
			return null;
		}
		BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(GeneralAuthenticateHelper.class));
		BerTlvs outer = tlvp.parse(apduData);
		List<BerTlv> outerValues = outer.getList();
		BerTlvs inner = tlvp.parse(outerValues.get(0).getBytesValue());
		List<BerTlv> values = inner.getList();
		byte[] rv = null;
		BerTag responseTag = new BerTag(GA_RESPONSE);
		for (BerTlv tlv : values) {
			if (tlv.getTag().equals(responseTag)) {
				rv = tlv.getBytesValue();
				break;
			}
		}
		return rv;
	}

	// these should be factored out into alg-specific helpers
	// digest a challenge using the specified digest OID and format it into a PKCS#1
	// v1.5 padded message
	public static byte[] preparePKCS1Challenge(byte[] challenge, String digestOid, int modulusLen) {
		String jceDigestName = MessageDigestUtils.getDigestName(new ASN1ObjectIdentifier(digestOid));
		byte[] challengeDigest = null;
		try {
			challengeDigest = MessageDigest.getInstance(jceDigestName, "BC").digest(challenge);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			s_logger.error("Unable to digest challenge", e);
			return null;
		}
		s_logger.debug("Challenge: {}", Hex.encodeHexString(challenge));
		s_logger.debug("{} ({}) digest of challenge: {}", digestOid, jceDigestName,
				Hex.encodeHexString(challengeDigest));

		AlgorithmIdentifier digestAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestOid),
				new NullParameters());
		DigestInfo formattedDigest = new DigestInfo(digestAlgId, challengeDigest);
		byte[] diBuf = null;
		try {
			diBuf = formattedDigest.getEncoded();
		} catch (IOException e) {
			s_logger.error("Unable to encode DigestInfo structure for PKCS#1 signature block", e);
			return null;
		}
		return padDigestInfo(diBuf, modulusLen);
	}

	// pad an encoded DigestInfo structure
	// based on steps in section 9.2 of RFC 3447
	public static byte[] padDigestInfo(byte[] digest, int modulusLen) {
		byte[] PS = new byte[modulusLen - digest.length - 3];
		Arrays.fill(PS, (byte) 0xff);
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

	public static byte[] generateChallenge(int size) {
		SecureRandom rng;
		try {
			rng = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			s_logger.error("Unable to instantiate RNG", e);
			return null;
		}
		byte[] challenge = new byte[size];
		rng.nextBytes(challenge);
		s_logger.debug("Challenge bytes: {}", Hex.encodeHexString(challenge));
		return challenge;
	}

	public static boolean verifyResponseSignature(String jceSignatureAlgName, PublicKey containerCertKey,
			byte[] signature, byte[] challenge) {
		boolean verified = false;
		try {
			Signature verifier = Signature.getInstance(jceSignatureAlgName);
			verifier.initVerify(containerCertKey);
			verifier.update(challenge);
			verified = verifier.verify(signature);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			s_logger.error("Unable to process signature for verification", e);
		}
		return verified;
	}
}
