package gov.gsa.pivconformance.tlv;

import java.util.HashMap;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.tlv.TagLengthRule;
import gov.gsa.pivconformance.tlv.TagConstants;
import gov.gsa.pivconformance.tlv.TagLengthRule.RULE;

public class TagLengthFactory {
    private static final Logger s_logger = LoggerFactory.getLogger(TagLengthFactory.class);
	private static final HashMap<byte[], TagLengthRule> m_maxLenMap = new HashMap<byte[], TagLengthRule>();

	private void initCache() {
		m_maxLenMap.put(TagConstants.ACCESS_CONTROL_RULE_TABLE_TAG, new TagLengthRule(RULE.OR, 0, 17));
		m_maxLenMap.put(TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG, new TagLengthRule(RULE.VARIABLE, 0, 20));
		m_maxLenMap.put(TagConstants.APPLICATIONS_CARDURL_TAG, new TagLengthRule(RULE.VARIABLE, 0, 128));
		m_maxLenMap.put(TagConstants.BIT_FOR_FIRST_FINGER_TAG, new TagLengthRule(RULE.FIXED, 28, 28));
		m_maxLenMap.put(TagConstants.BIT_FOR_SECOND_FINGER_TAG, new TagLengthRule(RULE.FIXED, 28, 28));
		m_maxLenMap.put(TagConstants.BUFFER_LENGTH_TAG, new TagLengthRule(RULE.FIXED, 2, 2));
		m_maxLenMap.put(TagConstants.CAPABILITY_CONTAINER_VERSION_NUMBER_TAG, new TagLengthRule(RULE.OR, 0, 1));
		m_maxLenMap.put(TagConstants.CAPABILITY_GRAMMAR_VERSION_NUMBER_TAG, new TagLengthRule(RULE.OR, 0, 1));
		m_maxLenMap.put(TagConstants.CAPABILITY_TUPLES_TAG, new TagLengthRule(RULE.FIXED, 0, 0));
		m_maxLenMap.put(TagConstants.CARD_APDUS_TAG, new TagLengthRule(RULE.FIXED, 0, 0));
		m_maxLenMap.put(TagConstants.CARD_IDENTIFIER_TAG, new TagLengthRule(RULE.OR, 0, 21));
		m_maxLenMap.put(TagConstants.CARDHOLDER_UUID_TAG, new TagLengthRule(RULE.FIXED, 16, 16));
		m_maxLenMap.put(TagConstants.CERTIFICATE_TAG, new TagLengthRule(RULE.VARIABLE, 0, 2100));
		m_maxLenMap.put(TagConstants.CERTINFO_TAG, new TagLengthRule(RULE.FIXED, 1, 1));
		m_maxLenMap.put(TagConstants.CHUID_EXPIRATION_DATE_TAG, new TagLengthRule(RULE.FIXED, 8, 8));
		m_maxLenMap.put(TagConstants.COEXISTENT_TAG_ALLOCATION_AUTHORITY, new TagLengthRule(RULE.FIXED, 1, 1));
		m_maxLenMap.put(TagConstants.DUNS_TAG, new TagLengthRule(RULE.VARIABLE, 0, 9));
		m_maxLenMap.put(TagConstants.EMPLOYEE_AFFILIATION_TAG, new TagLengthRule(RULE.VARIABLE, 0, 20));
		m_maxLenMap.put(TagConstants.ERROR_DETECTION_CODE_TAG, new TagLengthRule(RULE.OR, 0, 0));
		m_maxLenMap.put(TagConstants.EXTENDED_APPLICATION_CARDURL_TAG, new TagLengthRule(RULE.FIXED, 48, 48));
		m_maxLenMap.put(TagConstants.FASC_N_TAG, new TagLengthRule(RULE.FIXED, 25, 25));
		m_maxLenMap.put(TagConstants.FINGERPRINT_I_AND_II_TAG, new TagLengthRule(RULE.VARIABLE, 88, 4000));
		m_maxLenMap.put(TagConstants.GUID_TAG, new TagLengthRule(RULE.FIXED, 16, 16));
		m_maxLenMap.put(TagConstants.IMAGE_FOR_VISUAL_VERIFICATION_TAG,
				new TagLengthRule(RULE.VARIABLE, 0, 12704));
		m_maxLenMap.put(TagConstants.IMAGES_FOR_IRIS_TAG, new TagLengthRule(RULE.VARIABLE, 0, 7100));
		m_maxLenMap.put(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG, new TagLengthRule(RULE.VARIABLE, 0, 3200));
		m_maxLenMap.put(TagConstants.ISSUER_IDENTIFICATION_TAG, new TagLengthRule(RULE.VARIABLE, 0, 15));
		m_maxLenMap.put(TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG, new TagLengthRule(RULE.VARIABLE, 0, 30));
		m_maxLenMap.put(TagConstants.MSCUID_TAG, new TagLengthRule(RULE.VARIABLE, 0, 38));
		m_maxLenMap.put(TagConstants.NAME_TAG, new TagLengthRule(RULE.VARIABLE, 0, 125));
		m_maxLenMap.put(TagConstants.NEXT_CCC_TAG, new TagLengthRule(RULE.FIXED, 0, 0));
		m_maxLenMap.put(TagConstants.NUMBER_OF_FINGERS_TAG, new TagLengthRule(RULE.FIXED, 1, 1));
		m_maxLenMap.put(TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG, new TagLengthRule(RULE.VARIABLE, 0, 20));
		m_maxLenMap.put(TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG, new TagLengthRule(RULE.VARIABLE, 0, 20));
		m_maxLenMap.put(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG, new TagLengthRule(RULE.VARIABLE, 0, 4));
		m_maxLenMap.put(TagConstants.PAIRING_CODE_TAG, new TagLengthRule(RULE.FIXED, 8, 8));
		m_maxLenMap.put(TagConstants.PIN_USAGE_POLICY_TAG, new TagLengthRule(RULE.FIXED, 2, 2));
		m_maxLenMap.put(TagConstants.PIV_CARD_APPLICATION_AID_TAG, new TagLengthRule(RULE.VARIABLE, 10, 12));
		m_maxLenMap.put(TagConstants.PKCS15_TAG, new TagLengthRule(RULE.OR, 0, 1));
		m_maxLenMap.put(TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG,
				new TagLengthRule(RULE.FIXED, 9, 9));
		m_maxLenMap.put(TagConstants.REDIRECTION_TAG_TAG, new TagLengthRule(RULE.FIXED, 0, 0));
		m_maxLenMap.put(TagConstants.REGISTERED_DATA_MODEL_NUMBER_TAG, new TagLengthRule(RULE.FIXED, 1, 1));
		m_maxLenMap.put(TagConstants.SECURITY_OBJECT_BUFFER_TAG, new TagLengthRule(RULE.VARIABLE, 0, 48));
		m_maxLenMap.put(TagConstants.SECURITY_OBJECT_TAG, new TagLengthRule(RULE.VARIABLE, 0, 1298));
		m_maxLenMap.put(TagConstants.STATUS_TUPLES_TAG, new TagLengthRule(RULE.FIXED, 0, 0));
	}

	/*
	 * Public constructor
	 */

	public TagLengthFactory() {
		initCache();
	}

	/*
	 * 
	 */
	public HashMap<byte[], TagLengthRule> getLengthRules() {
		return m_maxLenMap;
	}

	/*
	 * 
	 */
	public RULE getLengthRule(byte[] tag) {
		return m_maxLenMap.get(tag).getRule();
	}

	/**
	 * Determines whether the length of the byte array corresponding
	 * to the tag falls within the length boundaries for that container
	 * 
	 * @param tag    the element's tag
	 * @param byteLength computed by adding value lengths from the value length under
	 *               test
	 * @return the difference between the prescribed lengths and the value length,
	 *         hopefully all bits clear
	 * @throws NullPointerException
	 */
	public int lengthDelta(byte[] tag, int bytesLength) throws NullPointerException {
		int rv = -1;
		TagLengthRule clr = m_maxLenMap.get(tag);
		if (clr == null) {
			String errStr = (String.format("Tag " + Hex.toHexString(tag) + " is null"));
			NullPointerException e = new NullPointerException(errStr);
			throw(e);
		}
		int hi = clr.getHighVal();
		int lo = clr.getLowVal();
		RULE rule = clr.getRule();
		switch (rule) {
		case VARIABLE:
			// When there's a range, negative indicates below floor,
			// positive indicates above ceiling, zero indicates in range.
			if (bytesLength >= lo && bytesLength <= hi) {
				rv = 0;
			} else if (bytesLength < lo) {
				rv = lo - bytesLength;
			} else
				rv = bytesLength - hi;
			break;
		case OR:
			// Here, we want the return value to indicate what didn't match
			if (bytesLength == lo || bytesLength == hi) {
				rv = 0;
			} else {
				rv = ((bytesLength != lo) ? 1 : 0) << 1;
				rv |= (bytesLength != hi) ? 1 : 0;
			}
			break;
		case FIXED:
		default:
			if (bytesLength == lo && bytesLength == hi) { // Check for typos in maxLenMap i suppose
				rv = 0;
			}
		}
		return rv;
	}
}
