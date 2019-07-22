package gov.gsa.pivconformance.tlv;

import java.util.HashMap;

import gov.gsa.pivconformance.tlv.ContainerLengthRule;
import gov.gsa.pivconformance.tlv.TagConstants;
import gov.gsa.pivconformance.tlv.ContainerLengthRule.RULE;

public class ContainerLengthFactory {
	
	private static final HashMap<byte[], ContainerLengthRule> m_maxLenMap = null;

	private static void initCache() {
		m_maxLenMap.put(TagConstants.ACCESS_CONTROL_RULE_TABLE_TAG, new ContainerLengthRule(RULE.OR, 0, 17));
		m_maxLenMap.put(TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 20));
		m_maxLenMap.put(TagConstants.APPLICATIONS_CARDURL_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 128));
		m_maxLenMap.put(TagConstants.BIT_FOR_FIRST_FINGER_TAG, new ContainerLengthRule(RULE.FIXED, 28, 28));
		m_maxLenMap.put(TagConstants.BIT_FOR_SECOND_FINGER_TAG, new ContainerLengthRule(RULE.FIXED, 28, 28));
		m_maxLenMap.put(TagConstants.BUFFER_LENGTH_TAG, new ContainerLengthRule(RULE.FIXED, 2, 2));
		m_maxLenMap.put(TagConstants.CAPABILITY_CONTAINER_VERSION_NUMBER_TAG, new ContainerLengthRule(RULE.OR, 0, 1));
		m_maxLenMap.put(TagConstants.CAPABILITY_GRAMMAR_VERSION_NUMBER_TAG, new ContainerLengthRule(RULE.OR, 0, 1));
		m_maxLenMap.put(TagConstants.CAPABILITY_TUPLES_TAG, new ContainerLengthRule(RULE.FIXED, 0, 0));
		m_maxLenMap.put(TagConstants.CARD_APDUS_TAG, new ContainerLengthRule(RULE.FIXED, 0, 0));
		m_maxLenMap.put(TagConstants.CARD_IDENTIFIER_TAG, new ContainerLengthRule(RULE.OR, 0, 21));
		m_maxLenMap.put(TagConstants.CARDHOLDER_UUID_TAG, new ContainerLengthRule(RULE.FIXED, 16, 16));
		m_maxLenMap.put(TagConstants.CERTIFICATE_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 2100));
		m_maxLenMap.put(TagConstants.CERTINFO_TAG, new ContainerLengthRule(RULE.FIXED, 1, 1));
		m_maxLenMap.put(TagConstants.CHUID_EXPIRATION_DATE_TAG, new ContainerLengthRule(RULE.FIXED, 8, 8));
		m_maxLenMap.put(TagConstants.COEXISTENT_TAG_ALLOCATION_AUTHORITY, new ContainerLengthRule(RULE.FIXED, 1, 1));
		m_maxLenMap.put(TagConstants.DUNS_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 9));
		m_maxLenMap.put(TagConstants.EMPLOYEE_AFFILIATION_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 20));
		m_maxLenMap.put(TagConstants.ERROR_DETECTION_CODE_TAG, new ContainerLengthRule(RULE.OR, 0, 0));
		m_maxLenMap.put(TagConstants.EXTENDED_APPLICATION_CARDURL_TAG, new ContainerLengthRule(RULE.FIXED, 48, 48));
		m_maxLenMap.put(TagConstants.FASC_N_TAG, new ContainerLengthRule(RULE.FIXED, 25, 25));
		m_maxLenMap.put(TagConstants.FINGERPRINT_I_AND_II_TAG, new ContainerLengthRule(RULE.VARIABLE, 88, 4000));
		m_maxLenMap.put(TagConstants.GUID_TAG, new ContainerLengthRule(RULE.FIXED, 16, 16));
		m_maxLenMap.put(TagConstants.IMAGE_FOR_VISUAL_VERIFICATION_TAG,
				new ContainerLengthRule(RULE.VARIABLE, 0, 12704));
		m_maxLenMap.put(TagConstants.IMAGES_FOR_IRIS_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 7100));
		m_maxLenMap.put(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 3200));
		m_maxLenMap.put(TagConstants.ISSUER_IDENTIFICATION_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 15));
		m_maxLenMap.put(TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 30));
		m_maxLenMap.put(TagConstants.MSCUID_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 38));
		m_maxLenMap.put(TagConstants.NAME_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 125));
		m_maxLenMap.put(TagConstants.NEXT_CCC_TAG, new ContainerLengthRule(RULE.FIXED, 0, 0));
		m_maxLenMap.put(TagConstants.NUMBER_OF_FINGERS_TAG, new ContainerLengthRule(RULE.FIXED, 1, 1));
		m_maxLenMap.put(TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 20));
		m_maxLenMap.put(TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 20));
		m_maxLenMap.put(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 4));
		m_maxLenMap.put(TagConstants.PAIRING_CODE_TAG, new ContainerLengthRule(RULE.FIXED, 8, 8));
		m_maxLenMap.put(TagConstants.PIN_USAGE_POLICY_TAG, new ContainerLengthRule(RULE.FIXED, 2, 2));
		m_maxLenMap.put(TagConstants.PIV_CARD_APPLICATION_AID_TAG, new ContainerLengthRule(RULE.VARIABLE, 10, 12));
		m_maxLenMap.put(TagConstants.PKCS15_TAG, new ContainerLengthRule(RULE.OR, 0, 1));
		m_maxLenMap.put(TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG,
				new ContainerLengthRule(RULE.FIXED, 9, 9));
		m_maxLenMap.put(TagConstants.REDIRECTION_TAG_TAG, new ContainerLengthRule(RULE.FIXED, 0, 0));
		m_maxLenMap.put(TagConstants.REGISTERED_DATA_MODEL_NUMBER_TAG, new ContainerLengthRule(RULE.FIXED, 1, 1));
		m_maxLenMap.put(TagConstants.SECURITY_OBJECT_BUFFER_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 48));
		m_maxLenMap.put(TagConstants.SECURITY_OBJECT_TAG, new ContainerLengthRule(RULE.VARIABLE, 0, 1298));
		m_maxLenMap.put(TagConstants.STATUS_TUPLES_TAG, new ContainerLengthRule(RULE.FIXED, 0, 0));
	}
	
	/* 
	 * Public constructor
	 */

	public ContainerLengthFactory() {
		initCache();
	}
	
	/*
	 * 
	 */
	public static HashMap<byte[], ContainerLengthRule> getRuleset() {
		return m_maxLenMap;
	}

	/*
	 * 
	 */
	public static RULE getRule(byte[] tag) {
		return m_maxLenMap.get(tag).getRule();
	}
	
	/**
	* Determines whether the total of all lengths of values on the container under
	* test falls within the length boundaries for that container
	* 
	* @param tag    the element's tag
	* @param length computed by adding value lengths from the value length under
	*               test
	* @return the difference between the prescribed lengths and the value length,
	*         hopefully all bits clear
	*/
	public static int lengthDifference(byte[] tag, int lenFromCut) {
	int rv = -1;
	ContainerLengthRule clr = m_maxLenMap.get(tag);
	int hi = clr.getHighVal();
	int lo = clr.getLowVal();
	RULE rule = clr.getRule();
	switch (rule) {
	case VARIABLE:
		// When there's a range, negative indicates below floor,
		// positive indicates above ceiling, zero indicates in range.
		if (lenFromCut >= lo && lenFromCut <= hi) {
			rv = 0;
		} else if (lenFromCut < lo) {
			rv = lo - lenFromCut;
		} else
			rv = lenFromCut - hi;
		break;
	case OR:
		// Here, we want the return value to indicate what didn't match
		if (lenFromCut == lo || lenFromCut == hi) {
			rv = 0;
		} else {
			rv = ((lenFromCut != lo) ? 1 : 0) << 1;
			rv |= (lenFromCut != hi) ? 1 : 0;
		}
		break;
	case FIXED:
	default:
		if (lenFromCut == lo && lenFromCut == hi) { // Check for typos in maxLenMap i suppose
			rv = 0;
		}
	}
	return rv;
	}
}
