/**
 * 
 */
package gov.gsa.pivconformance.tlv;

import java.util.HashMap;
import gov.gsa.pivconformance.tlv.TagConstants;

/**
 * Private class to encapsulate the rather fuzzy max lengths per Tables 8-43 in SP 800-73-4
 * TODO: Add logic to account for embedded content signing certs in biometrics
 */
public class ContainerLengthRule {

	public static final int OR_MASK = 0x40000000; // Unmask from return of lengthDifference() to know what to do next
	
	/**
	 * Eunumeration used to compute lengths of TLV values
	 *
	 */
	private enum RULE {
		FIXED, OR, VARIABLE
	};

	@SuppressWarnings("unused")
	private static byte[] m_tag;
	private RULE m_rule;
	private int m_lowVal;
	private int m_highVal;
	
	// Constructor
	private ContainerLengthRule(byte[] tag, RULE rule, int lowVal, int highVal) {
		m_tag = tag;
		m_rule = rule;
		m_lowVal = lowVal;
		m_highVal = highVal;
	}

	// TODO: This is just one huge kludge for CCT. We should be putting is into a
	// separate database table
	private static final HashMap<byte[], ContainerLengthRule> maxLenMap = new HashMap<byte[], ContainerLengthRule>() {
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;

		{
			put(TagConstants.ACCESS_CONTROL_RULE_TABLE_TAG,
					new ContainerLengthRule(TagConstants.ACCESS_CONTROL_RULE_TABLE_TAG, RULE.OR, 0, 17));
			put(TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG,
					new ContainerLengthRule(TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG, RULE.FIXED, 20, 20));
			put(TagConstants.APPLICATIONS_CARDURL_TAG,
					new ContainerLengthRule(TagConstants.APPLICATIONS_CARDURL_TAG, RULE.VARIABLE, 0, 128));
			put(TagConstants.BIT_FOR_FIRST_FINGER_TAG,
					new ContainerLengthRule(TagConstants.BIT_FOR_FIRST_FINGER_TAG, RULE.FIXED, 28, 28));
			put(TagConstants.BIT_FOR_SECOND_FINGER_TAG,
					new ContainerLengthRule(TagConstants.BIT_FOR_SECOND_FINGER_TAG, RULE.FIXED, 28, 28));
			put(TagConstants.BUFFER_LENGTH_TAG,
					new ContainerLengthRule(TagConstants.BUFFER_LENGTH_TAG, RULE.FIXED, 2, 2));
			put(TagConstants.CAPABILITY_CONTAINER_VERSION_NUMBER_TAG,
					new ContainerLengthRule(TagConstants.CAPABILITY_CONTAINER_VERSION_NUMBER_TAG, RULE.OR, 0, 1));
			put(TagConstants.CAPABILITY_GRAMMAR_VERSION_NUMBER_TAG,
					new ContainerLengthRule(TagConstants.CAPABILITY_GRAMMAR_VERSION_NUMBER_TAG, RULE.OR, 0, 1));
			put(TagConstants.CAPABILITY_TUPLES_TAG,
					new ContainerLengthRule(TagConstants.CAPABILITY_TUPLES_TAG, RULE.FIXED, 0, 0));
			put(TagConstants.CARD_APDUS_TAG, new ContainerLengthRule(TagConstants.CARD_APDUS_TAG, RULE.FIXED, 0, 0));
			put(TagConstants.CARD_IDENTIFIER_TAG,
					new ContainerLengthRule(TagConstants.CARD_IDENTIFIER_TAG, RULE.OR, 0, 21));
			put(TagConstants.CARDHOLDER_UUID_TAG,
					new ContainerLengthRule(TagConstants.CARDHOLDER_UUID_TAG, RULE.FIXED, 16, 16));
			put(TagConstants.CERTIFICATE_TAG,
					new ContainerLengthRule(TagConstants.CERTIFICATE_TAG, RULE.FIXED, 2100, 2100));
			put(TagConstants.CERTINFO_TAG, new ContainerLengthRule(TagConstants.CERTINFO_TAG, RULE.FIXED, 1, 1));
			put(TagConstants.CHUID_EXPIRATION_DATE_TAG,
					new ContainerLengthRule(TagConstants.CHUID_EXPIRATION_DATE_TAG, RULE.FIXED, 8, 8));
			put(TagConstants.COEXISTENT_TAG_ALLOCATION_AUTHORITY,
					new ContainerLengthRule(TagConstants.COEXISTENT_TAG_ALLOCATION_AUTHORITY, RULE.FIXED, 1, 1));
			put(TagConstants.DUNS_TAG, new ContainerLengthRule(TagConstants.DUNS_TAG, RULE.FIXED, 9, 9));
			put(TagConstants.EMPLOYEE_AFFILIATION_TAG,
					new ContainerLengthRule(TagConstants.EMPLOYEE_AFFILIATION_TAG, RULE.FIXED, 20, 20));
			put(TagConstants.ERROR_DETECTION_CODE_TAG,
					new ContainerLengthRule(TagConstants.ERROR_DETECTION_CODE_TAG, RULE.OR, 0, 0));
			put(TagConstants.EXTENDED_APPLICATION_CARDURL_TAG,
					new ContainerLengthRule(TagConstants.EXTENDED_APPLICATION_CARDURL_TAG, RULE.FIXED, 48, 48));
			put(TagConstants.FASC_N_TAG, new ContainerLengthRule(TagConstants.FASC_N_TAG, RULE.FIXED, 25, 25));
			put(TagConstants.FINGERPRINT_I_AND_II_TAG,
					new ContainerLengthRule(TagConstants.FINGERPRINT_I_AND_II_TAG, RULE.FIXED, 4000, 4000));
			put(TagConstants.GUID_TAG, new ContainerLengthRule(TagConstants.GUID_TAG, RULE.FIXED, 16, 16));
			put(TagConstants.IMAGE_FOR_VISUAL_VERIFICATION_TAG,
					new ContainerLengthRule(TagConstants.IMAGE_FOR_VISUAL_VERIFICATION_TAG, RULE.FIXED, 12704, 12704));
			put(TagConstants.IMAGES_FOR_IRIS_TAG,
					new ContainerLengthRule(TagConstants.IMAGES_FOR_IRIS_TAG, RULE.FIXED, 7100, 7100));
			put(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG,
					new ContainerLengthRule(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG, RULE.FIXED, 3200, 3200));
			put(TagConstants.ISSUER_IDENTIFICATION_TAG,
					new ContainerLengthRule(TagConstants.ISSUER_IDENTIFICATION_TAG, RULE.FIXED, 15, 15));
			put(TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG,
					new ContainerLengthRule(TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG, RULE.FIXED, 30, 30));
			put(TagConstants.MSCUID_TAG, new ContainerLengthRule(TagConstants.MSCUID_TAG, RULE.FIXED, 38, 38));
			put(TagConstants.NAME_TAG, new ContainerLengthRule(TagConstants.NAME_TAG, RULE.FIXED, 125, 125));
			put(TagConstants.NEXT_CCC_TAG, new ContainerLengthRule(TagConstants.NEXT_CCC_TAG, RULE.FIXED, 0, 0));
			put(TagConstants.NUMBER_OF_FINGERS_TAG,
					new ContainerLengthRule(TagConstants.NUMBER_OF_FINGERS_TAG, RULE.FIXED, 1, 1));
			put(TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG,
					new ContainerLengthRule(TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG, RULE.FIXED, 20, 20));
			put(TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG,
					new ContainerLengthRule(TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG, RULE.FIXED, 20, 20));
			put(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG,
					new ContainerLengthRule(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG, RULE.FIXED, 4, 4));
			put(TagConstants.PAIRING_CODE_TAG,
					new ContainerLengthRule(TagConstants.PAIRING_CODE_TAG, RULE.FIXED, 8, 8));
			put(TagConstants.PAIRING_CODE_TAG,
					new ContainerLengthRule(TagConstants.PAIRING_CODE_TAG, RULE.FIXED, 8, 8));
			put(TagConstants.PIN_USAGE_POLICY_TAG,
					new ContainerLengthRule(TagConstants.PIN_USAGE_POLICY_TAG, RULE.FIXED, 2, 2));
			put(TagConstants.PIV_CARD_APPLICATION_AID_TAG,
					new ContainerLengthRule(TagConstants.PIV_CARD_APPLICATION_AID_TAG, RULE.FIXED, 12, 12));
			put(TagConstants.PKCS15_TAG, new ContainerLengthRule(TagConstants.PKCS15_TAG, RULE.OR, 0, 1));
			put(TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG,
					new ContainerLengthRule(TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG, RULE.FIXED, 9, 9));
			put(TagConstants.REDIRECTION_TAG_TAG,
					new ContainerLengthRule(TagConstants.REDIRECTION_TAG_TAG, RULE.FIXED, 0, 0));
			put(TagConstants.REGISTERED_DATA_MODEL_NUMBER_TAG,
					new ContainerLengthRule(TagConstants.REGISTERED_DATA_MODEL_NUMBER_TAG, RULE.FIXED, 1, 1));
			put(TagConstants.SECURITY_OBJECT_BUFFER_TAG,
					new ContainerLengthRule(TagConstants.SECURITY_OBJECT_BUFFER_TAG, RULE.FIXED, 48, 48));
			put(TagConstants.SECURITY_OBJECT_TAG,
					new ContainerLengthRule(TagConstants.SECURITY_OBJECT_TAG, RULE.FIXED, 1298, 1298));
			put(TagConstants.STATUS_TUPLES_TAG,
					new ContainerLengthRule(TagConstants.STATUS_TUPLES_TAG, RULE.FIXED, 0, 0));
		}
	};

	/**
	 * Determines whether the total of all lengths of values on the container under
	 * test falls within the length boundaries for that container
	 * 
	 * @param tag    the element's tag
	 * @param length computed by adding value lengths from the value length under test
	 * @return the difference between the prescribed lengths and the value length
	 */
	public static int lengthDifference(byte[] tag, int lenFromCut) {
		int rv = 0xFFFFFFFF & ~OR_MASK;
		ContainerLengthRule msr = maxLenMap.get(tag);
		switch (msr.m_rule) {
		case VARIABLE:
			// When there's a range, negative indicates below floor,
			// positive indicates above ceiling, zero indicates in range.
			if (lenFromCut >= msr.m_lowVal && lenFromCut <= msr.m_highVal) {
				rv = 0;
			} else if (lenFromCut < msr.m_lowVal) {
				rv = msr.m_lowVal - lenFromCut;
			} else
				rv = lenFromCut - msr.m_highVal;			
			break;
		case OR:
			if (lenFromCut == msr.m_lowVal || lenFromCut == msr.m_highVal) {
				rv = 0;
			} else {
				rv += (lenFromCut != msr.m_lowVal) ? 1 : 0;
				rv += (lenFromCut != msr.m_highVal) ? 1: 0;
			}
			rv |= OR_MASK;
			break;
		case FIXED:
		default:
			if (lenFromCut < msr.m_lowVal && lenFromCut == msr.m_highVal) { // Check for typos in maxLenMap i suppose
				rv = 0;
			}
		}
		return rv;
	}
}
