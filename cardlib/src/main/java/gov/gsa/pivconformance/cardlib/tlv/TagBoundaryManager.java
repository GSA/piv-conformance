package gov.gsa.pivconformance.cardlib.tlv;

import java.util.ArrayList;
import java.util.HashMap;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.cardlib.tlv.TagLengthRule.CONSTRAINT;
import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.CardClientException;
import gov.gsa.pivconformance.cardlib.card.client.SoftTagBoundaryException;
/**
 * This class is intended to be used side-by-side SP 800-73 for quick comparison/updates to
 * lengths. 
 * 
 * TODO: This class statically marks a tag as eligible per SP 800-73-4 table, but until the tag is obtained, 
 * we only know that it is allowed in-contecxt if the container also contains a separate signing cert.  That gets
 * determined when the container is loaded and we've determined that there is or is not a cert.  Whether the tool looks
 * for that needs to be flushed out.
 *
 */
public class TagBoundaryManager {
	private static final Logger s_logger = LoggerFactory.getLogger(TagBoundaryManager.class);
	private static final HashMap<String, ContainerRuleset> m_maxLenMap = new HashMap<String, ContainerRuleset>();

	private void initCache() {
		/*
		 * This cache gets hung from the gov.gsa.pivconformance.card.client.DataModelSingleton object
		 * with a public accessor getLengthRules() method.
		 */
		// Handle cert containers from Table 10, 15, 16, 17, 20-39, 42 of SP 800-73-4
		ArrayList<String> certNames = new ArrayList<String>();
		certNames.add(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_NAME);
		certNames.add(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_NAME);
		certNames.add(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_NAME);
		certNames.add(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_NAME);
		certNames.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_NAME);
		certNames.add(APDUConstants.SECURE_MESSAGING_CERTIFICATE_SIGNER_NAME);
		
		ArrayList<String> certOids = new ArrayList<String>();
		certOids.add(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID);
		certOids.add(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID);
		certOids.add(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID);
		certOids.add(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID);
		certOids.add(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID);
		certOids.add(APDUConstants.SECURE_MESSAGING_CERTIFICATE_SIGNER_OID);		

		// SP800-73-4 Part 1, Table 8. Card Capability Container tags
		ContainerRuleset crs = new ContainerRuleset(APDUConstants.CARD_CAPABILITY_CONTAINER_OID);
		crs.add(new BerTag(TagConstants.CARD_IDENTIFIER_TAG), new TagLengthRule(CONSTRAINT.OR, 0, 21));
		crs.add(new BerTag(TagConstants.CAPABILITY_CONTAINER_VERSION_NUMBER_TAG), new TagLengthRule(CONSTRAINT.OR, 0, 1));
		crs.add(new BerTag(TagConstants.CAPABILITY_GRAMMAR_VERSION_NUMBER_TAG), new TagLengthRule(CONSTRAINT.OR, 0, 1));
		crs.add(new BerTag(TagConstants.APPLICATIONS_CARDURL_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 128));
		crs.add(new BerTag(TagConstants.PKCS15_TAG), new TagLengthRule(CONSTRAINT.OR, 0, 1));
		crs.add(new BerTag(TagConstants.REGISTERED_DATA_MODEL_NUMBER_TAG), new TagLengthRule(CONSTRAINT.FIXED, 1, 1));
		crs.add(new BerTag(TagConstants.ACCESS_CONTROL_RULE_TABLE_TAG), new TagLengthRule(CONSTRAINT.OR, 0, 17));
		crs.add(new BerTag(TagConstants.CARD_APDUS_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		crs.add(new BerTag(TagConstants.REDIRECTION_TAG_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		crs.add(new BerTag(TagConstants.CAPABILITY_TUPLES_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		crs.add(new BerTag(TagConstants.STATUS_TUPLES_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		crs.add(new BerTag(TagConstants.NEXT_CCC_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		crs.add(new BerTag(TagConstants.EXTENDED_APPLICATION_CARDURL_TAG), new TagLengthRule(CONSTRAINT.FIXED, 48, 48));
		crs.add(new BerTag(TagConstants.SECURITY_OBJECT_BUFFER_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 48));
		crs.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		m_maxLenMap.put(APDUConstants.CARD_CAPABILITY_CONTAINER_OID, crs);

		// SP800-73-4 Part 1, Table 9. Card Holder Unique Identifier tags
		crs = new ContainerRuleset(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		crs.add(new BerTag(TagConstants.BUFFER_LENGTH_TAG), new TagLengthRule(CONSTRAINT.FIXED, 2, 2));
		crs.add(new BerTag(TagConstants.FASC_N_TAG), new TagLengthRule(CONSTRAINT.FIXED, 25, 25));
		crs.add(new BerTag(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG), new TagLengthRule(CONSTRAINT.FIXED, 4, 4));
		crs.add(new BerTag(TagConstants.DUNS_TAG), new TagLengthRule(CONSTRAINT.FIXED, 9, 9));
		crs.add(new BerTag(TagConstants.GUID_TAG), new TagLengthRule(CONSTRAINT.FIXED, 16, 16));
		crs.add(new BerTag(TagConstants.CHUID_EXPIRATION_DATE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 8, 8));
		crs.add(new BerTag(TagConstants.CARDHOLDER_UUID_TAG), new TagLengthRule(CONSTRAINT.FIXED, 16, 16));
		crs.add(new BerTag(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 3200, true));
		crs.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		m_maxLenMap.put(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, crs);

		// Handle cert containers from Table 10, 15, 16, 17, 20-39, 42 of SP 800-73-4

		for (String cn : certOids) {
			crs = new ContainerRuleset(cn);
			crs.add(new BerTag(TagConstants.CERTIFICATE_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 1858, true));
			crs.add(new BerTag(TagConstants.CERTINFO_TAG), new TagLengthRule(CONSTRAINT.FIXED, 1, 1));
			crs.add(new BerTag(TagConstants.MSCUID_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 38));
			crs.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
			m_maxLenMap.put(cn, crs);
		}

		// SP 800-73-4 Part 1, Table 11. Cardholder Fingerprints
		crs = new ContainerRuleset(APDUConstants.CARDHOLDER_FINGERPRINTS_OID);
		crs.add(new BerTag(TagConstants.FINGERPRINT_I_AND_II_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 88, 4000, true));
		crs.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		m_maxLenMap.put(APDUConstants.CARDHOLDER_FINGERPRINTS_OID, crs);

		// SP 800-73-4 Part 1, Table 12. Security Object
		crs = new ContainerRuleset(APDUConstants.SECURITY_OBJECT_OID);
		crs.add(new BerTag(TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 30));
		crs.add(new BerTag(TagConstants.SECURITY_OBJECT_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 1298));
		crs.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		m_maxLenMap.put(APDUConstants.SECURITY_OBJECT_OID, crs);

		// SP 800-73-4 Part 1, Table 13. Cardholder Facial Image
		crs = new ContainerRuleset(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID);
		crs.add(new BerTag(TagConstants.IMAGE_FOR_VISUAL_VERIFICATION_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 12704, true));
		crs.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		m_maxLenMap.put(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID, crs);

		// SP 800-73-4 Part 1, Table 14. Printed Information tags
		crs = new ContainerRuleset(APDUConstants.PRINTED_INFORMATION_OID);
		crs.add(new BerTag(TagConstants.NAME_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 125));
		crs.add(new BerTag(TagConstants.EMPLOYEE_AFFILIATION_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 20));
		crs.add(new BerTag(TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 9, 9));
		crs.add(new BerTag(TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 20));
		crs.add(new BerTag(TagConstants.ISSUER_IDENTIFICATION_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 15));
		crs.add(new BerTag(TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 20));
		crs.add(new BerTag(TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 20));
		crs.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		m_maxLenMap.put(APDUConstants.PRINTED_INFORMATION_OID, crs);

		// SP 800-73-4 Part 1, Table 18. Discovery Object
		crs = new ContainerRuleset(APDUConstants.DISCOVERY_OBJECT_OID);
		crs.add(new BerTag(TagConstants.PIV_CARD_APPLICATION_AID_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 10, 12));
		crs.add(new BerTag(TagConstants.PIN_USAGE_POLICY_TAG), new TagLengthRule(CONSTRAINT.FIXED, 2, 2));
		m_maxLenMap.put(APDUConstants.DISCOVERY_OBJECT_OID, crs);

		// SP 800-73-4 Part 1, Table 19. Key History
		crs = new ContainerRuleset(APDUConstants.KEY_HISTORY_OBJECT_OID);
		crs.add(new BerTag(TagConstants.KEYS_WITH_ON_CARD_CERTS_TAG), new TagLengthRule(CONSTRAINT.FIXED, 1, 1));
		crs.add(new BerTag(TagConstants.KEYS_WITH_OFF_CARD_CERTS_TAG), new TagLengthRule(CONSTRAINT.FIXED, 1, 1));
		// TODO: Handle conditional hmmm...
		crs.add(new BerTag(TagConstants.OFF_CARD_CERT_URL_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 118));
		crs.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		m_maxLenMap.put(APDUConstants.KEY_HISTORY_OBJECT_OID, crs);

		// SP 800-73-4 Part 1, Table 40. Cardholder Iris Images
		crs = new ContainerRuleset(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID);
		crs.add(new BerTag(TagConstants.IMAGES_FOR_IRIS_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 7100, true));
		crs.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		m_maxLenMap.put(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID, crs);

		// SP 800-73-4 Part 1, Table 41. Biometric Information Templates Group Template
		crs = new ContainerRuleset(APDUConstants.BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID);
		crs.add(new BerTag(TagConstants.NUMBER_OF_FINGERS_TAG), new TagLengthRule(CONSTRAINT.FIXED, 1, 1));
		crs.add(new BerTag(TagConstants.BIT_FOR_FIRST_FINGER_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 28));
		crs.add(new BerTag(TagConstants.BIT_FOR_SECOND_FINGER_TAG), new TagLengthRule(CONSTRAINT.VARIABLE, 0, 28));
		crs.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		m_maxLenMap.put(APDUConstants.BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID, crs);

		// SP 800-73-4 Part 1, Table 43. Pairing Code Reference Data
		crs = new ContainerRuleset(APDUConstants.PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID);
		crs.add(new BerTag(TagConstants.PAIRING_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 1, 1));
		crs.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG), new TagLengthRule(CONSTRAINT.FIXED, 0, 0));
		m_maxLenMap.put(APDUConstants.PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID, crs);
	}

	/*
	 * Public constructor
	 */

	public TagBoundaryManager() {
		initCache();
	}

	/**
	 * Gets the tag length rules
	 * 
	 * @param oid container OID
	 * @return HashMap of TagLengthRule objects, one for each tag
	 */
	private HashMap<BerTag, TagLengthRule> getTagLengthRules(String oid) {
		ContainerRuleset cr = m_maxLenMap.get(oid);
		HashMap<BerTag, TagLengthRule> tlr;
		tlr = cr.getTagRuleset();
		return tlr;
	}

	/**
	 *
	 */
	public ContainerRuleset getMaxLenMap(String oid) {
		return m_maxLenMap.get(oid);
	}

	public HashMap getMaxLenMap() {
		return m_maxLenMap;
	}

	/**
	 * Determines whether the length of the byte array corresponding to the tag
	 * falls within the length boundaries for that container
	 *
	 * @param containerOid Container OID
	 * @param tag        the element's tag
	 * @param bytesLength computed by adding value lengths from the value length
	 *                   under test
	 * @return the difference between the prescribed lengths and the value length,
	 *         hopefully all bits clear
	 * @throws NullPointerException
	 * @throws CardClientException 
	 */
	public int lengthDelta(String containerOid, BerTag tag, int bytesLength) throws NullPointerException, CardClientException, SoftTagBoundaryException {
		int rv = -1;
		HashMap<BerTag, TagLengthRule> tlRules = getTagLengthRules(containerOid);
		if (tlRules == null) {
			String errStr = (String.format("Rules for %s, tag 0x%02x is null", APDUConstants.containerOidToNameMap.get(containerOid), Hex.toHexString(tag.bytes)));
			s_logger.error(errStr);
			NullPointerException e = new NullPointerException(errStr);
			throw (e);
		}
		TagLengthRule tlr = tlRules.get(tag);
		int hi = tlr.getHighVal();
		int lo = tlr.getLowVal();
		CONSTRAINT rule;
		if((rule = tlr.getRule()) != null) {
		switch (rule) {
			case VARIABLE:
				// When there's a range, negative indicates below floor,
				// positive indicates above ceiling, zero indicates in range.
				if (bytesLength >= lo && bytesLength <= hi) {
					rv = 0; // Pass
				} else if (bytesLength < lo) {
					rv = lo - bytesLength;			
				} else {
					rv = bytesLength - hi;
                }
				break;
				
			case OR:
				// Here, we want the return value to indicate what didn't match
				if (bytesLength == lo || bytesLength == hi) {
					rv = 0; // Pass
				} else {
					rv = ((bytesLength != lo) ? 1 : 0) << 1;
					rv |= (bytesLength != hi) ? 1 : 0;
				}
				break;
			case FIXED:
				if (bytesLength == lo && bytesLength == hi) { // Check for typos in maxLenMap i suppose
					rv = 0; // Pass
				}
				break;
			default: // Let's fail the programmer
				String errStr = String.format("Rule for %s, container %s has unknown rule", Hex.toHexString(tag.bytes));
				s_logger.error(errStr);
				break;
			}
		}
		if (rv != 0) {
			if (tlr.hasSoftUpperBound()) {
				String errStr = String.format("Container %s, Tag %s varies from SP 800-73-4 table by %d",
				containerOid, Hex.toHexString(tag.bytes), rv);
				try {
					rv = 0; // TODO: Here, we should *really* be checking a boolean m_signerCertEmbedded flag.
					errStr += " (ignored due to tag container rule)";
					throw new SoftTagBoundaryException(errStr);
				} catch (SoftTagBoundaryException e) {
					s_logger.error(errStr);
				}
			} else {
			  String errStr = String.format("Container %s, Tag %s varies from SP 800-73-4 table by %d",
			  containerOid, Hex.toHexString(tag.bytes), rv); s_logger.error(errStr);
			  throw new CardClientException(errStr);
			}
		}
		return rv;
	}
}
