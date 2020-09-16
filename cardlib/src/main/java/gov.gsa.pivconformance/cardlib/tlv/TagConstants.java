package gov.gsa.pivconformance.cardlib.tlv;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class TagConstants {
	public static final byte[] AID_TAG = { 0x4F };
	public static final byte[] APPLICATION_LABEL = { 0x50 };
	public static final byte[] UNIFORM_RESOURCE_LOCATOR = { 0x50 };
	public static final byte[] CRYPTOGRAPHIC_ALGORITHMS = { (byte) 0xAC };
	public static final byte[] CRYPTOGRAPHIC_ALGORITHM_IDENTIFIER = { (byte) 0x80 };
	public static final byte[] OBJECT_IDENTIFIER = { (byte) 0x06 };
	public static final byte[] TAG_LIST = { 0x5c };
	public static final byte[] COEXISTENT_TAG_ALLOCATION_AUTHORITY = { 0x79 };

	public static final byte[] CERTIFICATE_TAG = { 0x70 };
	public static final byte[] CERTINFO_TAG = { 0x71 };
	public static final byte[] MSCUID_TAG = { 0x72 };

	/**
	 *
	 * List of all x509 Tags for easy lookup
	 *
	 */
	public static final List<byte[]> Allx509Tags() {

		ArrayList<byte[]> rv = new ArrayList<byte[]>();
		rv.add(CERTIFICATE_TAG);
		rv.add(CERTINFO_TAG);
		rv.add(MSCUID_TAG);
		rv.add(ERROR_DETECTION_CODE_TAG);

		return rv;
	}

	public static final byte[] COMPRESSED_TAG = { 0x01 };

	public static final byte CRYPTO_MECHANISM_TAG = (byte) 0x80;
	public static final byte PARAMETER_TAG = (byte) 0x81;
	public static final byte DATA_FIELD_TAG = 0x5c;

	public static final byte[] INTERMEDIATE_CVC_TAG = { 0x7F, 0x21 };

	public static final byte[] ERROR_DETECTION_CODE_TAG = { (byte) 0xFE };

	// Card Capability Container tags 800-73-4 Part 1 Table 8
	public static final byte[] CARD_IDENTIFIER_TAG = { (byte) 0xF0 };
	public static final byte[] CAPABILITY_CONTAINER_VERSION_NUMBER_TAG = { (byte) 0xF1 };
	public static final byte[] CAPABILITY_GRAMMAR_VERSION_NUMBER_TAG = { (byte) 0xF2 };
	public static final byte[] APPLICATIONS_CARDURL_TAG = { (byte) 0xF3 };
	public static final byte[] PKCS15_TAG = { (byte) 0xF4 };
	public static final byte[] REGISTERED_DATA_MODEL_NUMBER_TAG = { (byte) 0xF5 };
	public static final byte[] ACCESS_CONTROL_RULE_TABLE_TAG = { (byte) 0xF6 };
	public static final byte[] CARD_APDUS_TAG = { (byte) 0xF7 };
	public static final byte[] REDIRECTION_TAG_TAG = { (byte) 0xFA };
	public static final byte[] CAPABILITY_TUPLES_TAG = { (byte) 0xFB };
	public static final byte[] STATUS_TUPLES_TAG = { (byte) 0xFC };
	public static final byte[] NEXT_CCC_TAG = { (byte) 0xFD };
	public static final byte[] EXTENDED_APPLICATION_CARDURL_TAG = { (byte) 0xE3 };
	public static final byte[] SECURITY_OBJECT_BUFFER_TAG = { (byte) 0xB4 };

	/**
	 *
	 * List of all CCC Tag for easy lookup
	 *
	 */
	public static final List<byte[]> AllCCCTags() {

		ArrayList<byte[]> rv = new ArrayList<byte[]>();
		rv.add(CARD_IDENTIFIER_TAG);
		rv.add(CAPABILITY_CONTAINER_VERSION_NUMBER_TAG);
		rv.add(CAPABILITY_GRAMMAR_VERSION_NUMBER_TAG);
		rv.add(APPLICATIONS_CARDURL_TAG);
		rv.add(PKCS15_TAG);
		rv.add(REGISTERED_DATA_MODEL_NUMBER_TAG);
		rv.add(ACCESS_CONTROL_RULE_TABLE_TAG);
		rv.add(CARD_APDUS_TAG);
		rv.add(REDIRECTION_TAG_TAG);
		rv.add(CAPABILITY_TUPLES_TAG);
		rv.add(STATUS_TUPLES_TAG);
		rv.add(NEXT_CCC_TAG);
		rv.add(EXTENDED_APPLICATION_CARDURL_TAG);
		rv.add(SECURITY_OBJECT_BUFFER_TAG);
		rv.add(ERROR_DETECTION_CODE_TAG);

		return rv;
	}

	// SP800-73-4 Part 1, Table 9. Card Holder Unique Identifier tags
	public static final byte[] BUFFER_LENGTH_TAG = { (byte) 0xEE };
	public static final byte[] FASC_N_TAG = { 0x30 };
	public static final byte[] ORGANIZATIONAL_IDENTIFIER_TAG = { 0x32 };
	public static final byte[] DUNS_TAG = { 0x33 };
	public static final byte[] GUID_TAG = { 0x34 };
	public static final byte[] CHUID_EXPIRATION_DATE_TAG = { 0x35 }; 
	public static final byte[] CARDHOLDER_UUID_TAG = { 0x36 };
	public static final byte[] DEPRECATED_AUTHENTICATION_KEY_MAP ={ 0x3D };
	public static final byte[] ISSUER_ASYMMETRIC_SIGNATURE_TAG = { 0x3E };

	/**
	 *
	 * List of all CHUID tags for easy lookup
	 *
	 */
	public static final List<byte[]> AllCHUIDTags() {

		ArrayList<byte[]> rv = new ArrayList<byte[]>();
		rv.add(BUFFER_LENGTH_TAG);
		rv.add(FASC_N_TAG);
		rv.add(ORGANIZATIONAL_IDENTIFIER_TAG);
		rv.add(DUNS_TAG);
		rv.add(GUID_TAG);
		rv.add(CHUID_EXPIRATION_DATE_TAG);
		rv.add(CARDHOLDER_UUID_TAG);
		rv.add(ISSUER_ASYMMETRIC_SIGNATURE_TAG);
		rv.add(ERROR_DETECTION_CODE_TAG);

		return rv;
	}

	// SP800-73-4 Part 1, Table 11. Card Holder Fingerprints Tags
	public static final byte[] FINGERPRINT_I_AND_II_TAG = { (byte) 0xBC };

	// SP800-73-4 Part 1, Table 12. Security Object Tags
	public static final byte[] MAPPING_OF_DG_TO_CONTAINER_ID_TAG = { (byte) 0xBA };
	public static final byte[] SECURITY_OBJECT_TAG = { (byte) 0xBB };

	// SP800-73-4 Part 1, Table 13. Card Holder Facial Image Tags
	public static final byte[] IMAGE_FOR_VISUAL_VERIFICATION_TAG = { (byte) 0xBC }; 

	// SP800-73-4 Part 1, Table 14. Printed Information Tags
	public static final byte[] NAME_TAG = { 0x01 };
	public static final byte[] EMPLOYEE_AFFILIATION_TAG = { 0x02 };
	public static final byte[] PRINTED_INFORMATION_EXPIRATION_DATE_TAG = { 0x04 };
	public static final byte[] AGENCY_CARD_SERIAL_NUMBER_TAG = { 0x05 };
	public static final byte[] ISSUER_IDENTIFICATION_TAG = { 0x06 };
	public static final byte[] ORGANIZATIONAL_AFFILIATION_L1_TAG = { 0x07 };
	public static final byte[] ORGANIZATIONAL_AFFILIATION_L2_TAG = { 0x08 };

	/**
	 *
	 * List of all Printed Information tags for easy lookup
	 *
	 */
	public static final List<byte[]> AllPrintedInfoTags() {

		ArrayList<byte[]> rv = new ArrayList<byte[]>();
		rv.add(NAME_TAG);
		rv.add(EMPLOYEE_AFFILIATION_TAG);
		rv.add(PRINTED_INFORMATION_EXPIRATION_DATE_TAG);
		rv.add(AGENCY_CARD_SERIAL_NUMBER_TAG);
		rv.add(ISSUER_IDENTIFICATION_TAG);
		rv.add(ORGANIZATIONAL_AFFILIATION_L1_TAG);
		rv.add(ORGANIZATIONAL_AFFILIATION_L2_TAG);
		rv.add(ERROR_DETECTION_CODE_TAG);

		return rv;
	}

	// SP800-73-4 Part 1, Table 18. Discovery Object Tags
	public static final byte[] PIV_CARD_APPLICATION_AID_TAG = { 0x4F };
	public static final byte[] PIN_USAGE_POLICY_TAG = { 0x5F, 0x2F };

	// SP800-73-4 Part 1, Table 19. Key history Object Tags
	public static final byte[] KEYS_WITH_ON_CARD_CERTS_TAG = { (byte) 0xC1 };
	public static final byte[] KEYS_WITH_OFF_CARD_CERTS_TAG = { (byte) 0xC2 };
	public static final byte[] OFF_CARD_CERT_URL_TAG = { (byte) 0xF3 };

	// SP800-73-4 Part 1, Table 40. Cardholder Iris Images
	public static final byte[] IMAGES_FOR_IRIS_TAG = { (byte) 0xBC };

	// SP800-73-4 Part 1, Table 41. Biometric Information Templates Group Template
	public static final byte[] NUMBER_OF_FINGERS_TAG = { 0x02 };
	public static final byte[] BIT_FOR_FIRST_FINGER_TAG = { 0x7f, 0x60 };
	public static final byte[] BIT_FOR_SECOND_FINGER_TAG = { 0x7f, 0x60 };

	// SP800-73-4 Part 1, Table 43. Pairing Code Reference Data Container
	public static final byte[] PAIRING_CODE_TAG = { (byte) 0x99 };

	// SP800-73-4 part 3, table 4 - authenticator template
	public static final byte[] REFERENCE_DATA_TAG = { (byte) 0x81 };
	public static final byte[] KEY_REFERENCE_TAG = { (byte) 0x83 };

	// SP800-73-4 part 1, table 4a PIV Card Application Authentication Data
	// References
	public static final byte KEY_REFERENCE_GLOBAL_PIN_TAG = 0x00;
	public static final byte KEY_REFERENCE_APPLICATION_PIN_TAG = (byte) 0x80;
	public static final byte KEY_REFERENCE_PIN_UNBLOCK_KEY_TAG = (byte) 0x81;
	public static final byte KEY_REFERENCE_PRIMARY_FINGER_OCC_TAG = (byte) 0x96;
	public static final byte KEY_REFERENCE_SECONDARY_FINGER_OCC_TAG = (byte) 0x97;
	public static final byte KEY_REFERENCE_PAIRING_CODE_TAG = (byte) 0x98;

	public static final byte[] Three_Key_Triple_DES_ECB_ID = { 0x00 };
	public static final String Three_Key_Triple_DES_ECB = "3 Key Triple DES ECB";

	public static final byte[] Three_Key_Triple_DES_ECB2_ID = { 0x03 };
	public static final String Three_Key_Triple_DES_ECB2 = "3 Key Triple DES ECB";

	public static final byte[] RSA_1024_bit_ID = { 0x06 };
	public static final String RSA_1024_bit = "RSA 1024 bit modulus, 65 537 exponent 2256 - 1";

	public static final byte[] RSA_2048_bit_ID = { 0x07 };
	public static final String RSA_2048_bit = "RSA 2048 bit modulus, 65 537 exponent 2256 - 1";

	public static final byte[] AES_128_ID = { 0x08 };
	public static final String AES_128 = "AES-128 ECB";

	public static final byte[] AES_192_ID = { 0x0A };
	public static final String AES_192 = "AES-192 ECB";

	public static final byte[] AES_256_ID = { 0x0C };
	public static final String AES_256 = "AES-256 ECB";

	public static final byte[] ECC_Curve_P_256_ID = { 0x11 };
	public static final String ECC_Curve_P_256 = "ECC: Curve P-256";

	public static final byte[] ECC_Curve_P_384_ID = { 0x14 };
	public static final String ECC_Curve_P_384 = "ECC: Curve P-384";

	public static final byte[] Cipher_Suite_2_ID = { 0x27 };
	public static final String Cipher_Suite_2 = "Cipher Suite 2";

	public static final byte[] Cipher_Suite_7_ID = { 0x2E };
	public static final String Cipher_Suite_7 = "Cipher Suite 7";

	public static final HashMap<byte[], String> algMAP = new HashMap<byte[], String>() {
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;

		{
			put(Three_Key_Triple_DES_ECB_ID, Three_Key_Triple_DES_ECB);
			put(Three_Key_Triple_DES_ECB2_ID, Three_Key_Triple_DES_ECB2);
			put(RSA_1024_bit_ID, RSA_1024_bit);
			put(RSA_2048_bit_ID, RSA_2048_bit);
			put(AES_128_ID, AES_128);
			put(AES_192_ID, AES_192);
			put(AES_256_ID, AES_256);
			put(ECC_Curve_P_256_ID, ECC_Curve_P_256);
			put(ECC_Curve_P_384_ID, ECC_Curve_P_384);
			put(Cipher_Suite_2_ID, Cipher_Suite_2);
			put(Cipher_Suite_7_ID, Cipher_Suite_7);
		}
	};
}

