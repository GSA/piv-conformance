package gov.gsa.pivconformance.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.cardlib.tlv.BerTag;
import gov.gsa.pivconformance.cardlib.tlv.TagConstants;

public class SP800_73_4CHUIDTests {
	private static final Logger s_logger = LoggerFactory.getLogger(SP800_73_4CHUIDTests.class);

	// CHUID value lengths comply with Table 9 of SP 800-73-4
	@DisplayName("SP800-73-4.8 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_8(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			if (!o.inBounds(oid)) {
				String errStr = (String.format("Tag in " + o.getFriendlyName() + " failed length check"));
				Exception e = new Exception(errStr);
				throw (e);
			}
		} catch (Exception e) {
			s_logger.info(e.getMessage());
			fail(e);
		}
	}

	// If CHUID tag 0xEE is present, it is the first tag in the blob
	@DisplayName("SP800-73-4.9 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_9(String oid, TestReporter reporter) {

		PIVDataObject o = AtomHelper.getDataObject(oid);

		List<BerTag> tagList = o.getTagList();

		BerTag berBufferLenTagTag = new BerTag(TagConstants.BUFFER_LENGTH_TAG);
		if (tagList.contains(berBufferLenTagTag)) {
			assertTrue(Arrays.equals(tagList.get(0).bytes, TagConstants.BUFFER_LENGTH_TAG));
		}
	}

	// SP 800-73-5 Part 1, Appendix A, Table 10 eliminates Buffer Length (EE).
	// The decoder keeps EE out of the signed-content tag list, so inspect the
	// decoded field rather than that list. Historical PIV-I retains 73-4.9.
	@DisplayName("SP800-73-5 CHUID Buffer Length absent")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_5_Test_9(String oid, TestReporter reporter) {
		CardHolderUniqueIdentifier chuid = (CardHolderUniqueIdentifier) AtomHelper.getDataObject(oid);
		assertTrue(chuid.getBufferLength() == null, "SP800-73-5 CHUID: eliminated tag EE is present");
	}

	// Tag 0x30 is present
	@DisplayName("SP800-73-4.10 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_10(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
		List<BerTag> tagList = o.getTagList();
		BerTag berFASCTag = new BerTag(TagConstants.FASC_N_TAG);
		assertTrue(tagList.contains(berFASCTag));
	}

	// Tags 0x32 and 0x33 are optionally present and must follow 0x30 in that order
	@DisplayName("SP800-73-4.11 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_11(String oid, TestReporter reporter) {

		PIVDataObject o = AtomHelper.getDataObject(oid);
		List<BerTag> tagList = o.getTagList();

		BerTag berOrgIDTag = new BerTag(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG);
		BerTag berDUNSTag = new BerTag(TagConstants.DUNS_TAG);
		BerTag berFASCTag = new BerTag(TagConstants.FASC_N_TAG);

		if (tagList.contains(berOrgIDTag)) {

			int orgIDTagIndex = tagList.indexOf(berFASCTag);

			assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes, TagConstants.FASC_N_TAG));
			assertTrue(Arrays.equals(tagList.get(orgIDTagIndex + 1).bytes, TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
		}

		if (tagList.contains(berDUNSTag)) {

			int orgIDTagIndex = tagList.indexOf(berFASCTag);

			if (tagList.contains(berOrgIDTag)) {

				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes, TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex + 1).bytes,
						TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex + 2).bytes, TagConstants.DUNS_TAG));

			} else {

				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes, TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex + 1).bytes, TagConstants.DUNS_TAG));

			}
		}
	}

	// SP 800-73-5 Part 1, Appendix A, Table 10 eliminates tags 32 and 33.
	@DisplayName("SP800-73-5 CHUID organization fields absent")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_5_Test_11(String oid, TestReporter reporter) {
		CardHolderUniqueIdentifier chuid = (CardHolderUniqueIdentifier) AtomHelper.getDataObject(oid);
		assertTrue(chuid.getOrganizationalIdentifier() == null,
				"SP800-73-5 CHUID: eliminated tag 32 is present");
		assertTrue(chuid.getdUNS() == null, "SP800-73-5 CHUID: eliminated tag 33 is present");
	}

	// The Agency Code, System Code, and Credential Number of the FASC-N are
	// present.
	// The credential series, individual credential issue, person identifier,
	// organizational category, organizational identifier, and person/organization
	// association category of the FASC-N are populated
	@DisplayName("SP800-73-4.12 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_12(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
		if (o == null) {
			ConformanceTestException e = new ConformanceTestException(String.format("Object for OID %s is null", oid));
			fail(e);
		}

		byte[] fascn = ((CardHolderUniqueIdentifier) o).getfASCN();
		// Extract agency code, system code, credential number and ensure they
		// are numeric.
		String cookedFascn = CardHolderUniqueIdentifier.cook(fascn);
		if (cookedFascn == null) {
			ConformanceTestException e = new ConformanceTestException(
					String.format("Couldn't decode FASC-N bytes", oid));
			fail(e);
		}
		s_logger.debug("Cooked FASC-N: {}", cookedFascn);
		assertTrue(Integer.parseInt(cookedFascn.substring(0, 4)) != 0, "Agency code is zero");
		assertTrue(Integer.parseInt(cookedFascn.substring(4, 8)) != 0, "System code is zero");
		assertTrue(Integer.parseInt(cookedFascn.substring(8, 14)) != 0, "Credential number is zero");
	}

	// Tag 0x36 is optionally present and follows tags from 73-4.10, 73-4.11,
	// 73-4.12
	@DisplayName("SP800-73-4.13 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_13(String oid, TestReporter reporter) {

		PIVDataObject o = AtomHelper.getDataObject(oid);

		List<BerTag> tagList = o.getTagList();

		BerTag berOrgIDTag = new BerTag(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG);
		BerTag berDUNSTag = new BerTag(TagConstants.DUNS_TAG);
		BerTag berFASCTag = new BerTag(TagConstants.FASC_N_TAG);
		BerTag berCardholderUUIDTag = new BerTag(TagConstants.CARDHOLDER_UUID_TAG);

		if (tagList.contains(berCardholderUUIDTag)) {

			assertTrue(tagList.size() >= 4);

			int orgFASCNTagIndex = tagList.indexOf(berFASCTag);
			assertTrue(orgFASCNTagIndex >= 0);

			boolean optionalTagsPresent = false;

			if (tagList.contains(berOrgIDTag)) {

				optionalTagsPresent = true;
				assertTrue(tagList.size() >= 5);

				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes, TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 1).bytes,
						TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 2).bytes, TagConstants.GUID_TAG));
				assertTrue(
						Arrays.equals(tagList.get(orgFASCNTagIndex + 3).bytes, TagConstants.CHUID_EXPIRATION_DATE_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 4).bytes, TagConstants.CARDHOLDER_UUID_TAG));
			}

			if (tagList.contains(berDUNSTag)) {

				optionalTagsPresent = true;

				if (tagList.contains(berOrgIDTag)) {

					assertTrue(tagList.size() >= 6);
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes, TagConstants.FASC_N_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 1).bytes,
							TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 2).bytes, TagConstants.DUNS_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 3).bytes, TagConstants.GUID_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 4).bytes,
							TagConstants.CHUID_EXPIRATION_DATE_TAG));
					assertTrue(
							Arrays.equals(tagList.get(orgFASCNTagIndex + 5).bytes, TagConstants.CARDHOLDER_UUID_TAG));

				} else {

					assertTrue(tagList.size() >= 5);
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes, TagConstants.FASC_N_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 1).bytes, TagConstants.DUNS_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 2).bytes, TagConstants.GUID_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 3).bytes,
							TagConstants.CHUID_EXPIRATION_DATE_TAG));
					assertTrue(
							Arrays.equals(tagList.get(orgFASCNTagIndex + 4).bytes, TagConstants.CARDHOLDER_UUID_TAG));

				}
			}

			if (optionalTagsPresent == false) {
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes, TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 1).bytes, TagConstants.GUID_TAG));
				assertTrue(
						Arrays.equals(tagList.get(orgFASCNTagIndex + 2).bytes, TagConstants.CHUID_EXPIRATION_DATE_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 3).bytes, TagConstants.CARDHOLDER_UUID_TAG));

			}
		}
	}

	// FIPS 201-3 Section 4.2.1 and SP 800-73-5 Part 1 Sections 3.1.2,
	// 3.4.2: the optional CHUID Cardholder UUID is a version 4 UUID.
	@DisplayName("SP800-73-5 optional CHUID Cardholder UUID")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_5_Test_13(String oid, TestReporter reporter) {
		CardHolderUniqueIdentifier chuid = (CardHolderUniqueIdentifier) AtomHelper.getDataObject(oid);
		byte[] value = chuid.getCardholderUUID();
		if (value == null) return;
		assertTrue(value.length == 16, "SP800-73-5 CHUID: Cardholder UUID must contain 16 bytes");
		ByteBuffer bytes = ByteBuffer.wrap(value);
		UUID uuid = new UUID(bytes.getLong(), bytes.getLong());
		assertTrue(uuid.variant() == 2, "SP800-73-5 CHUID: Cardholder UUID must use RFC 4122 variant");
		assertTrue(uuid.version() == 4, "SP800-73-5 CHUID: Cardholder UUID must be version 4");
		List<BerTag> tags = chuid.getTagList();
		assertTrue(tags.indexOf(new BerTag(TagConstants.CARDHOLDER_UUID_TAG))
				== tags.indexOf(new BerTag(TagConstants.CHUID_EXPIRATION_DATE_TAG)) + 1,
				"SP800-73-5 CHUID: tag 36 must immediately follow tag 35");
	}

	// Tags 0x3E and 0xFE are present
	@DisplayName("SP800-73-4.14 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_14(String oid, TestReporter reporter) {

		PIVDataObject o = AtomHelper.getDataObject(oid);

		List<BerTag> tagList = o.getTagList();

		BerTag berIssuerAssymSigTag = new BerTag(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG);
		BerTag berErrorDetectionCodeTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);

		assertTrue(tagList.contains(berIssuerAssymSigTag) && tagList.contains(berErrorDetectionCodeTag));
	}

	// Expiration Date is formatted YYYYMMDD
	@DisplayName("SP800-73-4.15 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_15(String oid, TestReporter reporter) {

		PIVDataObject o = AtomHelper.getDataObject(oid);
		byte[] encodedDate = ((CardHolderUniqueIdentifier) o).getExpirationDateBytes();
		String message = "CHUID expiration date must be an eight-digit valid YYYYMMDD date";
		assertNotNull(encodedDate, message);
		assertEquals(8, encodedDate.length, message);
		assertDoesNotThrow(() -> LocalDate.parse(new String(encodedDate, StandardCharsets.US_ASCII),
				DateTimeFormatter.BASIC_ISO_DATE), message);

	}

	// Expiration Date is with in N years
	@DisplayName("SP800-73-4.16 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider2")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_16(String oid, String yearsStr, TestReporter reporter) {
		int years = 0;
		// Check that the yearsStr passed in is not null
		if (yearsStr == null) {
			ConformanceTestException e = new ConformanceTestException("OID is null");
			fail(e);
		}

		try {
			years = Integer.parseInt(yearsStr);
		} catch (NumberFormatException e) {
			s_logger.error("Integer parsing error {} on '{}'", e.getMessage(), yearsStr);
			fail(e);
		}

		PIVDataObject o = AtomHelper.getDataObject(oid);

		Date expirationDate = ((CardHolderUniqueIdentifier) o).getExpirationDate();

		Calendar cal = Calendar.getInstance();
		Date today = cal.getTime();
		cal.add(Calendar.YEAR, years);
		Date todayPlus6Years = cal.getTime();

		assertTrue(expirationDate.compareTo(today) >= 0);
		assertTrue(expirationDate.compareTo(todayPlus6Years) <= 0);
	}

	// No tags other than (0xEE, 0x30, 0x32, 0x33, 0x34, 0x35, 0x36, 0x3E, 0xFE) are
	// present
	@DisplayName("SP800-73-4.17 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_17(String oid, TestReporter reporter) {

		PIVDataObject o = AtomHelper.getDataObject(oid);

		List<BerTag> tagList = o.getTagList();

		List<byte[]> allCHUIDTags = TagConstants.AllCHUIDTags();
		for (BerTag tag : tagList) {

			// Check that the tag is present in the all CHUID tags list
			boolean present = false;
			for (int i = 0; i < allCHUIDTags.size(); i++) {

				if (Arrays.equals(allCHUIDTags.get(i), tag.bytes)) {
					present = true;
					break;
				}
			}
			assertTrue(present);
		}
	}

	@DisplayName("SP800-73-5 CHUID allowed tags")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_5_Test_17(String oid, TestReporter reporter) {
		CardHolderUniqueIdentifier chuid = (CardHolderUniqueIdentifier) AtomHelper.getDataObject(oid);
		assertTrue(chuid.getBufferLength() == null, "SP800-73-5 CHUID: eliminated tag EE is present");
		for (BerTag tag : chuid.getTagList()) {
			boolean allowed = Arrays.equals(tag.bytes, TagConstants.FASC_N_TAG)
					|| Arrays.equals(tag.bytes, TagConstants.GUID_TAG)
					|| Arrays.equals(tag.bytes, TagConstants.CHUID_EXPIRATION_DATE_TAG)
					|| Arrays.equals(tag.bytes, TagConstants.CARDHOLDER_UUID_TAG)
					|| Arrays.equals(tag.bytes, TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG)
					|| Arrays.equals(tag.bytes, TagConstants.ERROR_DETECTION_CODE_TAG);
			assertTrue(allowed, "SP800-73-5 CHUID: tag " + Hex.encodeHexString(tag.bytes) + " is not permitted");
		}
	}

	// Tag 0x30 is the first tag or the first tag following 0xEE (split from
	// 73-4.10)
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.43 test")
	void sp800_73_4_Test_43(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			List<BerTag> tagList = o.getTagList();
			BerTag berFASCTag = new BerTag(TagConstants.FASC_N_TAG);
			if (tagList.contains(berFASCTag) == false) {
				Exception e = new Exception("0x30 tag is missing");
				throw e;
			}
			int tagIndex = tagList.indexOf(berFASCTag);
			assertTrue(tagIndex == 0 || tagIndex == 1);
		} catch (Exception e) {
			fail(e);
		}
	}

	@DisplayName("SP800-73-5 CHUID FASC-N first")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_5_Test_43(String oid, TestReporter reporter) {
		CardHolderUniqueIdentifier chuid = (CardHolderUniqueIdentifier) AtomHelper.getDataObject(oid);
		assertTrue(chuid.getBufferLength() == null, "SP800-73-5 CHUID: eliminated tag EE is present");
		List<BerTag> tags = chuid.getTagList();
		assertTrue(!tags.isEmpty() && Arrays.equals(tags.get(0).bytes, TagConstants.FASC_N_TAG),
				"SP800-73-5 CHUID: tag 30 must be first");
	}

	// Tag 0x34 is present (split from 73-4.12)
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.44 test")
	void sp800_73_4_Test_44(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			List<BerTag> tagList = o.getTagList();
			BerTag berGUIDTag = new BerTag(TagConstants.GUID_TAG);
			assertTrue(tagList.contains(berGUIDTag));
		} catch (Exception e) {
			fail(e);
		}
	}

	// Tag 0x34 follows Tag 0x30, 32, or 0x33
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.45 test")
	void sp800_73_4_Test_45(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			List<BerTag> tagList = o.getTagList();

			BerTag berOrgIDTag = new BerTag(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG); // 0x32
			BerTag berDUNSTag = new BerTag(TagConstants.DUNS_TAG); // 0x33
			BerTag berFASCTag = new BerTag(TagConstants.FASC_N_TAG); // 0x30
			BerTag berGUIDTag = new BerTag(TagConstants.GUID_TAG); // 0x34

			if (tagList.contains(berGUIDTag) == false) {
				Exception e = new Exception("0x34 tag is missing");
				throw e;
			}

			if (!(tagList.size() >= 3)) {
				Exception e = new Exception("tagList.size() < 3");
				throw e;
			}

			int orgFASCNTagIndex = tagList.indexOf(berFASCTag);
			if (!(orgFASCNTagIndex >= 0)) {
				Exception e = new Exception("orgFASCNTagIndex is not >= 0");
				throw e;
			}

			boolean optionalTagsPresent = false;

			if (tagList.contains(berDUNSTag)) {

				optionalTagsPresent = true;

				if (tagList.contains(berOrgIDTag)) {

					assertTrue(tagList.size() >= 5);
					if ((Arrays.equals(tagList.get(orgFASCNTagIndex).bytes, TagConstants.FASC_N_TAG)) == false) {
						Exception e = new Exception("tagList.get(orgFASCNTagIndex).bytes != TagConstants.FASC_N_TAG");
						throw e;
					}
					if ((Arrays.equals(tagList.get(orgFASCNTagIndex + 1).bytes,
							TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG)) == false) {
						Exception e = new Exception(
								"tagList.get(orgFASCNTagIndex+1).bytes != TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG");
						throw e;
					}
					if ((Arrays.equals(tagList.get(orgFASCNTagIndex + 2).bytes, TagConstants.DUNS_TAG)) == false) {
						Exception e = new Exception("tagList.get(orgFASCNTagIndex+2).bytes != TagConstants.DUNS_TAG");
						throw e;
					}
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 3).bytes, TagConstants.GUID_TAG));

				} else {

					assertTrue(tagList.size() >= 4);
					if ((Arrays.equals(tagList.get(orgFASCNTagIndex).bytes, TagConstants.FASC_N_TAG)) == false) {
						Exception e = new Exception("tagList.get(orgFASCNTagIndex).bytes != TagConstants.FASC_N_TAG");
						throw e;
					}
					if ((Arrays.equals(tagList.get(orgFASCNTagIndex + 1).bytes, TagConstants.DUNS_TAG)) == false) {
						Exception e = new Exception("tagList.get(orgFASCNTagIndex+1).bytes != TagConstants.DUNS_TAG");
						throw e;
					}
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 2).bytes, TagConstants.GUID_TAG));

				}
			} else if (tagList.contains(berOrgIDTag)) {
				optionalTagsPresent = true;
				if (!(tagList.size() >= 4)) {
					Exception e = new Exception("tagList.size() < 4");
					throw e;
				}

				if (Arrays.equals(tagList.get(orgFASCNTagIndex).bytes, TagConstants.FASC_N_TAG) == false) {
					Exception e = new Exception("tagList.get(orgFASCNTagIndex).bytes != TagConstants.FASC_N_TAG");
					throw e;
				}
				if (Arrays.equals(tagList.get(orgFASCNTagIndex + 1).bytes,
						TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG) == false) {
					Exception e = new Exception(
							"orgFASCNTagIndex+1).bytes != TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG");
					throw e;
				}
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 2).bytes, TagConstants.GUID_TAG));
			}

			if (optionalTagsPresent == false) {

				if (Arrays.equals(tagList.get(orgFASCNTagIndex).bytes, TagConstants.FASC_N_TAG) == false) {
					Exception e = new Exception("tagList.get(orgFASCNTagIndex).bytes != TagConstants.FASC_N_TAG");
					throw e;
				}
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex + 1).bytes, TagConstants.GUID_TAG));

			}
		} catch (Exception e) {
			fail(e);
		}
	}

	@DisplayName("SP800-73-5 CHUID GUID after FASC-N")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_5_Test_45(String oid, TestReporter reporter) {
		CardHolderUniqueIdentifier chuid = (CardHolderUniqueIdentifier) AtomHelper.getDataObject(oid);
		List<BerTag> tags = chuid.getTagList();
		assertTrue(tags.size() >= 2 && Arrays.equals(tags.get(0).bytes, TagConstants.FASC_N_TAG)
				&& Arrays.equals(tags.get(1).bytes, TagConstants.GUID_TAG),
				"SP800-73-5 CHUID: tag 34 must immediately follow tag 30");
	}

	// Tag 0x35 is present (split from 73-4.12)
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.46 test")
	void sp800_73_4_Test_46(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			List<BerTag> tagList = o.getTagList();
			BerTag berExpirationDateTag = new BerTag(TagConstants.CHUID_EXPIRATION_DATE_TAG);
			assertTrue(tagList.contains(berExpirationDateTag));
		} catch (Exception e) {
			fail(e);
		}
	}

	// Tag 0x35 follows Tag 0x34 (split from 73-4.12)
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.47 test")
	void sp800_73_4_Test_47(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);

			List<BerTag> tagList = o.getTagList();

			BerTag berGUIDTag = new BerTag(TagConstants.GUID_TAG);
			BerTag berExpirationDateTag = new BerTag(TagConstants.CHUID_EXPIRATION_DATE_TAG);
			if ((tagList.contains(berGUIDTag) && tagList.contains(berExpirationDateTag)) == false) {
				Exception e = new Exception(
						"(tagList.contains(berGUIDTag) && tagList.contains(berExpirationDateTag)) == false");
				throw e;
			}
			if ((tagList.size() >= 3) == false) {
				Exception e = new Exception("(tagList.size() >= 3) == false");
				throw e;
			}

			int orgGuidTagIndex = tagList.indexOf(berGUIDTag);
			if ((orgGuidTagIndex >= 0) == false) {
				Exception e = new Exception("(orgGuidTagIndex >= 0) == false");
				throw e;
			}
			if ((Arrays.equals(tagList.get(orgGuidTagIndex).bytes, TagConstants.GUID_TAG)) == false) {
				Exception e = new Exception(
						"(Arrays.equals(tagList.get(orgGuidTagIndex).bytes,TagConstants.GUID_TAG)) == false");
				throw e;
			}
			assertTrue(Arrays.equals(tagList.get(orgGuidTagIndex + 1).bytes, TagConstants.CHUID_EXPIRATION_DATE_TAG));

		} catch (Exception e) {
			fail(e);
		}
	}

	// Tag 0x3E is present (split from 73-4.14)
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.48 test")
	void sp800_73_4_Test_48(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			List<BerTag> tagList = o.getTagList();
			BerTag berIssuerAssymSigTag = new BerTag(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG);
			assertTrue(tagList.contains(berIssuerAssymSigTag));
		} catch (Exception e) {
			fail(e);
		}
	}

	// Tag 0x3E follows Tag 0x35 or 0x36 (split from 73-4.14)
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.49 test")
	void sp800_73_4_Test_49(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);

			List<BerTag> tagList = o.getTagList();

			BerTag berIssuerAssymSigTag = new BerTag(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG); // 0x3E
			if (tagList.contains(berIssuerAssymSigTag) == false) {
				Exception e = new Exception("ISSUER_ASYMMETRIC_SIGNATURE_TAG not found");
				fail(e);
			}

			int berIssuerAssymSigTagIndex = tagList.indexOf(berIssuerAssymSigTag);
			if ((berIssuerAssymSigTagIndex >= 0) == false) {
				Exception e = new Exception("ISSUER_ASYMMETRIC_SIGNATURE_TAG not found");
				fail(e);
			}
			assertTrue((Arrays.equals(tagList.get(berIssuerAssymSigTagIndex - 1).bytes,
					TagConstants.CHUID_EXPIRATION_DATE_TAG)
					|| Arrays.equals(tagList.get(berIssuerAssymSigTagIndex - 1).bytes,
							TagConstants.CARDHOLDER_UUID_TAG)),
					"Tag 0x3E preceded by invalid tag"

			);
		} catch (Exception e) {
			fail(e);
		}
	}

	// Tag 0xFE is present (split from 73-4.14)
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.49 test")
	void sp800_73_4_Test_50(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);

			List<BerTag> tagList = o.getTagList();

			BerTag berErrorDetectionCodeTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);

			assertTrue(tagList.contains(berErrorDetectionCodeTag));
		} catch (Exception e) {
			fail(e);
		}
	}

	// Tag 0xFE follows Tag 0x3E (split from 73-4.14)
	@ParameterizedTest(name = "{index} => oid = {0}")
	// @MethodSource("sp800_73_4_CHUIDTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.51 test")
	void sp800_73_4_Test_51(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);

			List<BerTag> tagList = o.getTagList();

			BerTag berIssuerAssymSigTag = new BerTag(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG);
			BerTag berErrorDetectionCodeTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);

			if ((tagList.contains(berIssuerAssymSigTag) && tagList.contains(berErrorDetectionCodeTag)) == false) {
				Exception e = new Exception(
						"Either tag ISSUER_ASYMMETRIC_SIGNATURE_TAG or ERROR_DETECTION_CODE_TAG or both are missing");
				fail(e);
			}

			int berIssuerAssymSigTagIndex = tagList.indexOf(berIssuerAssymSigTag);
			int berErrorDetectionCodeTagIndex = tagList.indexOf(berErrorDetectionCodeTag);
			assertTrue(berErrorDetectionCodeTagIndex == berIssuerAssymSigTagIndex + 1, "Tag 0xFE must follow tag 0x3E");
		} catch (Exception e) {
			fail(e);
		}
	}

	// this is now used only to test changes to atoms
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_73_4_CHUIDTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID));

	}

	// this is now used only to test changes to atoms
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_73_4_CHUIDTestProvider2() {

		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, "14"));

	}

}
