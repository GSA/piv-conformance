package gov.gsa.pivconformance.cardlib.test;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.cardlib.utils.OSUtils;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class X509DataObjectTests {
	private static String resDir = null;
	static {
		resDir = new X509DataObjectTests().getClass().getResource("").getPath();
		System.out.println("Looking in: " + resDir);
	}
	@DisplayName("Test X.509 Data Object parsing")
	@ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
	@MethodSource("dataObjectTestProvider")

	void dataObjectTest(String oid, String file, TestReporter reporter) {
		assertNotNull(oid);
		assertNotNull(file);
		Path filePath = Paths.get(resDir + File.separator + file);
		List<String> lines = null;
		try {

			lines = Files.readAllLines(filePath);
			// Convert to DER
			StringBuffer sb = new StringBuffer("");
			for (String l : lines) {
				sb.append(l + "\r\n");
			}

			StringReader sr = new StringReader(sb.toString());
			PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
			assertNotNull(o);
			reporter.publishEntry(oid, o.getClass().getSimpleName());

			//XXX Unit tests will need to be updated files here are just cert files not card data objects.

			o.setOID(oid);
			o.setBytes(convertPemFileToBytes(sr).getEncoded());
			boolean decoded = o.decode();
			assert(decoded);
		} catch (IOException | CertificateEncodingException e) {
			fail(e);
		}
	}

	/**
	 * Converts a PEM formatted String to a {@link X509Certificate} instance.
	 *
	 * @param pem PEM formatted String
	 * @return a X509Certificate instance
	 * @throws CertificateException
	 * @throws IOException
	 */
	public X509Certificate convertPemFileToBytes(StringReader pem) {
		X509CertificateHolder certHolder = null;
		X509Certificate cert = null;
		@SuppressWarnings("resource")
		PEMParser pp = new PEMParser(pem);
		try {
			certHolder = (X509CertificateHolder) pp.readObject();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		Provider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(provider);

		try {
			cert = new JcaX509CertificateConverter().setProvider(provider).getCertificate(certHolder);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cert;
	}

	/*
	 * CertificateFactory cFactory = CertificateFactory.getInstance("X.509"); X509Certificate cert = (X509Certificate) cFactory.generateCertificate(getInputStream(of_the_original_unmodified_certificate_file));
	 */
	private static Stream<Arguments> dataObjectTestProvider() {
		return Stream.of(
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/03_SKID_Mismatch/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/04_Tampered_CHUID/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/05_Tampered_Certificates/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/06_Tampered_PHOTO/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/07_Tampered_Fingerprints/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/08_Tampered_Security_Object/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/09_Expired_CHUID_Signer/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/10_Expired_Cert_Signer/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/11_Certs_Expire_after_CHUID/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/12_Certs_not_yet_valid/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/13_Certs_are_expired/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/14_Expired_CHUID/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/15_CHUID_FASCN_mismatch/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/16_Card_Authentication_FASCN_mismatch/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/17_PHOTO_FASCN_mismatch/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/18_Fingerprints_FASCN_mismatch/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/19_CHUID_UUID_mismatch/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/20_Card_Authent_UUID_mismatch/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/21_PHOTO_UUID_mismatch/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/22_Fingerprints_UUID_mismatch/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/23_Public_Private_Key_mismatch/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/24_Revoked_Certificates/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/25_Disco_Object_Not_Present/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/26_Disco_Object_Present_App_PIN_Only/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/27_Disco_Object_Present_App_PIN_Primary/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/28_Disco_Object_Present_Global_PIN_Primary/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/38_Bad_Hash_in_Sec_Object/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/39_Golden_FIPS_201-2_Fed_PIV-I-X/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/39_Golden_FIPS_201-2_Fed_PIV-I/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/41_Re-keyed_Card/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/42_OCSP_Expired/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/43_OCSP_revoked_w_nocheck/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/44_OCSP_revoked_wo_nocheck/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/45_OCSP_Invalid_Signature/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV_ICI_8/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV_ICI_9/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/47_Golden_FIPS_201-2_PIV_SAN_Order-X/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/47_Golden_FIPS_201-2_PIV_SAN_Order/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/48_T=0_with_Non-Zero_PPS_LEN_Value/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/49_FIPS_201-2_Facial_Image_CBEFF_Expired/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/50_FIPS_201-2_Facial_Image_CBEFF_Expires_before_CHUID/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/51_FIPS_201-2_Fingerprint_CBEFF_Expired/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/52_FIPS_201-2_Fingerprint_CBEFF_Expires_before_CHUID/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/53_FIPS_201-2_Large_Card_Auth_Cert/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/54_Golden_FIPS_201-2_NFI_PIV-I-X/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/54_Golden_FIPS_201-2_NFI_PIV-I/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/55_FIPS_201-2_Missing_Security_Object/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/56_FIPS_201-2_Signer_Expires/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/57_Revoked_CHUID_Cert/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/58_Revoked_Card_Auth_Cert/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/59_Valid_CBEFF_for_Card_51/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/03_SKID_Mismatch/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/04_Tampered_CHUID/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/05_Tampered_Certificates/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/06_Tampered_PHOTO/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/07_Tampered_Fingerprints/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/08_Tampered_Security_Object/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/09_Expired_CHUID_Signer/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/10_Expired_Cert_Signer/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/11_Certs_Expire_after_CHUID/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/12_Certs_not_yet_valid/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/13_Certs_are_expired/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/14_Expired_CHUID/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/15_CHUID_FASCN_mismatch/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/16_Card_Authentication_FASCN_mismatch/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/17_PHOTO_FASCN_mismatch/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/18_Fingerprints_FASCN_mismatch/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/19_CHUID_UUID_mismatch/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/20_Card_Authent_UUID_mismatch/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/21_PHOTO_UUID_mismatch/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/22_Fingerprints_UUID_mismatch/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/23_Public_Private_Key_mismatch/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/24_Revoked_Certificates/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/25_Disco_Object_Not_Present/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/26_Disco_Object_Present_App_PIN_Only/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/27_Disco_Object_Present_App_PIN_Primary/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/28_Disco_Object_Present_Global_PIN_Primary/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/38_Bad_Hash_in_Sec_Object/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/39_Golden_FIPS_201-2_Fed_PIV-I-X/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/39_Golden_FIPS_201-2_Fed_PIV-I/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/41_Re-keyed_Card/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/42_OCSP_Expired/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/43_OCSP_revoked_w_nocheck/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/44_OCSP_revoked_wo_nocheck/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/45_OCSP_Invalid_Signature/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV_ICI_8/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV_ICI_9/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/47_Golden_FIPS_201-2_PIV_SAN_Order-X/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/47_Golden_FIPS_201-2_PIV_SAN_Order/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/48_T=0_with_Non-Zero_PPS_LEN_Value/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/49_FIPS_201-2_Facial_Image_CBEFF_Expired/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/50_FIPS_201-2_Facial_Image_CBEFF_Expires_before_CHUID/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/51_FIPS_201-2_Fingerprint_CBEFF_Expired/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/52_FIPS_201-2_Fingerprint_CBEFF_Expires_before_CHUID/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/53_FIPS_201-2_Large_Card_Auth_Cert/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/54_Golden_FIPS_201-2_NFI_PIV-I-X/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/54_Golden_FIPS_201-2_NFI_PIV-I/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/55_FIPS_201-2_Missing_Security_Object/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/56_FIPS_201-2_Signer_Expires/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/57_Revoked_CHUID_Cert/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gsa-icam-card-builder/cards/ICAM_Card_Objects/58_Revoked_Card_Auth_Cert/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt")
				);

	}
}
