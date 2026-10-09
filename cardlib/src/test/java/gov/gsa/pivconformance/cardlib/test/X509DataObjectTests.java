package gov.gsa.pivconformance.cardlib.test;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObjectFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class X509DataObjectTests {
	// [53 82 06 19 [70 82 06 10 [30 82 .. ]] [71 01 00] [FE 00]
	private byte[] insertOuterTag(byte[] databytes) {
		byte[] rv = null;
		rv = new byte[databytes.length + 13];
		short datalength = (short) databytes.length;
		rv[0] = (byte) 0x53;
		rv[1] = (byte) 0x82;
		rv[2] = (byte) (((datalength + 9) & 0xff00) >> 8);
		rv[3] = (byte) ((datalength + 9) & 0x00ff);
		rv[4] = (byte) 0x70;
		rv[5] = (byte) 0x82;
		rv[6] = (byte) ((datalength & 0xff00) >> 8);
		rv[7] = (byte) (datalength & 0x00ff);
		System.arraycopy(databytes, 0, rv, 8, datalength);
		rv[8 + datalength] = (byte) 0x71;
		rv[8 + datalength + 1] = (byte) 0x01;
		rv[8 + datalength + 2] = (byte) 0x00;
		rv[8 + datalength + 3] = (byte) 0xfe;
		rv[8 + datalength + 4] = (byte) 0x00;
		return rv;
	}

	@DisplayName("Test X.509 Data Object parsing")
	@ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
	@MethodSource("dataObjectTestProvider")

	void dataObjectTest(String oid, String file, TestReporter reporter) {
		assertNotNull(oid);
		assertNotNull(file);
		Path filePath = TestResourceUtils.path(file);
		List<String> lines = null;
		try {

			lines = Files.readAllLines(filePath);
			// Convert to DER
			StringBuffer sb = new StringBuffer();
			for (String l : lines) {
				sb.append(l + "\r\n");
			}
			StringReader sr = new StringReader(sb.toString());
			PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
			assertNotNull(o);
			o.setContainerName(APDUConstants.getFileNameForOid(oid));
			reporter.publishEntry(oid, o.getClass().getSimpleName());
			byte[] certBuf = convertPemFileToBytes(sr).getEncoded();
			o.setBytes(insertOuterTag(certBuf));

			//XXX Unit tests will need to be updated files here are just cert files not card data objects.

			o.setOID(oid);

			boolean decoded = o.decode();
			assertTrue(decoded);
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
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/3 - ICAM_PIV_Auth_SP_800-73-4.crt"),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt"),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/6 - ICAM_PIV_Card_Auth_SP_800-73-4.crt")
        );
    }
}
