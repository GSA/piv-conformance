package gov.gsa.pivconformancetest;

import gov.gsa.pivconformance.card.client.*;
import gov.gsa.pivconformance.utils.PCSCUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestReporter;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class PIVSignatureVerificationTests {
	List<CardTerminal> terminals = null;
	DefaultPIVApplication piv = null;

	@BeforeEach
	void init() {
		PCSCUtils.ConfigureUserProperties();
		TerminalFactory tf = TerminalFactory.getDefault();
		try {
			terminals = tf.terminals().list();
		} catch (CardException e) {
			fail("Unable to list readers");
		}
	}

	@Test
	@DisplayName("Ensure readers")
	void testReaderList() {
		assert (terminals.size() > 0);
	}

	@Test
	@DisplayName("Test signature verfication")
	void testPIVGetData(TestReporter reporter) {
		X509Certificate signingCertificate = null;
		ConnectionDescription cd = ConnectionDescription.createFromTerminal(terminals.get(0));
		try {
			assert (terminals.get(0).isCardPresent());
		} catch (CardException ce) {
			fail(ce);
		}
		CardHandle ch = new CardHandle();
		MiddlewareStatus result = PIVMiddleware.pivConnect(true, cd, ch);
		assertEquals(result, MiddlewareStatus.PIV_OK);
		piv = new DefaultPIVApplication();
		ApplicationAID aid = new ApplicationAID();
		ApplicationProperties cardAppProperties = new ApplicationProperties();
		result = piv.pivSelectCardApplication(ch, aid, cardAppProperties);
		assertEquals(MiddlewareStatus.PIV_OK, result);
		PIVAuthenticators authenticators = new PIVAuthenticators();
		authenticators.addApplicationPin("123456");
		result = piv.pivLogIntoCardApplication(ch, authenticators.getBytes());
		assertEquals(MiddlewareStatus.PIV_OK, result);

		for (String containerOID : APDUConstants.MandatoryContainers()) {
			PIVDataObject dataObject = PIVDataObjectFactory.createDataObjectForOid(containerOID);

			result = piv.pivGetData(ch, containerOID, dataObject);
			assertEquals(MiddlewareStatus.PIV_OK, result);

			boolean decoded = dataObject.decode();
			assertEquals(true, decoded);

			if (containerOID.equals(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID)) {
				signingCertificate = ((SignedPIVDataObject) dataObject).getChuidSignerCert();
				CMSSignedData sd = ((CardHolderUniqueIdentifier) dataObject).getAsymmetricSignature();
				assertNotNull(sd);
				boolean rv = ((CardHolderUniqueIdentifier) dataObject).verifySignature();
				assertEquals(true, rv);

				signingCertificate = ((SignedPIVDataObject) dataObject).getChuidSignerCert();

				assertNotNull(signingCertificate);
			}

			if (containerOID.equals(APDUConstants.CARDHOLDER_FINGERPRINTS_OID)) {
				signingCertificate = ((SignedPIVDataObject) dataObject).getSignerCert();
				if (signingCertificate != null) {
					boolean rv = ((SignedPIVDataObject) dataObject).verifySignature();
					assertEquals(true, rv);
				}
			}

			if (containerOID.equals(APDUConstants.SECURITY_OBJECT_OID)) {
				signingCertificate = ((SignedPIVDataObject) dataObject).getSignerCert();
				if (signingCertificate != null) {
					boolean rv = ((SignedPIVDataObject) dataObject).verifySignature();
					assertEquals(true, rv);
				}
			}

			if (containerOID.equals(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID)) {
				signingCertificate = ((SignedPIVDataObject) dataObject).getSignerCert();
				if (signingCertificate != null) {
					boolean rv = ((SignedPIVDataObject) dataObject).verifySignature();
					assertEquals(true, rv);
				}
			}
		}
	}
}
