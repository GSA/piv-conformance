package gov.gsa.conformancelib.tests;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;

public class PlaceholderTests {

	public PlaceholderTests() {
	}
	
	/*
	 * +-----------------------------------------------------------------------------------+
	 * |             Atom Prototypes Based on Parameter-passing Attributes                 |
	 * | Implementations of atoms waiting to be placed into their appropriate test classes |
	 * +-----------------------------------------------------------------------------------+
	 */

	// The cat shall jump over the moon...
	// CCT parameter Type 1 (no parameters - single purpose)
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("placeholderTestProvider")
	@DisplayName("PlaceholderTestParamType1Model.1 Test")
	void PlaceholderTestParamType1Model_1 (String oid, TestReporter reporter) {
		assertNotNull(null);
	}

	// Only if it's a cat, dog, or elephant, shall it jump over the moon 
	// CCT parameter Type 2 model (one parameter, which could be a comma-separated list, multi-select [OR])
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("placeholderTestProvider")
	@DisplayName("PlaceholderTestParamType1Model.2 Test")
	void PlaceholderTestParamType2Model_1(String oid, String params, TestReporter reporter) {
		
		PIVDataObject o = null;
		
		// Orthogonal for coding style is more extensible and better isolates actual test cases
		// Note: From here to </snip> will be put into a separate class (issue #80)

		if (oid == null) {
			ConformanceTestException e  = new ConformanceTestException("OID is null");
			fail(e);
		}
		if (params == null) {
			ConformanceTestException e  = new
					ConformanceTestException("Parameter is null");
			fail(e);
		}
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		if (css == null) {
			ConformanceTestException e  = new
					ConformanceTestException("Singleton is null");
			fail(e);
		}
		if (css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
			ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
			fail(e);
		}
			
		try {
			CardUtils.setUpPivAppHandleInSingleton();
			o = PIVDataObjectFactory.createDataObjectForOid(oid);
			if (o == null) {
				ConformanceTestException e  = new ConformanceTestException("Failed to allocate PIVDataObject");
				fail(e);
			}
		} catch (ConformanceTestException e) {
			fail(e);
		}
		
		AbstractPIVApplication piv = css.getPivHandle();
		
		if (piv == null) {
			ConformanceTestException e  = new ConformanceTestException("Failed to obtain valid PIV handle");
			fail(e);
		}
		
		CardHandle c = css.getCardHandle();
		if (c == null) {
			ConformanceTestException e  = new ConformanceTestException("Failed to obtain valid card handle");
			fail(e);
		}

		// Caching this coming soon!
		MiddlewareStatus result = MiddlewareStatus.PIV_OK;
		
		result = piv.pivGetData(c, oid, o);
		if (result == null) {
			ConformanceTestException e  = new
					ConformanceTestException("Internal error");
			fail(e);
		}

		if (o.decode() != true) {
			ConformanceTestException e  = new ConformanceTestException("Failed to decode object for OID " + oid);
			fail(e);
		}
		// </snip>
		
		// This particular example could have been just any data object
		// The object 
		
		// PIVDataObject pdo = PIVDataObjectFactory.createDataObjectForOid(oid);
		//
		// if (pdo == null) {
		//		ConformanceTestException e  = new ConformanceTestException("Object for OID " + oid + " is null");
		//		fail(e);
		// }
		
		// Or, as in this example it can be a certificate.
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		if (cert == null) {
			ConformanceTestException e  = new
					ConformanceTestException("Certificate retrived from X509CertificateDataObject object is NULL");
			fail(e);
		}
		
		// The actual assertion code goes here.  Note that the object will NOT be null here.
		
		// Comma-separated list of zero or more OIDs

		List<String> policyOidList = new ArrayList<String>();
		String oidArray[] = params.split (",");
		for (String s : oidArray) {
			policyOidList.add(s);
		}
		byte[] policyOids = cert.getExtensionValue("2.5.29.32");
		
		// This is part of the test case - certificate must assert one of the requested OIDs
		// No need to split this.
		
		assertTrue (policyOids != null && oidArray.length > 0);

		// Cert has certificate policy extension and we're looking for one or more

		CertificatePolicies policies = null;
		try {
			// BC's fromExtensionValue throws an IOException.  Nice.
			policies = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(policyOids));
		} catch (IOException ex) {
			// If this fails, it's almost certainly an encoding error, but we'll currently assume a S/W issue
			// TODO: Revisit try/catch and NPE here
			ConformanceTestException e  = new ConformanceTestException("Could not obtain policies from extension");
			fail(e);
		}
		
		// The polices instance won't point to null here due to try/catch above
		
		boolean containsOOID = false;
		PolicyInformation[] policyInformation = policies.getPolicyInformation();
		for (PolicyInformation pInfo : policyInformation) {
			ASN1ObjectIdentifier curroid = pInfo.getPolicyIdentifier();
			if(policyOidList.contains(curroid.toString())) {
				containsOOID = true;
				break;
			}
		}
		assertTrue(containsOOID == true, "Did not directly assert acceptable certificate policy OID(s)" + params);		
	}

	// If it's a cat, it must be:sleepy, if it's a dog, it must be:hungry, if it's an elephant:sad
	// Model for CCT test parameter type 3 (comma-separated list of parameters, with each parameter being a name:value pair)
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("placeholderTestProvider")
	@DisplayName("PlaceholderTestParamType1Model.2 Test")
	void PlaceholderTestParamType3Model_1(String oid, String params, TestReporter reporter) {
		// TODO: @Geoff - probably need to do this one soon
		
		
		
		
		// For now...
		assertNotNull(null);
	}

	/*
	 * +-------------------------- Concrete Test Atoms ------------------------------------+
	 * | Implementations of atoms waiting to be placed into their appropriate test classes |
	 * +-----------------------------------------------------------------------------------+
	 */
	
	// The cat shall jump over the moon...
	// CCT parameter Type 1 (no parameters - single purpose)
	@DisplayName("PlaceholderTest.1 Test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("placeholderTestProvider")
	void PlaceholderTest_1(String oid, TestReporter reporter) {
		assertNotNull(null);
	}
	
	// Only if it's a cat, dog, or elephant, shall it jump over the moon 
	// CCT parameter Type 2 model (one parameter, which could be a comma-separated list, multi-select [OR])
	@DisplayName("PlaceholderTest.2 Test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("placeholderTestProvider")
	void PlaceholderTest_2(String oid, String params, TestReporter reporter) {
		

	}
	
	// Model for CCT test parameter type 3 (comma-separated list of parameters, with each parameter being a name:value pair)
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("placeholderTestProvider")
	@DisplayName("PlaceholderTest.3 Test")
	void PlaceholderTest_3(String oid, String params, TestReporter reporter) {
		assertNotNull(null);
	}

	// TODO: @Geoff, need a generic provider or two so that we can unit test this
}
