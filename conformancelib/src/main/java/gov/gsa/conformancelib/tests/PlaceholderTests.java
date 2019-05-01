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
import gov.gsa.conformancelib.utilities.AtomHelper;
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
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode(), "Couldn't decode " + oid);
		
		// TODO: Assert something meaningful here
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}

	// Only if it's a cat, dog, or elephant, shall it jump over the moon 
	// CCT parameter Type 2 model (one parameter, which could be a comma-separated list, multi-select [OR])
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("placeholderTestProvider")
	@DisplayName("PlaceholderTestParamType1Model.2 Test")
	void PlaceholderTestParamType2Model_1(String oid, String params, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

		// TODO: Decode params into a List
		
		
		
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode());	

		// TODO: The assertion that this atom wants to make.  
		// This is an example of the only other allowed assertion.
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}

	// If it's a cat, it must be:sleepy, if it's a dog, it must be:hungry, if it's an elephant:sad
	// Model for CCT test parameter type 3 (comma-separated list of parameters, with each parameter being a name:value pair)
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("placeholderTestProvider")
	@DisplayName("PlaceholderTestParamType1Model.2 Test")
	void PlaceholderTestParamType3Model_1(String oid, String params, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

		// TODO: Decode params into a List
		
		
		
		
		// The first of 2 allowed assertions
		assertTrue(o.decode());	

		// TODO: The assertion that this atom wants to make.  
		// This is merely an example of the second allowed assertion.
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
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
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode(), "Couldn't decode " + oid);
		
		// TODO: Assert something meaningful here
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}
	
	// Only if it's a cat, dog, or elephant, shall it jump over the moon 
	// CCT parameter Type 2 model (one parameter, which could be a comma-separated list, multi-select [OR])
	@DisplayName("PlaceholderTest.2 Test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("placeholderTestProvider")
	void PlaceholderTest_2(String oid, String params, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

		// TODO: Decode params into a List
		
		
		
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode());	

		// TODO: The assertion that this atom wants to make.  
		// This is an example of the only other allowed assertion.
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}
	
	// Model for CCT test parameter type 3 (comma-separated list of parameters, with each parameter being a name:value pair)
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("placeholderTestProvider")
	@DisplayName("PlaceholderTest.3 Test")
	void PlaceholderTest_3(String oid, String params, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

		// TODO: Decode params into a List
		
		
		
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode());	

		// TODO: The assertion that this atom wants to make.  
		// This is an example of the only other allowed assertion.
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}

	// TODO: @Geoff, need a generic provider or two so that we can unit test this
}
