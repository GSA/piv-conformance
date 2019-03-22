package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

public class X509DataObjectTests {
	
	//Container blob is no larger than 1905 bytes
    @DisplayName("SP800-73-4.18 testg")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_70_4_x509TestProvider")
    void sp800_73_4_Test_18(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		//XXX This seems too low for certificates
		assertTrue(bertlv.length <= 1905);
        
    }
    
    
	//Tags 0x70 and 0x71 are present in that order
    @DisplayName("SP800-73-4.19 testg")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_70_4_x509TestProvider")
    void sp800_73_4_Test_19(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
        
        
		List<BerTag> tagList = ((X509CertificateDataObject) o).getTagList();
		
		BerTag berCertTag = new BerTag(TagConstants.CERTIFICATE_TAG);
		BerTag berCertInfoTag = new BerTag(TagConstants.CERTINFO_TAG);
		
		assertTrue(tagList.contains(berCertTag));
		assertTrue(tagList.contains(berCertInfoTag));
		
		int tagIndex = tagList.indexOf(berCertTag);
		
		assertTrue(Arrays.equals(tagList.get(tagIndex).bytes,TagConstants.CERTIFICATE_TAG));
		assertTrue(Arrays.equals(tagList.get(tagIndex+1).bytes,TagConstants.CERTINFO_TAG));
        
        
    }
    
	//No tags other than (0x70, 0x71, 0x72, 0xFE) are present
    @DisplayName("SP800-73-4.22 testg")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_70_4_x509TestProvider")
    void sp800_73_4_Test_22(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
        
        
		List<BerTag> tagList = ((X509CertificateDataObject) o).getTagList();
		
		List<byte[]> allx509Tags = TagConstants.Allx509Tags();
		for(BerTag tag : tagList) {

			//Check that the tag is present in the all x509 tags list
			assertTrue(allx509Tags.contains(tag.bytes));
			
		}
        
        
    }

    
    private static Stream<Arguments> sp800_70_4_x509TestProvider() {
    	
    	return Stream.of(
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID)
                );

    }
}
