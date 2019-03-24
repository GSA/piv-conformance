package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.cms.*;
import org.bouncycastle.util.Store;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.Calendar;
import java.util.Collection;
import java.security.Principal;
import java.security.cert.X509Certificate;

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
import gov.gsa.pivconformance.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;

public class CMSTests {

	//Verify that the asymmetric digital field contains a CMS signed data object with no encapsulated content
	@DisplayName("CMS.1 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_1(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        
        //Get card handle and PIV handle
        CardHandle ch = css.getCardHandle();
        AbstractPIVApplication piv = css.getPivHandle();
        
        //Created an object corresponding to the OID value
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
    	
        //Get data from the card corresponding to the OID value
        MiddlewareStatus result = piv.pivGetData(ch, oid, o);
        assertTrue(result == MiddlewareStatus.PIV_OK);
        	
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		//Confirm that no encapsulated content present
		assertTrue(issuerAsymmetricSignature.isDetachedSignature());
    }
	
	//Verify that version is set to 3
	@DisplayName("CMS.2 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_2(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        
        //Get card handle and PIV handle
        CardHandle ch = css.getCardHandle();
        AbstractPIVApplication piv = css.getPivHandle();
        
        //Created an object corresponding to the OID value
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
    	
        //Get data from the card corresponding to the OID value
        MiddlewareStatus result = piv.pivGetData(ch, oid, o);
        assertTrue(result == MiddlewareStatus.PIV_OK);
        	
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		//Confirm version is 3
		assertTrue(issuerAsymmetricSignature.getVersion() == 3);
    }
	
	//Validate signing key length
	@DisplayName("CMS.3 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_3(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        
        //Get card handle and PIV handle
        CardHandle ch = css.getCardHandle();
        AbstractPIVApplication piv = css.getPivHandle();
        
        //Created an object corresponding to the OID value
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
    	
        //Get data from the card corresponding to the OID value
        MiddlewareStatus result = piv.pivGetData(ch, oid, o);
        assertTrue(result == MiddlewareStatus.PIV_OK);
        	
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		//XXX Not entierly sure how to do this test
    }

	//Verify digestAlgorithms attribute is present and algorithm is present and consistent with signature algorithm
	@DisplayName("CMS.4 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_4(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        
        //Get card handle and PIV handle
        CardHandle ch = css.getCardHandle();
        AbstractPIVApplication piv = css.getPivHandle();
        
        //Created an object corresponding to the OID value
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
    	
        //Get data from the card corresponding to the OID value
        MiddlewareStatus result = piv.pivGetData(ch, oid, o);
        assertTrue(result == MiddlewareStatus.PIV_OK);
        	
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		//Confirm version is 3
		Set<AlgorithmIdentifier> digestAlgSet = issuerAsymmetricSignature.getDigestAlgorithmIDs();
		
		//Confirm that digestAlgorithms attribute is present and algorithm is present
		assertTrue(digestAlgSet.size() > 0);
		
		SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
		
		assertNotNull(signers);
		
		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();

			AlgorithmIdentifier algID = signer.getDigestAlgorithmID();
			
			assertTrue(digestAlgSet.contains(algID));
		}
    }
	
	//Ensure encapsulated content is absent and eContentType is id-piv-CHUIDSecurityContent in encapContentInfo
	@DisplayName("CMS.5 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_5(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        
        //Get card handle and PIV handle
        CardHandle ch = css.getCardHandle();
        AbstractPIVApplication piv = css.getPivHandle();
        
        //Created an object corresponding to the OID value
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
    	
        //Get data from the card corresponding to the OID value
        MiddlewareStatus result = piv.pivGetData(ch, oid, o);
        assertTrue(result == MiddlewareStatus.PIV_OK);
        	
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		//Confirm encapsulated content is absent
		assertTrue(issuerAsymmetricSignature.isDetachedSignature());
		
		
		ContentInfo contentInfo = ((CardHolderUniqueIdentifier) o).getContentInfo();
		
		ASN1ObjectIdentifier ct = contentInfo.getContentType();
		
		//XXX Couldn't find OID for  id-piv-CHUIDSecurityContent need to find it and put here
		assertTrue(ct.getId().compareTo("1.2.3.4.5.6.7.8.9") == 0);
		
		ASN1Encodable content = contentInfo.getContent();
		
		//Confirm that encapsulated content is absent
		assertTrue(content == null);
    }
	
	
	//Ensure CRLs field is absent in signed data structure
	@DisplayName("CMS.6 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_6(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        
        //Get card handle and PIV handle
        CardHandle ch = css.getCardHandle();
        AbstractPIVApplication piv = css.getPivHandle();
        
        //Created an object corresponding to the OID value
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
    	
        //Get data from the card corresponding to the OID value
        MiddlewareStatus result = piv.pivGetData(ch, oid, o);
        assertTrue(result == MiddlewareStatus.PIV_OK);
        	
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		//Confirm encapsulated content is absent
		assertTrue(issuerAsymmetricSignature.isDetachedSignature());
		
		Store<?> crlStore = issuerAsymmetricSignature.getCRLs();
		
		
		Collection<?> crlColl = crlStore.getMatches(null);
		
		assertTrue(crlColl.size() == 0);
    }
	
	//Verify SignerInfos contains only a single signerInfo
	@DisplayName("CMS.7 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_7(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        
        //Get card handle and PIV handle
        CardHandle ch = css.getCardHandle();
        AbstractPIVApplication piv = css.getPivHandle();
        
        //Created an object corresponding to the OID value
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
    	
        //Get data from the card corresponding to the OID value
        MiddlewareStatus result = piv.pivGetData(ch, oid, o);
        assertTrue(result == MiddlewareStatus.PIV_OK);
        	
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
		
		assertNotNull(signers);
		
		//Confirm only one signer is present
		assertTrue(signers.size() == 1);

    }
	
	//Ensure that the signerId uses ths IssuerAndSerialNumber choice
	@DisplayName("CMS.8 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_8(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        
        //Get card handle and PIV handle
        CardHandle ch = css.getCardHandle();
        AbstractPIVApplication piv = css.getPivHandle();
        
        //Created an object corresponding to the OID value
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
    	
        //Get data from the card corresponding to the OID value
        MiddlewareStatus result = piv.pivGetData(ch, oid, o);
        assertTrue(result == MiddlewareStatus.PIV_OK);
        	
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
		
		assertNotNull(signers);
		

		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();

			SignerId signerId = signer.getSID();
			
			//Confirm issuer and serial number are present 
			assertNotNull(signerId.getIssuer());
			assertNotNull(signerId.getSerialNumber());
			
			//Confirm SKID is absent
			assertTrue(signerId.getSubjectKeyIdentifier() == null);
			
		}		
    }
	
	//Ensure that the Issuer and Serial in the signer info corresponds to the issuer and serial values in the signer's certificate
	@DisplayName("CMS.9 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_9(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        
        //Get card handle and PIV handle
        CardHandle ch = css.getCardHandle();
        AbstractPIVApplication piv = css.getPivHandle();
        
        //Created an object corresponding to the OID value
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
    	
        //Get data from the card corresponding to the OID value
        MiddlewareStatus result = piv.pivGetData(ch, oid, o);
        assertTrue(result == MiddlewareStatus.PIV_OK);
        	
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		assertNotNull(signingCert);
		
		SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
		
		assertNotNull(signers);
		

		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();

			SignerId signerId = signer.getSID();
			assertNotNull(signerId.getIssuer());
			assertNotNull(signerId.getSerialNumber());
			
			//Confirm seral from the cert matched serial from signer info
			assertTrue(signingCert.getSerialNumber().compareTo(signerId.getSerialNumber()) == 0);
			
			Principal issuerFromCert = signingCert.getIssuerDN();
			X500Name tmp = new X500Name(issuerFromCert.getName());
			
			//XXX Is this the right style??
			X500NameStyle style = RFC4519Style.INSTANCE;
			
			//Confirm issuer from the cert matcher issuer from the signer info
			assertTrue(style.areEqual(signerId.getIssuer(), tmp));
			
		}		
    }
	
	//Confirm that piv interim extension is present
	@DisplayName("CMS.10 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_10(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        
        //Get card handle and PIV handle
        CardHandle ch = css.getCardHandle();
        AbstractPIVApplication piv = css.getPivHandle();
        
        //Created an object corresponding to the OID value
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
    	
        //Get data from the card corresponding to the OID value
        MiddlewareStatus result = piv.pivGetData(ch, oid, o);
        assertTrue(result == MiddlewareStatus.PIV_OK);
        	
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		assertNotNull(signingCert);
		
		SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
		
		assertNotNull(signers);
		
		//XXX Two questions about this tests.  Is the extension need to be found in the signing certificate?  What is the oid for piv interum 
		byte[] pivInterim = signingCert.getExtensionValue("2.5.29.32");
		
		//Confirm the extension is not null
		assertNotNull(pivInterim);
    }
	
	private static Stream<Arguments> CMS_TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID));

	}

}
