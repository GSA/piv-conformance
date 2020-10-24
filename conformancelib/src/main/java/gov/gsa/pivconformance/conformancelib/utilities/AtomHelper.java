package gov.gsa.pivconformance.conformancelib.utilities;

import static org.junit.jupiter.api.Assertions.fail;

import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.cardlib.card.client.CardHandle;
import gov.gsa.pivconformance.cardlib.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.cardlib.card.client.CardHolderBiometricData;
import gov.gsa.pivconformance.cardlib.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.cardlib.card.client.SecurityObject;
import gov.gsa.pivconformance.cardlib.card.client.SignedPIVDataObject;
import gov.gsa.pivconformance.cardlib.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.pivconformance.conformancelib.tests.ConformanceTestException;

public class AtomHelper {
    private static final Logger s_logger = LoggerFactory.getLogger(AtomHelper.class);

    /**
    * Helper function that retrieves a data object from the card based on the container OID
    * and performs certain pre-screening functions for atoms.
    * 
    * @param OID String containing OID value identifying data object whose data content is to be
    * retrieved
    * @param data PIVDataObject object that will store retrieved data content
    * @return MiddlewareStatus value indicating the result of the function call
    */
	public static PIVDataObject getDataObject(String oid) {
				
		//Check that the oid passed in is not null
		if (oid == null) {
			ConformanceTestException e  = new ConformanceTestException("OID is null");
			fail(e);
		}
		
// This snippet can be used to target a folder full of containers
//		byte[] allBytes = null;
//		 try (
//		            InputStream inputStream = new FileInputStream("G:\\GSA\\GSA_GIT\\piv-conformance-pkix-11\\tools\\85b-swing-gui\\85b-swing-gui-201907010300\\" + oid + ".bin");
//		            
//		        ) {
//		 
//		            long fileSize = new File("G:\\GSA\\GSA_GIT\\piv-conformance-pkix-11\\tools\\85b-swing-gui\\85b-swing-gui-201907010300\\" + oid + ".bin").length();
//		 
//		            allBytes = new byte[(int) fileSize];
//		 
//		            inputStream.read(allBytes);
//		 
//		        } catch (IOException ex) {
//		            ex.printStackTrace();
//		        }
//		 PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
//		 o.setOID(oid);
//         o.setBytes(allBytes);
//         
// 		if (o.decode() != true) {
//			ConformanceTestException e  = new ConformanceTestException("Failed to decode object for OID " + oid);
//			fail(e);
//		}
		
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		
		//Check that CardSettingsSingleton
		if (css == null) {
			ConformanceTestException e  = new
					ConformanceTestException("Singleton is null");
			fail(e);
		}
		
		if (css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
			ConformanceTestException e = new ConformanceTestException(
					"Login has already been attempted and failed. Not trying again.");
			fail(e);
		}
		
		try {
			CardUtils.setUpPivAppHandleInSingleton();
			if (APDUConstants.isProtectedContainer(oid))
				CardUtils.authenticateInSingleton(false); // TODO: Not always needed
		} catch (ConformanceTestException e) {
			fail(e);
		}

		// Get card handle and PIV handle
		CardHandle ch = css.getCardHandle();
		
		if (ch == null) {
			ConformanceTestException e  = new
					ConformanceTestException("Failed to obtain valid card handle");
			fail(e);
		}
		
		AbstractPIVApplication piv = css.getPivHandle();

		if (piv == null) {
			ConformanceTestException e  = new
					ConformanceTestException("Failed to obtain valid PIV handle");
			fail(e);
		}
		// Created an object corresponding to the OID value
		PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
		
		if (o == null) {
			ConformanceTestException e  = new ConformanceTestException("Failed to allocate PIVDataObject");
			fail(e);
		}

		// Get data from the card corresponding to the OID value
		MiddlewareStatus result = piv.pivGetData(ch, oid, o);
		
		switch (result) {
		case PIV_DATA_OBJECT_NOT_FOUND:	// Only fail mandatory containers 
			if (APDUConstants.isContainerMandatory(oid)) {
				ConformanceTestException e  = new ConformanceTestException("Failed to find " + APDUConstants.oidNameMap.get(oid) + " container");
				fail(e);
			}
			break;
		case PIV_OK:
			break;
		default:
			ConformanceTestException e  = new ConformanceTestException("Failed to retrieve data object for OID " + oid + " from the card");
			fail(e);				
		}

		if (o.decode() != true) {
			ConformanceTestException e  = new ConformanceTestException("Failed to decode object for OID " + oid);
			fail(e);
		}
		
		if ((o instanceof SignedPIVDataObject) && ((SignedPIVDataObject) o).getCertCount() > 1) {
			ConformanceTestException e  = new ConformanceTestException("More than one cert found in " + APDUConstants.oidNameMap.get(oid) + " container");
			fail(e);			
		}
		
		return o;		
	}
	
	/**
	 * Get a certificate from a container specified by oid. For the CHUID and Security Object containers
	 * the certificate will be the CHUID content signer cerificate.  For biometrics, the cerificate will be
	 * either the cert in the CMS cert bag *or* the CHUID content signer certificate.  For X509 certificates,
	 * the certificate is in Tag 70.
	 * @param pivDataObject o the PIV data object being processed
	 * @param oid the OID for the container
	 * @return Certificate from container
	 */
	public static X509Certificate getCertificateForContainer(PIVDataObject pivDataObject) {
		X509Certificate cert = null;
		if (pivDataObject instanceof CardHolderUniqueIdentifier ||
			pivDataObject instanceof CardHolderBiometricData ||
			pivDataObject instanceof SecurityObject) {
			cert = ((SignedPIVDataObject) pivDataObject).hasOwnSignerCert() ? 
					((SignedPIVDataObject) pivDataObject).getSignerCert() : 
					((SignedPIVDataObject) pivDataObject).getChuidSignerCert();
		} else {
			cert = ((X509CertificateDataObject) pivDataObject).getCertificate();
		}
		s_logger.debug(cert.toString());
		return cert;
	}
	
	public static CMSSignedData getSignedDataForObject(SignedPIVDataObject o) {
		CMSSignedData rv = null;
		if(!o.isSigned()) {
			return null;
		}
		rv = o.getAsymmetricSignature();
		return rv;
	}
	
	/***
	 * Quick helper function to determine whether to run the atom
	 * @param oid Container OID
	 * @return true if this container is optional and absent (and can be skipped)
	 */

	public static boolean isOptionalAndAbsent(String oid) {
		if(!APDUConstants.isContainerMandatory(oid) && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return true;
		}
		return false;
	}
	
	/**
	 * 
	 * Helper function that checks whether a data object is present based on
	 * container OID, possibly authenticating to the card along the way.
	 * 
	 * This function will only throw RuntimeErrors and will not cause an atom to fail
	 * 
	 * @param OID  String containing OID value identifying data object whose data
	 *             content is to be retrieved
	 * @param authenticate controls whether the helper will attempt to log in
	 * @return true if the object was found, false otherwise
	 */
	public static boolean isDataObjectPresent(String oid, boolean authenticate) {
		// Check that the oid passed in is not null
		if (oid == null) {
			throw new IllegalArgumentException("isDataObjectPresent called with null oid");
		}

		CardSettingsSingleton css = CardSettingsSingleton.getInstance();

		// Check that CardSettingsSingleton
		if (css == null) {
			s_logger.error("isDataObjectPresent({},{}) called, but couldn't get an instance of CardSettingsSingleton", oid, authenticate);
			return false;
		}

		if (authenticate && css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
			s_logger.error("isDataObjectPresent({},{}) called, but login has already been attempted unsuccessfully", oid, authenticate);
			return false;
		}

		if (authenticate) {
			try {
				CardUtils.setUpPivAppHandleInSingleton();
				CardUtils.authenticateInSingleton(false);
			} catch (ConformanceTestException e) {
				s_logger.error("isDataObjectPresent({},{}) called, but login failed with a ConformanceTestException", oid, authenticate, e);
				return false;
			} 
		}
		// Get card handle and PIV handle
		CardHandle ch = css.getCardHandle();

		if (ch == null) {
			s_logger.error("isDataObjectPresent({},{}) failed to obtain a valid card handle", oid, authenticate);
			return false;
		}

		AbstractPIVApplication piv = css.getPivHandle();

		if (piv == null) {
			s_logger.error("isDataObjectPresent({},{}) failed to obtain a valid PIV handle", oid, authenticate);
			return false;
		}
		
		// Created an object corresponding to the OID value
		PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);

		if (o == null) {
			s_logger.error("isDataObjectPresent() failed to allocate a PIVDataObject for {} {} authentication.", oid, authenticate ? "with":"without");
			return false;
		}

		// Get data from the card corresponding to the OID value
		MiddlewareStatus result = piv.pivGetData(ch, oid, o);

		if (result != MiddlewareStatus.PIV_OK) {
			s_logger.error("isDataObjectPresent() failed to get data for {} {} authentication: {}.", oid, authenticate ? "with":"without", result);
			return false;
		}

		// if we got here, the object is present and has now been cached. others can attempt a decode and complain if that fails
		return true;
	}
}
