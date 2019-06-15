package gov.gsa.conformancelib.utilities;

import static org.junit.jupiter.api.Assertions.fail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.conformancelib.tests.ConformanceTestException;
import gov.gsa.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;

public class AtomHelper {
    private static final Logger s_logger = LoggerFactory.getLogger(AtomHelper.class);

    
    /**
    * Helper function that retrieves  a data object from the card based on the container OID
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

		if (result != MiddlewareStatus.PIV_OK) {
			ConformanceTestException e  = new
					ConformanceTestException("Failed to retrieve data object for OID " + oid + " from the card");
			fail(e);
		}

		if (o.decode() != true) {
			ConformanceTestException e  = new ConformanceTestException("Failed to decode object for OID " + oid);
			fail(e);
		}
		
		return o;		
	}
	
    /**
    * 
    * Helper function that retrieves  a data object from the card based on the container OID, authenticating to the
    * card along the way
    * 
    * @param OID String containing OID value identifying data object whose data content is to be
    * retrieved
    * @param data PIVDataObject object that will store retrieved data content
    * @return MiddlewareStatus value indicating the result of the function call
    */
	public static PIVDataObject getDataObjectWithAuth(String oid) {
		
		//Check that the oid passed in is not null
		if (oid == null) {
			ConformanceTestException e  = new ConformanceTestException("OID is null");
			fail(e);
		}
		
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
			CardUtils.authenticateInSingleton(false);
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

		if (result != MiddlewareStatus.PIV_OK) {
			ConformanceTestException e  = new
					ConformanceTestException("Failed to retrieve data object for OID " + oid + " from the card");
			fail(e);
		}

		if (o.decode() != true) {
			ConformanceTestException e  = new ConformanceTestException("Failed to decode object for OID " + oid);
			fail(e);
		}
		
		return o;		
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
