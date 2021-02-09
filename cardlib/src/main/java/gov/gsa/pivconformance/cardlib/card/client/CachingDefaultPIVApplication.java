package gov.gsa.pivconformance.cardlib.card.client;

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static gov.gsa.pivconformance.cardlib.card.client.APDUConstants.getFileNameForOid;

/**
 * PIV Application class that caches the contents of containers read from the card.
 */
public class CachingDefaultPIVApplication extends DefaultPIVApplication {
    private static final Logger s_logger = LoggerFactory.getLogger(CachingDefaultPIVApplication.class);
    
    static HashMap<String, byte[]> m_containerMap = new HashMap<String, byte[]>();
    
    // Cache the buffers coming back from pivGetData to minimize churn
	/**
	 * Obtains and caches the given container OID from the card
	 * @param cardHandle the card handle
	 * @param OID the container OID to retrieve
	 * @param data buffer to in which to store the card data
	 */
	@Override
	public MiddlewareStatus pivGetData(CardHandle cardHandle, String OID, PIVDataObject data) {
    	MiddlewareStatus result = MiddlewareStatus.PIV_OK;
    	byte[] dataBytes = m_containerMap.get(OID);
    	if(dataBytes == null) {  // Not cached
			result = super.pivGetData(cardHandle, OID, data);
			if (result == MiddlewareStatus.PIV_OK) {
				m_containerMap.put(OID, data.getBytes());
			}
		} else {
			data.setBytes(dataBytes);
		}

		data.setOID(OID);
		data.setContainerName(getFileNameForOid(OID));

    	return result;
    }
	
	/**
	 * Clears container cache
	 */
    public void clearCache() {
    	m_containerMap.clear();
    }    
}
