package gov.gsa.pivconformance.cardlib.card.client;

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static gov.gsa.pivconformance.cardlib.card.client.APDUConstants.getFileNameForOid;

public class CachingDefaultPIVApplication extends DefaultPIVApplication {
    private static final Logger s_logger = LoggerFactory.getLogger(CachingDefaultPIVApplication.class);
    
    static HashMap<String, byte[]> m_containerMap = new HashMap<String, byte[]>();
    
    // Cache the buffers coming back from pivGetData to minimize churn
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
	 * Clear cache
	 */
    public void clearCache() {
    	m_containerMap.clear();
    }    
}
