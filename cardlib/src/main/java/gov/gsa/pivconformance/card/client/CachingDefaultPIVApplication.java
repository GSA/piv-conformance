package gov.gsa.pivconformance.card.client;

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CachingDefaultPIVApplication extends DefaultPIVApplication {
    private static final Logger s_logger = LoggerFactory.getLogger(CachingDefaultPIVApplication.class);
    
    HashMap<String, byte[]> m_containerMap = new HashMap<String, byte[]>();

    // Cache the buffers coming back from pivGetData to minimize churn
	public MiddlewareStatus pivGetData(CardHandle cardHandle, String OID, PIVDataObject data) {
    	MiddlewareStatus result = MiddlewareStatus.PIV_OK;
    	byte[] dataBytes = m_containerMap.get(OID);
    	if(dataBytes == null) {
    		result = super.pivGetData(cardHandle, OID, data);
    		if(result == MiddlewareStatus.PIV_OK) {
    			m_containerMap.put(OID, data.getBytes());
    		}
    	} else {
    		data.setOID(OID);
    		data.setBytes(dataBytes);
    	}
    	return result;
    }
    
    public void clearCache() {
    	m_containerMap.clear();
    }
    
}
