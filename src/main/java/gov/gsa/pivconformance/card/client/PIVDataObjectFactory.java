package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PIVDataObjectFactory {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PIVDataObjectFactory.class);

    /**
     * Instantiate an appropriate PIVDataObject class given an OID, or a generic one in the absence of an OID
     *
     * @param OID
     * @return
     */
    public static PIVDataObject createDataObjectForOid(String OID) {
        return new PIVDataObject();
    }
}
