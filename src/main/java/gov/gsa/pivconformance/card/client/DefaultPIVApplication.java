package gov.gsa.pivconformance.card.client;

/**
 * A default implementation of the PIV application interface that will be used by the test harness in most cases.
 */
public class DefaultPIVApplication extends AbstractPIVApplication {
    @Override
    public MiddlewareStatus pivEstablishSecureMessaging(CardHandle cardHandle) {
        return null;
    }

    @Override
    public MiddlewareStatus pivPutData(CardHandle cardHandle, String OID, PIVDataObject data) {
        return null;
    }

    @Override
    public MiddlewareStatus pivGenerateKeyPair(CardHandle cardHandle, byte keyReference, byte cryptographicMechanism, PIVDataObject publicKey) {
        return null;
    }
}
