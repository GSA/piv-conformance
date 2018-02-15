package gov.gsa.pivconformance.card.client;

/**
 * This interface encapsulates the entry points for data access from SP800-73.
 *
 * Defined as an interface to allow per-card implementations to differ.
 *
 */
public interface IPIVApplication {

    /**
     * pivSelectCardApplication from SP800-73-4 part 3 section 3.2.1
     *
     * @param cardHandle
     * @param applicationAID
     * @param applicationProperties
     * @return
     */
    MiddlewareStatus pivSelectCardApplication(CardHandle cardHandle, ApplicationAID applicationAID, ApplicationProperties applicationProperties);

    /**
     * pivEstablishSecureMessaging from SP800-73-4 part 3 section 3.2.2
     * @param cardHandle
     * @return
     */
    MiddlewareStatus pivEstablishSecureMessaging(CardHandle cardHandle);

    /**
     * pivLogIntoCardApplication from SP800-73-4 part 3 section 3.2.3
     *
     * @param cardHandle
     * @param authenticators
     * @return
     */
    MiddlewareStatus pivLogIntoCardApplication(CardHandle cardHandle, byte[] authenticators);

    /**
     * pivGetData from SP800-73-4 part 3 section 3.2.4
     * @param cardHandle
     * @param OID
     * @param data
     * @return
     */
    MiddlewareStatus pivGetData(CardHandle cardHandle, String OID, PIVDataObject data);

    /**
     * pivLogoutOfCardApplication from SP800-73-4 part 3 section 3.2.5 - reset application security status of PIV card application
     *
     * @param cardHandle
     * @return
     */
    MiddlewareStatus pivLogoutOfCardApplication(CardHandle cardHandle);

    /**
     * pivCrypt from SP800-73-4 part 3 section 3.3.1
     *
     * @param cardHandle
     * @param algorithmIdentifier
     * @param keyReference
     * @param algorithmInput
     * @param algorithmOutput
     * @return
     */
    MiddlewareStatus pivCrypt(CardHandle cardHandle, byte algorithmIdentifier, byte keyReference, PIVDataObject algorithmInput, PIVDataObject algorithmOutput);

    /**
     *
     * pivPutData from SP800-73-4 part 3 section 3.4.1
     *
     * @param cardHandle
     * @param OID
     * @param data
     * @return
     */
    MiddlewareStatus pivPutData(CardHandle cardHandle, String OID, PIVDataObject data);


    /**
     *
     * pivGenerateKeyPair from SP800-73-4 part 3 section 3.4.2
     *
     * @param cardHandle
     * @param keyReference
     * @param cryptographicMechanism
     * @param publicKey
     * @return
     */
    MiddlewareStatus pivGenerateKeyPair(CardHandle cardHandle, byte keyReference, byte cryptographicMechanism, PIVDataObject publicKey);
}
