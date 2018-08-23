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
     * @param cardHandle Opaque identifier of the card to be acted upon as
     * returned by pivConnect.
     * @param applicationAID The AID of the PIV Card Application that is to
     * become the currently selected card application.
     * @param applicationProperties The application properties of the selected PIV
     * Card Application. See Part 2, Table 3.
     * @return MiddlewareStatus value indicating the result of the function call
     */
    MiddlewareStatus pivSelectCardApplication(CardHandle cardHandle, ApplicationAID applicationAID, ApplicationProperties applicationProperties);

    /**
     * pivEstablishSecureMessaging from SP800-73-4 part 3 section 3.2.2
     * @param cardHandle Opaque identifier of the card to be acted upon as
     *      * returned by pivConnect.
     * @return MiddlewareStatus value indicating the result of the function call
     */
    MiddlewareStatus pivEstablishSecureMessaging(CardHandle cardHandle);

    /**
     * pivLogIntoCardApplication from SP800-73-4 part 3 section 3.2.3
     *
     * @param cardHandle Opaque identifier of the card to be acted upon as returned by pivConnect.
     * @param authenticators A sequence of zero or more BER-TLV encoded authenticators to be used to authenticate and set security
     * state/status in the PIV Card Application contex
     * @return MiddlewareStatus value indicating the result of the function call
     */
    MiddlewareStatus pivLogIntoCardApplication(CardHandle cardHandle, byte[] authenticators);

    /**
     * pivGetData from SP800-73-4 part 3 section 3.2.4
     * @param cardHandle Opaque identifier of the card to be acted upon as returned by pivConnect.
     * @param OID Object identifier of the object whose data content is to be
     * retrieved coded as a string
     * @param data Retrieved data content stored in PIVDataObject object
     * @return MiddlewareStatus value indicating the result of the function call
     */
    MiddlewareStatus pivGetData(CardHandle cardHandle, String OID, PIVDataObject data);

    /**
     * pivLogoutOfCardApplication from SP800-73-4 part 3 section 3.2.5 - reset application security status of PIV card application
     *
     * @param cardHandle Opaque identifier of the card to be acted upon as returned by pivConnect.
     * @return MiddlewareStatus value indicating the result of the function call
     */
    MiddlewareStatus pivLogoutOfCardApplication(CardHandle cardHandle);

    /**
     * pivCrypt from SP800-73-4 part 3 section 3.3.1
     *
     * @param cardHandle Opaque identifier of the card to be acted upon as returned by pivConnect.
     * @param algorithmIdentifier Identifier of the cryptographic algorithm to be used for
     * the cryptographic operation.
     * @param keyReference Identifier of the on-card key to be used for the
     * cryptographic operation.
     * @param algorithmInput Sequence of bytes used as the input to the cryptographic
     * operation stored in PIVDataObject object.
     * @param algorithmOutput Sequence of bytes output by the cryptographic operation stored in PIVDataObject object.
     * @return MiddlewareStatus value indicating the result of the function call
     */
    MiddlewareStatus pivCrypt(CardHandle cardHandle, byte algorithmIdentifier, byte keyReference, PIVDataObject algorithmInput, PIVDataObject algorithmOutput);

    /**
     *
     * pivPutData from SP800-73-4 part 3 section 3.4.1
     *
     * @param cardHandle Opaque identifier of the card to be acted upon as returned by pivConnect.
     * @param OID Object identifier of the object whose data content is to be
     * replaced coded as a String.
     * @param data Data to be used to replace in its entirety the data content
     * of the named data object stored in PIVDataObject object
     * @return MiddlewareStatus value indicating the result of the function call
     */
    MiddlewareStatus pivPutData(CardHandle cardHandle, String OID, PIVDataObject data);


    /**
     *
     * pivGenerateKeyPair from SP800-73-4 part 3 section 3.4.2
     *
     * @param cardHandle Opaque identifier of the card to be acted upon as returned by pivConnect.
     * @param keyReference The key reference of the generated key pair.
     * @param cryptographicMechanism The type of key pair to be generated.
     * @param publicKey BER-TLV data objects defining the public key
     * of the generated key pair stored in PIVDataObject object.
     * @return MiddlewareStatus value indicating the result of the function call
     */
    MiddlewareStatus pivGenerateKeyPair(CardHandle cardHandle, byte keyReference, byte cryptographicMechanism, PIVDataObject publicKey);
}
