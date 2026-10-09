package gov.gsa.pivconformance.cardlib.test;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.APDUUtils;
import gov.gsa.pivconformance.cardlib.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.cardlib.card.client.SignedPIVDataObject;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class CHUIDDataObjectTests {
    @DisplayName("Test CHUID Data Object parsing")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("dataObjectTestProvider")
    void dataObjectTest(String oid, String file, TestReporter reporter) {
        assertNotNull(oid);
        assertNotNull(file);
        Path filePath = TestResourceUtils.path(file);
        byte[] fileData = null;
        try {
            fileData = Files.readAllBytes(filePath);
        } catch (IOException e) {
            fail(e);
        }
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        o.setContainerName(APDUConstants.getFileNameForOid(oid));
        reporter.publishEntry(oid, o.getClass().getSimpleName());

        byte[] data = APDUUtils.getTLV(APDUConstants.DATA, fileData);

        o.setOID(oid);
        o.setBytes(data);
        boolean decoded = o.decode();
        assertTrue(decoded);

        assertNotNull(((CardHolderUniqueIdentifier) o).getfASCN());
        assertNotNull(((CardHolderUniqueIdentifier) o).getgUID());
        assertNotNull(((CardHolderUniqueIdentifier) o).getExpirationDate());

        assertNotNull(((SignedPIVDataObject) o).getAsymmetricSignature());

        ((SignedPIVDataObject) o).verifySignature();
        assertNotNull(((SignedPIVDataObject) o).getSignerCert());

        assertTrue(o.getErrorDetectionCode());
    }

    private static Stream<Arguments> dataObjectTestProvider() {
        return Stream.of(
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/8 - CHUID Object")
        );
    }
}
