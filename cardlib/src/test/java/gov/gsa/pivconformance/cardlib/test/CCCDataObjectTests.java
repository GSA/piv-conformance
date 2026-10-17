package gov.gsa.pivconformance.cardlib.test;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.APDUUtils;
import gov.gsa.pivconformance.cardlib.card.client.CardCapabilityContainer;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObjectFactory;
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
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CCCDataObjectTests {
    @DisplayName("Test CCC object parsing")
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

        assertNotNull(((CardCapabilityContainer) o).getCardIdentifier());
        assertNotNull(((CardCapabilityContainer) o).getCapabilityContainerVersionNumber());
        assertNotNull(((CardCapabilityContainer) o).getCapabilityGrammarVersionNumber());

        assertNotNull(((CardCapabilityContainer) o).getRegisteredDataModelNumber());
        assertNotNull(((CardCapabilityContainer) o).getAccessControlRuleTable());


        assertTrue(((CardCapabilityContainer) o).getCardAPDUs());

        assertTrue(((CardCapabilityContainer) o).getRedirectionTag());
        assertTrue(((CardCapabilityContainer) o).getCapabilityTuples());
        assertTrue(((CardCapabilityContainer) o).getStatusTuples());
        assertTrue(((CardCapabilityContainer) o).getNextCCC());

        assertTrue(o.getErrorDetectionCode());
    }

    private static Stream<Arguments> dataObjectTestProvider() {
        return Stream.of(
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/7 - CCC")
        );
    }
}
