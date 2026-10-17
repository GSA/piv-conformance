package gov.gsa.pivconformance.cardlib.test;

import gov.gsa.pivconformance.cardlib.card.client.DiscoveryObject;
import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
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

import static gov.gsa.pivconformance.cardlib.card.client.APDUConstants.DISCOVERY_OBJECT_OID;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class DODataObjectTests {
    @DisplayName("Test discovery object parsing")
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
        o.setOID(oid);
        o.setBytes(fileData);
        boolean decoded = o.decode();
        if (file.contains("/25_Disco_Object_Not_Present/")) {
            assertFalse(decoded, "A deliberately absent Discovery Object must not decode successfully");
            return;
        }
        assertTrue(decoded);

        assertNotNull(((DiscoveryObject) o).getSignedContent());
    }

    private static Stream<Arguments> dataObjectTestProvider() {
        return Stream.of(
                Arguments.of(DISCOVERY_OBJECT_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/1 - Discovery Object"),
                Arguments.of(DISCOVERY_OBJECT_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/1 - Discovery Object")
        );
    }
}
