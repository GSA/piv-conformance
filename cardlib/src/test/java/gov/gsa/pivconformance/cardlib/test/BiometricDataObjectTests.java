package gov.gsa.pivconformance.cardlib.test;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.APDUUtils;
import gov.gsa.pivconformance.cardlib.card.client.CardHolderBiometricData;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.cardlib.card.client.SignedPIVDataObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BiometricDataObjectTests {
    @DisplayName("Test Biometric Data Object parsing")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("dataObjectTestProvider")
    void dataObjectTest(String oid, String file, TestReporter reporter) {
        assertNotNull(oid);
        assertNotNull(file);
        Path filePath = TestResourceUtils.path(file);
        System.out.println("Looking for " + filePath.getParent() + File.separator + filePath.getFileName());
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

        assertNotNull(((CardHolderBiometricData) o).getBiometricCreationDate());
        assertNotNull(((CardHolderBiometricData) o).getValidityPeriodFrom());
        assertNotNull(((CardHolderBiometricData) o).getValidityPeriodTo());

        assertNotSame(((CardHolderBiometricData) o).getBiometricCreationDate(), "");
        assertNotSame(((CardHolderBiometricData) o).getValidityPeriodFrom(), "");
        assertNotSame(((CardHolderBiometricData) o).getValidityPeriodTo(), "");

        assertNotNull(((SignedPIVDataObject) o).getAsymmetricSignature());

        assertTrue(o.getErrorDetectionCode());

    }

    private static Stream<Arguments> dataObjectTestProvider() {
        return Stream.of(
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/9 - Fingerprints"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/10 - Face Object"),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID, "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/10 - Face Object")
        );
    }
}
