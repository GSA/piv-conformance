package gov.gsa.pivconformancetest;

import gov.gsa.pivconformance.card.client.*;
import gov.gsa.pivconformance.utils.OSUtils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class PrintedInformationDataObjectTests {
    @DisplayName("Test Printed Information Object Data Object parsing")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("dataObjectTestProvider")
    void dataObjectTest(String oid, String file, TestReporter reporter) {
        assertNotNull(oid);
        assertNotNull(file);
        Path filePath = Paths.get(OSUtils.getTempDir(), file);
        byte[] fileData = null;
        try {
            fileData = Files.readAllBytes(filePath);
        } catch (IOException e) {
            fail(e);
        }
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        reporter.publishEntry(oid, o.getClass().getSimpleName());

        byte[] data = APDUUtils.getTLV(APDUConstants.DATA, fileData);

        o.setOID(oid);
        o.setBytes(data);
        assert(o.decode());


        assertNotNull(((PrintedInformation) o).getName());
        assertNotNull(((PrintedInformation) o).getEmployeeAffiliation());
        assertNotNull(((PrintedInformation) o).getExpirationDate());
        assertNotNull(((PrintedInformation) o).getAgencyCardSerialNumber());
        assertNotNull(((PrintedInformation) o).getIssuerIdentification());

        assertNotSame(((PrintedInformation) o).getName(), "");
        assertNotSame(((PrintedInformation) o).getEmployeeAffiliation(), "");
        assertNotSame(((PrintedInformation) o).getExpirationDate(), "");
        assertNotSame(((PrintedInformation) o).getAgencyCardSerialNumber(), "");
        assertNotSame(((PrintedInformation) o).getIssuerIdentification(), "");
        assertTrue(((PrintedInformation) o).getErrorDetectionCode());
    }

    private static Stream<Arguments> dataObjectTestProvider() {
        return Stream.of(
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/25_Disco_Object_Not_Present/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/26_Disco_Object_Present_App_PIN_Only/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/27_Disco_Object_Present_App_PIN_Primary/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/28_Disco_Object_Present_Global_PIN_Primary/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/38_Bad_Hash_in_Sec_Object/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/39_Golden_FIPS_201-2_Fed_PIV-I/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/41_Re-keyed_Card/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/42_OCSP_Expired/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/43_OCSP_revoked_w_nocheck/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/44_OCSP_revoked_wo_nocheck/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/45_OCSP_Invalid_Signature/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/47_Golden_FIPS_201-2_PIV_SAN_Order/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/48_T=0_with_Non-Zero_PPS_LEN_Value/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/49_FIPS_201-2_Facial_Image_CBEFF_Expired/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/50_FIPS_201-2_Facial_Image_CBEFF_Expires_before_CHUID/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/51_FIPS_201-2_Fingerprint_CBEFF_Expired/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/52_FIPS_201-2_Fingerprint_CBEFF_Expires_before_CHUID/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/53_FIPS_201-2_Large_Card_Auth_Cert/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/54_Golden_FIPS_201-2_NFI_PIV-I/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/55_FIPS_201-2_Missing_Security_Object/11 - Printed Information"),
                Arguments.of(APDUConstants.PRINTED_INFORMATION_OID,
                        "cards/ICAM_Card_Objects/56_FIPS_201-2_Signer_Expires/11 - Printed Information")
                );
    }
}
