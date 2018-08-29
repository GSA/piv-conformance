package gov.gsa.pivconformancetest;

import gov.gsa.pivconformance.card.client.*;
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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CCCDataObjectTests {
    @DisplayName("Test CCC object parsing")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    @MethodSource("dataObjectTestProvider")
    void dataObjectTest(String oid, String file, TestReporter reporter) {
        assertNotNull(oid);
        assertNotNull(file);
        Path filePath = Paths.get("/tmp", file);
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

        assertTrue(((CardCapabilityContainer) o).getErrorDetectionCode());
    }

    private static Stream<Arguments> dataObjectTestProvider() {
        return Stream.of(
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/01_Golden_PIV/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/02_Golden_PIV-I/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/03_SKID_Mismatch/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/04_Tampered_CHUID/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/05_Tampered_Certificates/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/06_Tampered_PHOTO/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/07_Tampered_Fingerprints/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/08_Tampered_Security_Object/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/09_Expired_CHUID_Signer/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/10_Expired_Cert_Signer/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/11_Certs_Expire_after_CHUID/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/12_Certs_not_yet_valid/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/13_Certs_are_expired/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/14_Expired_CHUID/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/15_CHUID_FASCN_mismatch/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/16_Card_Auth_FASCN_mismatch/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/17_PHOTO_FASCN_mismatch/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/18_Fingerprints_FASCN_mismatch/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/19_CHUID_UUID_mismatch/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/20_Card_Auth_UUID_mismatch/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/21_PHOTO_UUID_mismatch/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/22_Fingerprints_UUID_mismatch/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/23_Public_Private_Key_mismatch/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/24_Revoked_Certificates/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/25_Disco_Object_Not_Present/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/26_Disco_Object_Present_App_PIN_Only/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/27_Disco_Object_Present_App_PIN_Primary/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/28_Disco_Object_Present_Global_PIN_Primary/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/38_Bad_Hash_in_Sec_Object/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/39_Golden_FIPS_201-2_Fed_PIV-I/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/41_Re-keyed_Card/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/42_OCSP_Expired/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/43_OCSP_revoked_w_nocheck/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/44_OCSP_revoked_wo_nocheck/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/45_OCSP_Invalid_Signature/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/47_Golden_FIPS_201-2_PIV_SAN_Order/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/48_T=0_with_Non-Zero_PPS_LEN_Value/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/49_FIPS_201-2_Facial_Image_CBEFF_Expired/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/50_FIPS_201-2_Facial_Image_CBEFF_Expires_before_CHUID/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/51_FIPS_201-2_Fingerprint_CBEFF_Expired/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/52_FIPS_201-2_Fingerprint_CBEFF_Expires_before_CHUID/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/53_FIPS_201-2_Large_Card_Auth_Cert/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/54_Golden_FIPS_201-2_NFI_PIV-I/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/55_FIPS_201-2_Missing_Security_Object/7 - CCC"),
                Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID,
                        "cards/ICAM_Card_Objects/56_FIPS_201-2_Signer_Expires/7 - CCC")
                );
    }
}
