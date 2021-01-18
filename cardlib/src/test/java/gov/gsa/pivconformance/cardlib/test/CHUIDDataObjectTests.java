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

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class CHUIDDataObjectTests {
	private static String resDir = null;
    static {
        try {
            URI uri = ClassLoader.getSystemResource("").toURI();
            resDir = Paths.get(uri).toString();
        } catch (URISyntaxException e) {
            e.printStackTrace(); 
        }
        System.out.println("Looking in: " + resDir);
    }

    @DisplayName("Test CHUID Data Object parsing")
    @ParameterizedTest(name = "{index} => oid = {0}, file = {1}")
    //@MethodSource("dataObjectTestProvider")
    void dataObjectTest(String oid, String file, TestReporter reporter) {
        assertNotNull(oid);
        assertNotNull(file);
        Path filePath = Paths.get(resDir + File.separator + file);
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
        boolean decoded = o.decode();
        assert(decoded);

        assertNotNull(((CardHolderUniqueIdentifier) o).getfASCN());
        assertNotNull(((CardHolderUniqueIdentifier) o).getgUID());
        assertNotNull(((CardHolderUniqueIdentifier) o).getExpirationDate());

        assertNotNull(((SignedPIVDataObject) o).getAsymmetricSignature());

        ((SignedPIVDataObject) o).verifySignature();
        assertNotNull(((SignedPIVDataObject) o).getSignerCert());

        assertTrue(((CardHolderUniqueIdentifier) o).getErrorDetectionCode());
    }

    private static Stream<Arguments> dataObjectTestProvider() {
        return Stream.of(
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/02_Golden_PIV-I/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/03_SKID_Mismatch/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/04_Tampered_CHUID/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/05_Tampered_Certificates/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/06_Tampered_PHOTO/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/07_Tampered_Fingerprints/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/08_Tampered_Security_Object/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/09_Expired_CHUID_Signer/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/10_Expired_Cert_Signer/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/11_Certs_Expire_after_CHUID/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/12_Certs_not_yet_valid/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/13_Certs_are_expired/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/14_Expired_CHUID/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/15_CHUID_FASCN_mismatch/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/16_Card_Authentication_FASCN_mismatch/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/17_PHOTO_FASCN_mismatch/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/18_Fingerprints_FASCN_mismatch/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/19_CHUID_UUID_mismatch/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/20_Card_Authent_UUID_mismatch/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/21_PHOTO_UUID_mismatch/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/22_Fingerprints_UUID_mismatch/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/23_Public_Private_Key_mismatch/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/24_Revoked_Certificates/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/25_Disco_Object_Not_Present/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/26_Disco_Object_Present_App_PIN_Only/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/27_Disco_Object_Present_App_PIN_Primary/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/28_Disco_Object_Present_Global_PIN_Primary/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/38_Bad_Hash_in_Sec_Object/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/39_Golden_FIPS_201-2_Fed_PIV-I/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/41_Re-keyed_Card/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/42_OCSP_Expired/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/43_OCSP_revoked_w_nocheck/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/44_OCSP_revoked_wo_nocheck/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/45_OCSP_Invalid_Signature/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/47_Golden_FIPS_201-2_PIV_SAN_Order/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/48_T=0_with_Non-Zero_PPS_LEN_Value/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/49_FIPS_201-2_Facial_Image_CBEFF_Expired/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/50_FIPS_201-2_Facial_Image_CBEFF_Expires_before_CHUID/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/51_FIPS_201-2_Fingerprint_CBEFF_Expired/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/52_FIPS_201-2_Fingerprint_CBEFF_Expires_before_CHUID/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/53_FIPS_201-2_Large_Card_Auth_Cert/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/54_Golden_FIPS_201-2_NFI_PIV-I/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/55_FIPS_201-2_Missing_Security_Object/8 - CHUID Object"),
                Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                        "gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/cards/ICAM_Card_Objects/56_FIPS_201-2_Signer_Expires/8 - CHUID Object")
                );
    }
}
