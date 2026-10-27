package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.cardlib.card.client.*;
import gov.gsa.pivconformance.cardlib.card.client.OtherName;
import gov.gsa.pivconformance.conformancelib.configuration.*;
import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.conformancelib.utilities.Validator;
import gov.gsa.pivconformance.cardlib.tlv.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignatureEncryptionAlgorithmFinder;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.launcher.*;
import org.junit.platform.launcher.core.*;
import javax.smartcardio.*;
import java.security.cert.CertificateFactory;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.sql.*;
import java.security.Security;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.*;
import java.util.stream.*;
import static org.junit.jupiter.api.Assertions.*;

/** Existing production rows -> TestCaseModel/TestStepModel -> argument provider ->
 * JUnit atom -> AtomHelper -> actual cardlib decoder. Only card acquisition is simulated.
 * Certificate field mutations isolate the legacy checks. Current key-profile
 * evidence uses valid self-signed certificates generated for each key boundary.
 */
@Tag("ExistingCctRegression")
public class ExistingCctRegressionTest {
    private static byte[] chuid;
    private static byte[] ccc;
    private static byte[] facialImage;
    private static String cardUrn;
    private static String holderUrn;
    private static KeyPair sanSigningKey;
    private static final Map<String, byte[]> keyProfileCertificates = new HashMap<>();
    private static final Map<String, byte[]> currentChuidObjects = new HashMap<>();
    // Retained only to build the Security Object with its required CHUID signing key.
    private static final Map<String, KeyPair> cmsKeys = new HashMap<>();
    private static final Map<String, X509Certificate> cmsCertificates = new HashMap<>();
    private static final Map<String, byte[]> cmsConsumerObjects = new HashMap<>();
    private static boolean addedProvider;

    @BeforeAll static void fixtures() throws Exception {
        // BC exposes encoded NULL parameters; SUN normalizes them to null.
        if (Boolean.getBoolean("cct.regressionBC")) {
            assertNull(Security.getProvider("BC"), "Run in an isolated test worker");
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
            addedProvider = true;
        }
        Path root = Path.of(System.getProperty("cct.repository"));
        Path fixture = root.resolve("cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/synthetic/chuid.bin");
        chuid = APDUUtils.getTLV(APDUConstants.DATA, Files.readAllBytes(fixture));
        ccc = Files.readAllBytes(fixture.resolveSibling("ccc.bin"));
        facialImage = APDUUtils.getTLV(APDUConstants.DATA,
                Files.readAllBytes(fixture.resolveSibling("face-header.bin")));
        CardCapabilityContainer decodedCcc = new CardCapabilityContainer();
        decodedCcc.setOID(APDUConstants.CARD_CAPABILITY_CONTAINER_OID);
        decodedCcc.setContainerName(APDUConstants.getFileNameForOid(APDUConstants.CARD_CAPABILITY_CONTAINER_OID));
        decodedCcc.setBytes(APDUUtils.getTLV(APDUConstants.DATA, ccc));
        assertTrue(decodedCcc.decode(), "Synthetic CCC must decode before testing current fields");
        CardHolderUniqueIdentifier decoded = new CardHolderUniqueIdentifier();
        decoded.setOID(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
        decoded.setBytes(chuid);
        assertTrue(decoded.decode(), "Synthetic CHUID must decode before testing UUID equality");
        ByteBuffer guid = ByteBuffer.wrap(decoded.getgUID());
        cardUrn = "urn:uuid:" + new UUID(guid.getLong(), guid.getLong());
        ByteBuffer holderBytes = ByteBuffer.wrap(decoded.getCardholderUUID());
        holderUrn = "urn:uuid:" + new UUID(holderBytes.getLong(), holderBytes.getLong());
        sanSigningKey = rsa(2048, RSAKeyGenParameterSpec.F4);
        for (String kind : List.of("plain", "EE", "32", "33", "unknown", "guid-first",
                "holder-absent", "holder-v1", "holder-v5", "holder-variant", "holder-short", "holder-before-date",
                "cms-sha384", "cms-rsa1024-sha256", "cms-rsa3072-sha256", "cms-rsa4096-sha384", "cms-rsa4096-sha256", "cms-p256-sha256", "cms-p256-sha384",
                "cms-p384-sha384", "cms-p384-sha256", "cms-p521-sha384", "cms-brainpool256-sha256", "cms-sha1", "date-month-13", "date-nonleap",
                "date-short", "date-leap", "date-nondigit", "date-nonascii", "guid-delayed",
                "cms-combined-rsa-oid", "cms-corrupt-signature",
                "cms-pss-sha256-zero", "cms-pss-sha256-max", "cms-pss-sha256-excess",
                "cms-pss-sha384-zero", "cms-pss-sha384-max", "cms-pss-sha384-excess"))
            currentChuidObjects.put(kind, signedCurrentChuid(decoded, kind));
        keyProfileCertificates.put("rsa2048", currentCertificate(rsa(2048, RSAKeyGenParameterSpec.F4)));
        for (boolean caIssuers : new boolean[]{false, true}) {
            var aia = new AuthorityInformationAccess(new AccessDescription(
                    caIssuers ? AccessDescription.id_ad_caIssuers : AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, "http://example.invalid/issuer")));
            keyProfileCertificates.put(caIssuers ? "aia-caIssuers" : "aia-ocsp",
                    currentCertificate(sanSigningKey, "SHA256withRSA", false, aia));
        }
        keyProfileCertificates.put("rsa3072", currentCertificate(rsa(3072, RSAKeyGenParameterSpec.F4)));
        // A fixed, self-signed weak-key certificate is the intentional negative
        // input for the key-profile cases. The separate CMS size negative uses
        // an ephemeral 1024-bit test key, never written to disk or packaged.
        byte[] weakDer = Files.readAllBytes(root.resolve("conformancelib/testdata/weak-rsa1024-test-only.der"));
        X509Certificate weakCertificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(weakDer));
        weakCertificate.verify(weakCertificate.getPublicKey());
        keyProfileCertificates.put("rsa1024", APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{0x70}, weakDer), new byte[]{0x71, 1, 0, (byte) 0xfe, 0})));
        keyProfileCertificates.put("rsaExponent3", currentCertificate(rsa(2048, BigInteger.valueOf(3))));
        keyProfileCertificates.put("p256", currentCertificate(ec("secp256r1")));
        keyProfileCertificates.put("p384", currentCertificate(ec("secp384r1")));
        keyProfileCertificates.put("p521", currentCertificate(ec("secp521r1")));
        keyProfileCertificates.put("rsaSha384Signature", currentCertificate(rsa(2048, RSAKeyGenParameterSpec.F4), "SHA384withRSA"));
        keyProfileCertificates.put("rsaSha1Signature", currentCertificate(rsa(2048, RSAKeyGenParameterSpec.F4), "SHA1withRSA"));
        keyProfileCertificates.put("rsaPssSha384Signature", currentCertificate(rsa(2048, RSAKeyGenParameterSpec.F4), "SHA384withRSAandMGF1"));
        keyProfileCertificates.put("ecdsaNullParameters", currentCertificate(ec("secp384r1"), "SHA384withECDSA", true));
        KeyPair rsaSubject = rsa(2048, RSAKeyGenParameterSpec.F4);
        keyProfileCertificates.put("rsaEncryptionSubjectKey", subjectKeyCertificate(rsaSubject,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)));
        keyProfileCertificates.put("rsaPssSubjectKey", subjectKeyCertificate(rsaSubject,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS)));
        KeyPair ecSubject = ec("secp256r1");
        keyProfileCertificates.put("ecExplicitParameters", subjectKeyCertificate(ecSubject,
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.2.1"),
                        org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256r1"))));
        keyProfileCertificates.put("ecDhIdentifier", subjectKeyCertificate(ecSubject,
                new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.132.1.12"),
                        new ASN1ObjectIdentifier("1.2.840.10045.3.1.7"))));
        currentChuidObjects.put("cms-rsa-absent-parameters",
                chuidWithRsaCmsParameters(currentChuidObjects.get("plain"), null));
    }

    @AfterAll static void restoreProvider() {
        cmsKeys.clear();
        cmsCertificates.clear();
        if (addedProvider) Security.removeProvider("BC");
    }

    @ParameterizedTest
    @ValueSource(strings = {"PIV_Production_Cards.db", "PIV-I_Production_Cards.db"})
    void chuidExpirationFormatThroughExistingAtom(String database) throws Exception {
        run(database, 38, "sp800_73_4_Test_15", currentChuidObjects.get("plain"), true, "");
        run(database, 38, "sp800_73_4_Test_15", currentChuidObjects.get("date-leap"), true, "");
        run(database, 38, "sp800_73_4_Test_15", currentChuidObjects.get("date-month-13"),
                false, "CHUID expiration date must be an eight-digit valid YYYYMMDD date");
        run(database, 38, "sp800_73_4_Test_15", currentChuidObjects.get("date-nonleap"),
                false, "CHUID expiration date must be an eight-digit valid YYYYMMDD date");
        for (String kind : List.of("date-short", "date-nondigit", "date-nonascii"))
            run(database, 38, "sp800_73_4_Test_15", currentChuidObjects.get(kind),
                    false, "CHUID expiration date must be an eight-digit valid YYYYMMDD date");
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
            "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"})
    void expiryDescriptionMatchesTheOriginalProfileParameter(String database) throws Exception {
        int years = database.contains("ICAM") ? 15 : 6;
        Path path = Path.of(System.getProperty("cct.repository"), "conformancelib/testdata", database);
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:file:" + path + "?mode=ro")) {
            var row = new TestCaseModel(new ConformanceTestDatabase(c));
            row.retrieveForId(39);
            assertEquals("8.2.4", row.getIdentifier());
            assertEquals(1, row.getSteps().size());
            assertEquals("sp800_73_4_Test_16", row.getSteps().get(0).getTestMethodName());
            assertEquals(List.of(Integer.toString(years)), row.getSteps().get(0).getParameters());
            assertEquals("Expiration Date is within the next " + years + " years", row.getDescription());
        }
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
            "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"})
    void expiryWindowRetainsProductionAndIcamOutcomes(String database) throws Exception {
        int years = database.contains("ICAM") ? 15 : 6;
        var today = java.time.LocalDate.now();
        String method = "sp800_73_4_Test_16";
        // These controls stay away from the unchanged time-of-day boundaries.
        run(database, 39, method, chuidExpiringOn(today.plusYears(years).minusDays(2)), true, "");
        run(database, 39, method, chuidExpiringOn(today.minusDays(2)), false,
                "CHUID expiration date is before the test date");
        run(database, 39, method, chuidExpiringOn(today.plusYears(years).plusDays(2)), false,
                "CHUID expiration date is more than " + years + " years after the test date");
        run(database, 39, method, chuidExpiringOn(today.plusYears(10)), years == 15,
                "CHUID expiration date is more than 6 years after the test date");
    }

    private static byte[] chuidExpiringOn(java.time.LocalDate expiration) throws Exception {
        var base = new CardHolderUniqueIdentifier();
        base.setOID(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
        base.setBytes(currentChuidObjects.get("plain"));
        assertTrue(base.decode());
        String encoded = expiration.format(java.time.format.DateTimeFormatter.BASIC_ISO_DATE);
        byte[] raw = signedCurrentChuid(base, "date-value-" + encoded);
        assertArrayEquals(encoded.getBytes(java.nio.charset.StandardCharsets.US_ASCII), fixtureValue(raw, 0x35));
        return raw;
    }

    static Stream<Arguments> uuidCases() {
        return IntStream.of(369, 451).boxed().flatMap(row -> Stream.of(
                "match", "uppercase", "mismatch", "missing", "bare", "short", "wrong-name-type",
                "holder-before-card", "holder-after-card", "unrelated-uri-before-card", "fascn-only", "fascn-and-card")
                .map(kind -> Arguments.of(row, kind)));
    }

    @ParameterizedTest(name="production row {0}: UUID {1}") @MethodSource("uuidCases")
    void uuidThroughExistingAtom(int row, String kind) throws Exception {
        GeneralName match = new GeneralName(GeneralName.uniformResourceIdentifier, cardUrn);
        GeneralName holder = new GeneralName(GeneralName.uniformResourceIdentifier,
                "urn:uuid:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        GeneralName fascn = new GeneralName(GeneralName.otherName, new OtherName(
                new ASN1ObjectIdentifier("2.16.840.1.101.3.6.6"), new DEROctetString(fixtureValue(chuid, 0x30))));
        GeneralName[] names = switch (kind) {
            case "match" -> new GeneralName[]{match};
            case "fascn-only" -> new GeneralName[]{fascn};
            case "fascn-and-card" -> new GeneralName[]{fascn, match};
            case "uppercase" -> new GeneralName[]{new GeneralName(6, cardUrn.toUpperCase(Locale.ROOT))};
            case "mismatch" -> new GeneralName[]{holder};
            case "missing" -> null;
            case "bare" -> new GeneralName[]{new GeneralName(6, cardUrn.substring(9))};
            case "short" -> new GeneralName[]{new GeneralName(6, "urn:uuid:1-2-3-4-5")};
            case "wrong-name-type" -> new GeneralName[]{new GeneralName(GeneralName.dNSName, cardUrn)};
            case "holder-before-card" -> new GeneralName[]{holder, match};
            case "holder-after-card" -> new GeneralName[]{match, holder};
            case "unrelated-uri-before-card" -> new GeneralName[]{new GeneralName(6, "https://example.invalid/"), match};
            default -> throw new AssertionError(kind);
        };
        boolean pass = Set.of("match", "uppercase", "unrelated-uri-before-card", "fascn-and-card").contains(kind)
                || (row == 451 && Set.of("holder-before-card", "holder-after-card").contains(kind));
        String failure = row == 369 && Set.of("holder-before-card", "holder-after-card").contains(kind)
                ? "PKIX.27 current:" : "PKIX.27:";
        byte[] signed = signedCertificateWithSan(names);
        for (String database : List.of("PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"))
            run(database, row, "PKIX_Test_27_current", signed, pass, failure);
        if (kind.startsWith("fascn-")) {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(fixtureValue(signed, 0x70)));
            long uriCount = certificate.getSubjectAlternativeNames().stream().filter(n -> n.get(0).equals(6)).count();
            assertEquals(kind.equals("fascn-only") ? 0 : 1, uriCount);
            for (String database : List.of("PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"))
                run(database, row, "PKIX_Test_27", signed, pass, "PKIX.27:");
        }
    }

    static Stream<Arguments> currentSanHolderCases() {
        return Stream.of(
                Arguments.of("absent", true), Arguments.of("match", true),
                Arguments.of("v1", false), Arguments.of("v5", false),
                Arguments.of("variant", false), Arguments.of("short", false),
                Arguments.of("mismatch", false), Arguments.of("unrelated", true));
    }

    @ParameterizedTest(name="production PIV Authentication SAN holder UUID: {0}")
    @MethodSource("currentSanHolderCases")
    void currentSanHolderThroughExistingAtom(String kind, boolean pass) throws Exception {
        List<GeneralName> names = new ArrayList<>();
        names.add(new GeneralName(GeneralName.uniformResourceIdentifier, cardUrn));
        String candidate = switch (kind) {
            case "absent", "unrelated" -> null;
            case "match" -> holderUrn;
            case "v1" -> uuidUrnWithByte(holderUrn, 6, 0x10);
            case "v5" -> uuidUrnWithByte(holderUrn, 6, 0x50);
            case "variant" -> uuidUrnWithByte(holderUrn, 8, 0x00);
            case "short" -> "urn:uuid:1-2-3-4-5";
            case "mismatch" -> "urn:uuid:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
            default -> throw new AssertionError(kind);
        };
        if (candidate != null) names.add(new GeneralName(GeneralName.uniformResourceIdentifier, candidate));
        if (kind.equals("unrelated"))
            names.add(new GeneralName(GeneralName.uniformResourceIdentifier, "https://example.invalid/"));
        byte[] signed = signedCertificateWithSan(names.toArray(new GeneralName[0]));
        for (String database : List.of("PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db")) {
            run(database, 369, "PKIX_Test_27_current", signed, pass, "PKIX.27 current:");
            if (pass) run(database, 369, "PKIX_Test_27_current", signed,
                    TestExecutionResult.Status.SUCCESSFUL, "", null, currentChuidObjects.get("holder-absent"));
        }
        if (kind.equals("v1") || kind.equals("mismatch"))
            run("PIV-I_Production_Cards.db", 369, "PKIX_Test_27", signed, true, "");
    }

    private static String uuidUrnWithByte(String urn, int index, int highBits) {
        UUID uuid = UUID.fromString(urn.substring(9));
        ByteBuffer bytes = ByteBuffer.allocate(16).putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits());
        byte[] value = bytes.array();
        value[index] = (byte) ((value[index] & 0x0f) | highBits);
        ByteBuffer changed = ByteBuffer.wrap(value);
        return "urn:uuid:" + new UUID(changed.getLong(), changed.getLong());
    }

    @ParameterizedTest(name="FASC-N explicit-tag compatibility: {0}")
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void fascnExplicitTagThroughExistingAtom(String database) throws Exception {
        CardHolderUniqueIdentifier decoded = new CardHolderUniqueIdentifier();
        decoded.setOID(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
        decoded.setBytes(chuid);
        assertTrue(decoded.decode());
        for (boolean matches : new boolean[]{true, false}) {
            byte[] value = decoded.getfASCN().clone();
            if (!matches) value[0] ^= 1;
            OtherName name = new OtherName(new ASN1ObjectIdentifier("2.16.840.1.101.3.6.6"),
                    new DEROctetString(value));
            OtherName parsed = OtherName.getInstance(name.getEncoded());
            assertArrayEquals(value, ASN1OctetString.getInstance(parsed.getValue()).getOctets());
            byte[] signed = signedCertificateWithSan(new GeneralName[]{
                    new GeneralName(GeneralName.otherName, name)});
            run(database, 368, "PKIX_Test_12", signed, matches, "Certificate doesn't contain ");
        }
    }

    private static byte[] signedCertificateWithSan(GeneralName[] names) throws Exception {
        X500Name name = new X500Name("CN=CCT PIV Authentication SAN regression");
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(4242),
                new java.util.Date(1704067200000L), new java.util.Date(1893456000000L),
                name, sanSigningKey.getPublic());
        if (names != null) builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
        X509Certificate signed = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(sanSigningKey.getPrivate())));
        signed.verify(sanSigningKey.getPublic());
        return APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{0x70}, signed.getEncoded()),
                new byte[]{0x71, 1, 0, (byte) 0xfe, 0}));
    }

    static Stream<Arguments> signatureCases() {
        return IntStream.of(350, 383, 406, 429).boxed().flatMap(row ->
                Stream.of("null", "absent", "integer", "octets").map(kind -> Arguments.of(row, kind)));
    }

    @ParameterizedTest(name="production row {0}: RSA parameters {1}") @MethodSource("signatureCases")
    void signatureThroughExistingAtom(int row, String kind) throws Exception {
        ASN1ObjectIdentifier rsaSha256 = new ASN1ObjectIdentifier("1.2.840.113549.1.1.11");
        AlgorithmIdentifier algorithm = switch (kind) {
            case "null" -> new AlgorithmIdentifier(rsaSha256, DERNull.INSTANCE);
            case "absent" -> new AlgorithmIdentifier(rsaSha256);
            case "integer" -> new AlgorithmIdentifier(rsaSha256, new ASN1Integer(0));
            case "octets" -> new AlgorithmIdentifier(rsaSha256, new DEROctetString(new byte[0]));
            default -> throw new AssertionError(kind);
        };
        run(row, "sp800_78_Test_3_current", encodedCertificate(null, algorithm),
                kind.equals("null") || kind.equals("absent"), "SP800-78.3 current:");
    }

    static Stream<Arguments> currentSignatureAlgorithmCases() {
        return IntStream.of(350, 383, 406, 429).boxed().flatMap(row -> Stream.of(
                Arguments.of(row, "rsa2048", true),
                Arguments.of(row, "rsaSha384Signature", true),
                Arguments.of(row, "rsaPssSha384Signature", true),
                Arguments.of(row, "p384", true),
                Arguments.of(row, "p256", true),
                Arguments.of(row, "rsaSha1Signature", false)));
    }

    @ParameterizedTest(name="production certificate signature row {0}: {1}")
    @MethodSource("currentSignatureAlgorithmCases")
    void currentSignatureAlgorithmThroughExistingAtom(int row, String kind, boolean pass) throws Exception {
        run(row, "sp800_78_Test_3_current", keyProfileCertificates.get(kind),
                pass, "SP800-78.3 current:");
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
            "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"})
    void ecdsaCertificateParametersMustBeAbsent(String database) throws Exception {
        boolean current = !database.startsWith("PIV-I_");
        String method = current ? "sp800_78_Test_3_current" : "sp800_78_Test_3";
        for (int row : new int[]{350, 383, 406, 429}) {
            run(database, row, method, keyProfileCertificates.get("p384"), true, "");
            run(database, row, method, keyProfileCertificates.get("ecdsaNullParameters"), false,
                    current ? "SP800-78.3 current: ECDSA parameters must be absent"
                            : "Non-conformant signature algorithm OID");
        }
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
            "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"})
    void optionalReadErrorsMustNotBeReportedAsAbsence(String database) throws Exception {
        boolean current = !database.startsWith("PIV-I_");
        if (current) {
            for (int row : new int[]{384, 385, 407, 408}) {
                run(database, row, "sp800_78_Test_1_current", keyProfileCertificates.get("rsa2048"), true, "");
                run(database, row, "sp800_78_Test_1_current", null, true, "");
                run(database, row, "sp800_78_Test_1_current", keyProfileCertificates.get("rsa2048"),
                        TestExecutionResult.Status.FAILED, "Failed to retrieve data object",
                        MiddlewareStatus.PIV_CONNECTION_FAILURE);
            }
            for (int row : new int[]{383, 406}) {
                run(database, row, "sp800_78_Test_3_current", keyProfileCertificates.get("rsa2048"), true, "");
                run(database, row, "sp800_78_Test_3_current", null, true, "");
                run(database, row, "sp800_78_Test_3_current", keyProfileCertificates.get("rsa2048"),
                        TestExecutionResult.Status.FAILED, "Failed to retrieve data object",
                        MiddlewareStatus.PIV_CONNECTION_FAILURE);
            }
        }
        run(database, 94, "sp800_73_4_Test_19", keyProfileCertificates.get("rsa2048"), true, "");
        run(database, 94, "sp800_73_4_Test_19", null, true, "");
        run(database, 94, "sp800_73_4_Test_19", keyProfileCertificates.get("rsa2048"),
                TestExecutionResult.Status.FAILED, "Failed to retrieve data object",
                MiddlewareStatus.PIV_CONNECTION_FAILURE);
        if (current) {
            for (int row : new int[]{95, 96, 97, 107, 108, 109}) {
                String method = row == 95 || row == 107 ? "sp800_73_5_Test_20"
                        : row == 97 || row == 108 ? "sp800_73_5_Test_21" : "sp800_73_5_Test_22";
                run(database, row, method, keyProfileCertificates.get("rsa2048"), true, "");
                run(database, row, method, null, true, "");
                run(database, row, method, keyProfileCertificates.get("rsa2048"),
                        TestExecutionResult.Status.FAILED, "Failed to retrieve data object",
                        MiddlewareStatus.PIV_CONNECTION_FAILURE);
            }
        }
        // Iris is optional; the PIV-I ICAM row-338 mapping is disabled.
        if (!database.equals("PIV-I_ICAM_Test_Cards.db")) {
            String cmsMethod = current ? "CMS_Test_23_current" : "CMS_Test_23";
            run(database, 338, cmsMethod, null, true, "");
            run(database, 338, cmsMethod, facialImage,
                    TestExecutionResult.Status.FAILED, "Failed to retrieve data object",
                    MiddlewareStatus.PIV_CONNECTION_FAILURE);
        }
    }

    static Stream<Arguments> absentContainerCases() throws Exception {
        List<Arguments> cases = new ArrayList<>();
        for (String database : List.of("PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
                "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db")) {
            Path path = Path.of(System.getProperty("cct.repository"), "conformancelib/testdata", database);
            try (Connection c = DriverManager.getConnection("jdbc:sqlite:file:" + path + "?mode=ro");
                 var rows = c.createStatement().executeQuery("SELECT tc.Id, s.Method, tc.TestCaseContainer "
                         + "FROM TestCases tc JOIN TestsToSteps ts ON tc.Id=ts.TestId "
                         + "JOIN TestSteps s ON s.Id=ts.TestStepId WHERE tc.Id IN "
                         + "(65,66,67,68,69,70,71,72,73,74,75,76,89,90,91,92,93,98,101,102,103,104,105,110,136,137,138,139,145,399,400,422,423) "
                         + "ORDER BY tc.Id")) {
                int count = 0;
                while (rows.next()) {
                    cases.add(Arguments.of(database, rows.getInt(1), rows.getString(2), rows.getString(3)));
                    count++;
                }
                assertEquals(33, count, "Retain captured and shared optional routes, including disabled ICAM diagnostics");
            }
        }
        return cases.stream();
    }

    @ParameterizedTest(name="{0} row {1}: {2}")
    @MethodSource("absentContainerCases")
    void absentContainerFieldsKeepAcquisitionBoundaries(String database, int row, String method,
                                                       String container) throws Exception {
        byte[] present = switch (container) {
            case "PRINTED_INFORMATION_OID" -> printedContainerFixture();
            case "DISCOVERY_OBJECT_OID" -> Files.readAllBytes(Path.of(System.getProperty("cct.repository"),
                    "cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/synthetic/discovery.bin"));
            default -> keyProfileCertificates.get("aia-caIssuers");
        };
        run(database, row, method, present, true, "");
        run(database, row, method, null, true, "");
        run(database, row, method, present, TestExecutionResult.Status.FAILED,
                "Failed to retrieve data object", MiddlewareStatus.PIV_CONNECTION_FAILURE);
        var malformed = run(database, row, method, new byte[]{0x53, 1, 0},
                TestExecutionResult.Status.FAILED, "", null, null);
        assertTrue(malformed.getThrowable().orElseThrow().getCause() instanceof ConformanceTestException);
        assertTrue(malformed.getThrowable().orElseThrow().getCause().getMessage()
                .startsWith("Failed to decode object for OID "));
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
            "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"})
    void sharedFieldChecksStillRejectMissingMandatoryContainers(String database) throws Exception {
        Path path = Path.of(System.getProperty("cct.repository"), "conformancelib/testdata", database);
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:file:" + path + "?mode=ro");
             var rows = c.createStatement().executeQuery("SELECT tc.Id, s.Method, tc.TestCaseContainer "
                     + "FROM TestCases tc JOIN TestsToSteps ts ON tc.Id=ts.TestId "
                     + "JOIN TestSteps s ON s.Id=ts.TestStepId WHERE s.Method IN "
                     + "('berTLV_Test_1','berTLV_Test_2','berTLV_Test_3','berTLV_Test_4',"
                     + "'sp800_73_4_Test_56','sp800_73_4_Test_23','PKIX_Test_7','PKIX_Test_22')")) {
            int count = 0;
            while (rows.next()) {
                String oid = APDUConstants.getStringForFieldNamed(rows.getString(3));
                if (!APDUConstants.isContainerMandatory(oid)) continue;
                run(database, rows.getInt(1), rows.getString(2), null, false, "Required container is absent:");
                count++;
            }
            assertEquals(48, count);
        }
    }

    private static byte[] printedContainerFixture() throws Exception {
        return APDUUtils.getTLV(APDUConstants.DATA,
                fixtureFields(APDUUtils.getTLV(APDUConstants.DATA, printedFixture())).stream()
                        .map(f -> f.isTag(new BerTag(4))
                                ? APDUUtils.getTLV(new byte[]{4}, "2030DEC31".getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                                : APDUUtils.getTLV(f.getTag().bytes, f.getBytesValue()))
                        .reduce(new byte[0], ExistingCctRegressionTest::concat));
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
            "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"})
    void presentOptionalFieldsStillReachTheirAssertions(String database) throws Exception {
        byte[] valid = printedContainerFixture();
        var fields = fixtureFields(valid);
        byte[] noEnd = APDUUtils.getTLV(APDUConstants.DATA, fields.stream()
                .filter(f -> !f.isTag(new BerTag(0xfe)))
                .map(f -> APDUUtils.getTLV(f.getTag().bytes, f.getBytesValue()))
                .reduce(new byte[0], ExistingCctRegressionTest::concat));
        run(database, 74, "sp800_73_4_Test_30", noEnd, false, "expected:");
        run(database, 76, "sp800_73_4_Test_23", noEnd, false, "expected:");
        byte[] body = new BerTlvParser().parse(valid).getList().get(0).getBytesValue();
        run(database, 75, "sp800_73_4_Test_31", APDUUtils.getTLV(APDUConstants.DATA,
                concat(new byte[]{(byte) 0xf8, 0}, body)), false, "expected:");
        byte[] reordered = APDUUtils.getTLV(APDUConstants.DATA, Stream.concat(
                Stream.of(fields.get(1), fields.get(0)), fields.stream().skip(2))
                .map(f -> APDUUtils.getTLV(f.getTag().bytes, f.getBytesValue()))
                .reduce(new byte[0], ExistingCctRegressionTest::concat));
        run(database, 71, "sp800_73_4_Test_52", reordered, false, "Tag 0x02 must follow tag 0x01");
        byte[] orgBeforeIssuer = APDUUtils.getTLV(APDUConstants.DATA, fields.stream()
                .map(f -> f.isTag(new BerTag(6))
                        ? concat(new byte[]{7, 1, 'A'}, APDUUtils.getTLV(f.getTag().bytes, f.getBytesValue()))
                        : APDUUtils.getTLV(f.getTag().bytes, f.getBytesValue()))
                .reduce(new byte[0], ExistingCctRegressionTest::concat));
        run(database, 73, "sp800_73_4_Test_29", orgBeforeIssuer, false, "Tag 0x07 must follow tag 0x06");
        run(database, 72, "sp800_73_4_Test_53", APDUUtils.getTLV(APDUConstants.DATA,
                concat(body, new byte[]{7, 1, 'A'})), false, "ERROR_DETECTION_TAG must be the last tag");
        for (int row : new int[]{399, 422}) {
            run(database, row, "PKIX_Test_7", keyProfileCertificates.get("rsa2048"), false, "AIA extension is not present");
            run(database, row + 1, "PKIX_Test_22", keyProfileCertificates.get("aia-ocsp"), false,
                    "An accessMethod containing 1.3.6.1.5.5.7.48.2 is not present");
        }
    }

    @Test void optionalContainerControlsAreIndependentlyWellFormed() throws Exception {
        byte[] printed = printedContainerFixture();
        assertTrue(printed.length <= 120);
        var fields = fixtureFields(printed);
        assertEquals(List.of(1, 2, 4, 5, 6, 0xfe), fields.stream()
                .map(f -> Byte.toUnsignedInt(f.getTag().bytes[0])).collect(Collectors.toList()));
        assertEquals(0, fields.get(fields.size() - 1).getBytesValue().length);
        for (String kind : List.of("aia-caIssuers", "aia-ocsp")) {
            var cert = fixtureCertificate(keyProfileCertificates.get(kind));
            assertTrue(cert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(sanSigningKey.getPublic())));
            var aia = AuthorityInformationAccess.fromExtensions(cert.getExtensions());
            assertEquals(1, aia.getAccessDescriptions().length);
            assertEquals(kind.equals("aia-caIssuers") ? AccessDescription.id_ad_caIssuers : AccessDescription.id_ad_ocsp,
                    aia.getAccessDescriptions()[0].getAccessMethod());
        }
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
            "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"})
    void cmsRsa4096AcceptanceIsLimitedToCurrentPivProfiles(String database) throws Exception {
        String method = database.startsWith("PIV-I_") ? "CMS_Test_23" : "CMS_Test_23_current";
        run(database, 269, method, currentChuidObjects.get("plain"), true, "");
        run(database, 269, method, currentChuidObjects.get("cms-rsa4096-sha256"),
                !database.startsWith("PIV-I_"), "4096 is an invalid key length");
    }

    static Stream<Arguments> cmsConsumerRoutes() {
        // PIV-I ICAM 286/338 are disabled: explicit compatibility guards, not scheduled coverage.
        return Stream.of("PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
                "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db").flatMap(database ->
                IntStream.of(269, 286, 306, 324, 338).mapToObj(row -> Arguments.of(database, row)));
    }

    @ParameterizedTest(name="CMS impact: {0}, row {1}")
    @MethodSource("cmsConsumerRoutes")
    void sharedCmsConsumersPreserveCurveAndEditionRules(String database, int row) throws Exception {
        // 78-5 Table 2 / 78-4 Table 3-2, through each original object's decoder.
        boolean current = !database.startsWith("PIV-I_");
        String method = current ? "CMS_Test_23_current" : "CMS_Test_23";
        for (String kind : List.of("plain", "cms-rsa1024-sha256", "cms-rsa3072-sha256", "cms-rsa4096-sha256", "cms-p256-sha256", "cms-p384-sha384",
                "cms-brainpool256-sha256", "cms-p256-sha384", "cms-p384-sha256")) {
            byte[] raw = cmsConsumerObject(row, kind);
            boolean pass = !kind.equals("cms-rsa1024-sha256") && !kind.equals("cms-brainpool256-sha256")
                    && !kind.equals("cms-p256-sha384") && !kind.equals("cms-p384-sha256")
                    && (current || !kind.equals("cms-rsa4096-sha256"));
            String reason = kind.equals("cms-brainpool256-sha256")
                    ? "EC signer must use named curve P-256 or P-384"
                    : kind.equals("cms-rsa1024-sha256") ? "1024 is an invalid key length"
                    : kind.equals("cms-rsa4096-sha256") ? "4096 is an invalid key length"
                    : "EC signer curve and digest are incompatible";
            run(database, row, method, raw, pass ? TestExecutionResult.Status.SUCCESSFUL
                    : TestExecutionResult.Status.FAILED, reason, null,
                    row == 324 ? currentChuidObjects.get(kind) : null);
        }
        run(database, row, method, cmsConsumerObject(row, "plain"),
                TestExecutionResult.Status.FAILED, "Failed to retrieve data object",
                MiddlewareStatus.PIV_CONNECTION_FAILURE);
        if (row == 338) run(database, row, method, null, true, "");
    }

    @Test
    void cmsImpactFixturesAreValid() throws Exception {
        // CMS/relationship scope only: synthetic records do not qualify biometric images or PKI profiles.
        for (int row : new int[]{286, 306, 324, 338}) {
            for (String kind : List.of("plain", "cms-rsa1024-sha256", "cms-rsa3072-sha256", "cms-rsa4096-sha256", "cms-p256-sha256", "cms-p384-sha384",
                    "cms-brainpool256-sha256", "cms-p256-sha384", "cms-p384-sha256")) {
                byte[] raw = cmsConsumerObject(row, kind);
                CMSSignedData cms;
                X509CertificateHolder expectedSigner;
                if (row == 324) {
                    cms = new CMSSignedData(fixtureValue(raw, 0xbb));
                    expectedSigner = assertFixtureCmsValid(fixtureChuidCms(currentChuidObjects.get(kind)));
                    assertTrue(cms.getCertificates().getMatches(null).isEmpty());
                    assertArrayEquals(new byte[]{1, (byte) 0xdb, 0, 2, 0x30, 1}, fixtureValue(raw, 0xba));
                    var lds = org.bouncycastle.asn1.icao.LDSSecurityObject.getInstance(cms.getSignedContent().getContent());
                    String digestOid = cms.getSignerInfos().getSigners().iterator().next().getDigestAlgOID();
                    assertEquals(digestOid, lds.getDigestAlgorithmIdentifier().getAlgorithm().getId(),
                            "SP 800-78-5 section 3.2.3: Security Object hashes must match its signature digest: " + kind);
                    var hash = java.security.MessageDigest.getInstance(digestOid);
                    var groups = lds.getDatagroupHash();
                    assertEquals(2, groups.length);
                    assertEquals(1, groups[0].getDataGroupNumber());
                    assertEquals(2, groups[1].getDataGroupNumber());
                    assertArrayEquals(hash.digest(ccc),
                            groups[0].getDataGroupHashValue().getOctets());
                    assertArrayEquals(hash.digest(printedFixture()),
                            groups[1].getDataGroupHashValue().getOctets());
                    assertEquals("2.23.136.1.1.1", cms.getSignedContentTypeOID());
                } else {
                    byte[] biometric = fixtureValue(raw, 0xbc);
                    int bdbLength = ByteBuffer.wrap(biometric).getInt(2);
                    int sbLength = Short.toUnsignedInt(ByteBuffer.wrap(biometric).getShort(6));
                    assertTrue(bdbLength > 0);
                    assertEquals(88 + bdbLength + sbLength, biometric.length);
                    cms = new CMSSignedData(new CMSProcessableByteArray(Arrays.copyOf(biometric, 88 + bdbLength)),
                            Arrays.copyOfRange(biometric, 88 + bdbLength, biometric.length));
                    expectedSigner = assertFixtureCmsValid(cms);
                    assertTrue(cms.isDetachedSignature());
                    assertEquals("2.16.840.1.101.3.6.2", cms.getSignedContentTypeOID());
                    assertArrayEquals(fixtureValue(chuid, 0x30), Arrays.copyOfRange(biometric, 59, 84));
                    var attrs = cms.getSignerInfos().getSigners().iterator().next().getSignedAttributes();
                    assertEquals(expectedSigner.getSubject(), X500Name.getInstance(attrs
                            .get(new ASN1ObjectIdentifier("2.16.840.1.101.3.6.5")).getAttrValues().getObjectAt(0)));
                    assertArrayEquals(fixtureValue(chuid, 0x30), ASN1OctetString.getInstance(attrs
                            .get(new ASN1ObjectIdentifier("2.16.840.1.101.3.6.6")).getAttrValues().getObjectAt(0)).getOctets());
                    assertArrayEquals(fixtureValue(chuid, 0x34), ASN1OctetString.getInstance(attrs
                            .get(new ASN1ObjectIdentifier("1.3.6.1.1.16.4")).getAttrValues().getObjectAt(0)).getOctets());
                    assertFalse(expectedSigner.getSubjectPublicKeyInfo().equals(
                            assertFixtureCmsValid(fixtureChuidCms(chuid)).getSubjectPublicKeyInfo()),
                            "A separately embedded biometric signer must differ from the fallback CHUID signer");
                }
                if (row == 324) assertFixtureCmsValid(cms, expectedSigner);
            }
        }
    }

    @ParameterizedTest(name="Security Object Discovery hashes: {0}")
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
            "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"})
    void securityObjectDiscoveryHashesThroughExistingAtom(String database) throws Exception {
        byte[] discovery = Files.readAllBytes(Path.of(System.getProperty("cct.repository"),
                "cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/synthetic/discovery.bin"));
        byte[] content = new BerTlvParser().parseConstructed(discovery).getBytesValue();
        byte[] security = securityObjectWithDiscovery(content);
        Map<String, byte[]> objects = new HashMap<>();
        objects.put(APDUConstants.CARD_CAPABILITY_CONTAINER_OID, APDUUtils.getTLV(APDUConstants.DATA, ccc));
        objects.put(APDUConstants.DISCOVERY_OBJECT_OID, discovery);
        run(database, 317, "sp800_73_4_Test_37", security, TestExecutionResult.Status.SUCCESSFUL,
                "", null, currentChuidObjects.get("plain"), objects);
        // The same decoded fields and exact value bytes survive a different outer BER length encoding.
        byte[] longLength = concat(new byte[]{0x7e, (byte) 0x81, (byte) content.length}, content);
        objects.put(APDUConstants.DISCOVERY_OBJECT_OID, longLength);
        run(database, 317, "sp800_73_4_Test_37", security, TestExecutionResult.Status.SUCCESSFUL,
                "", null, currentChuidObjects.get("plain"), objects);
        byte[] changed = discovery.clone();
        changed[changed.length - 2] ^= 0x10;
        DiscoveryObject changedObject = new DiscoveryObject();
        changedObject.setOID(APDUConstants.DISCOVERY_OBJECT_OID);
        changedObject.setContainerName(APDUConstants.getFileNameForOid(APDUConstants.DISCOVERY_OBJECT_OID));
        changedObject.setBytes(changed);
        assertTrue(changedObject.decode(), "The intended hash violation must remain decodable");
        objects.put(APDUConstants.DISCOVERY_OBJECT_OID, changed);
        run(database, 317, "sp800_73_4_Test_37", security, TestExecutionResult.Status.FAILED,
                "Hashes in Security Object do not match", null, currentChuidObjects.get("plain"), objects);
        objects.put(APDUConstants.DISCOVERY_OBJECT_OID, discovery);
        byte[] changedCcc = ccc.clone(); changedCcc[4] ^= 1;
        CardCapabilityContainer decodedCcc = new CardCapabilityContainer();
        decodedCcc.setOID(APDUConstants.CARD_CAPABILITY_CONTAINER_OID);
        decodedCcc.setContainerName(APDUConstants.getFileNameForOid(APDUConstants.CARD_CAPABILITY_CONTAINER_OID));
        decodedCcc.setBytes(APDUUtils.getTLV(APDUConstants.DATA, changedCcc));
        assertTrue(decodedCcc.decode());
        objects.put(APDUConstants.CARD_CAPABILITY_CONTAINER_OID, APDUUtils.getTLV(APDUConstants.DATA, changedCcc));
        run(database, 317, "sp800_73_4_Test_37", security, TestExecutionResult.Status.FAILED,
                "Hashes in Security Object do not match", null, currentChuidObjects.get("plain"), objects);
        objects.put(APDUConstants.CARD_CAPABILITY_CONTAINER_OID, APDUUtils.getTLV(APDUConstants.DATA, ccc));
        // Hash integrity is independent of the separate allowed-field assertion.
        byte[] extraContent = concat(content, new byte[]{0x01, 1, 0x42});
        byte[] extraSecurity = securityObjectWithDiscovery(extraContent);
        objects.put(APDUConstants.DISCOVERY_OBJECT_OID, APDUUtils.getTLV(new byte[]{0x7e}, extraContent));
        run(database, 317, "sp800_73_4_Test_37", extraSecurity, TestExecutionResult.Status.SUCCESSFUL,
                "", null, currentChuidObjects.get("plain"), objects);
        extraContent[extraContent.length - 1] ^= 1;
        objects.put(APDUConstants.DISCOVERY_OBJECT_OID, APDUUtils.getTLV(new byte[]{0x7e}, extraContent));
        run(database, 317, "sp800_73_4_Test_37", extraSecurity, TestExecutionResult.Status.FAILED,
                "Hashes in Security Object do not match", null, currentChuidObjects.get("plain"), objects);
        objects.remove(APDUConstants.DISCOVERY_OBJECT_OID);
        run(database, 317, "sp800_73_4_Test_37", security, TestExecutionResult.Status.FAILED,
                "Security object data group", null, currentChuidObjects.get("plain"), objects);
    }

    @Test void discoveryHashInputPreservesEncodedValue() throws Exception {
        byte[] discovery = Files.readAllBytes(Path.of(System.getProperty("cct.repository"),
                "cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/synthetic/discovery.bin"));
        byte[] content = new BerTlvParser().parseConstructed(discovery).getBytesValue();
        // Additional fields are outside this hash-input check's field-conformance claim.
        for (byte[] value : List.of(content, concat(content, new byte[]{0x01, 1, 0x42}))) {
            DiscoveryObject object = new DiscoveryObject();
            object.setOID(APDUConstants.DISCOVERY_OBJECT_OID);
            object.setContainerName(APDUConstants.getFileNameForOid(APDUConstants.DISCOVERY_OBJECT_OID));
            object.setBytes(APDUUtils.getTLV(new byte[]{0x7e}, value));
            assertTrue(object.decode());
            assertArrayEquals(value, object.getSignedContent(), "Hash the exact value, including any unrecognized field");
        }
    }

    @Test void securityObjectHashVerificationCanBeRepeated() throws Exception {
        byte[] discovery = Files.readAllBytes(Path.of(System.getProperty("cct.repository"),
                "cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/synthetic/discovery.bin"));
        byte[] content = new BerTlvParser().parseConstructed(discovery).getBytesValue();
        SecurityObject object = new SecurityObject();
        object.setOID(APDUConstants.SECURITY_OBJECT_OID);
        object.setContainerName(APDUConstants.getFileNameForOid(APDUConstants.SECURITY_OBJECT_OID));
        object.setBytes(securityObjectWithDiscovery(content));
        assertTrue(object.decode());
        Map<String, byte[]> data = new HashMap<>();
        data.put(APDUConstants.CARD_CAPABILITY_CONTAINER_OID, ccc);
        data.put(APDUConstants.DISCOVERY_OBJECT_OID, content);
        object.setMapOfDataElements(new HashMap<>(data));
        assertTrue(object.verifyHashes());
        assertTrue(object.verifyHashes(), "A second verification must recompute, not fail because a cache is populated");
        byte[] changed = content.clone(); changed[changed.length - 2] ^= 0x10;
        data.put(APDUConstants.DISCOVERY_OBJECT_OID, changed);
        object.setMapOfDataElements(new HashMap<>(data));
        assertFalse(object.verifyHashes());
        data.put(APDUConstants.DISCOVERY_OBJECT_OID, content);
        object.setMapOfDataElements(new HashMap<>(data));
        assertTrue(object.verifyHashes());
    }

    @Test void securityObjectSingleGroupHashRejectsErrors() throws Exception {
        byte[] discovery = Files.readAllBytes(Path.of(System.getProperty("cct.repository"),
                "cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/synthetic/discovery.bin"));
        byte[] content = new BerTlvParser().parseConstructed(discovery).getBytesValue();
        SecurityObject object = new SecurityObject();
        object.setOID(APDUConstants.SECURITY_OBJECT_OID);
        object.setContainerName(APDUConstants.getFileNameForOid(APDUConstants.SECURITY_OBJECT_OID));
        object.setBytes(securityObjectWithDiscovery(content));
        assertTrue(object.decode());
        Map<String, byte[]> data = new HashMap<>();
        data.put(APDUConstants.CARD_CAPABILITY_CONTAINER_OID, ccc);
        data.put(APDUConstants.DISCOVERY_OBJECT_OID, content);
        object.setMapOfDataElements(new HashMap<>(data));
        assertTrue(object.verifyHash(11), "The single-group helper must work before all-group verification");
        byte[] changedGroup = content.clone(); changedGroup[changedGroup.length - 2] ^= 0x10;
        data.put(APDUConstants.DISCOVERY_OBJECT_OID, changedGroup);
        object.setMapOfDataElements(new HashMap<>(data));
        assertFalse(object.verifyHash(11), "A single-group parse/error path must not falsely accept altered content");
        data.remove(APDUConstants.DISCOVERY_OBJECT_OID);
        object.setMapOfDataElements(new HashMap<>(data));
        assertFalse(object.verifyHash(11), "Unavailable content must fail closed");
        data.put(APDUConstants.DISCOVERY_OBJECT_OID, content);
        object.setMapOfDataElements(new HashMap<>(data));
        assertTrue(object.verifyHash(11));
        assertTrue(object.verifyHash(1));
        assertFalse(object.verifyHash(99), "An unmapped group cannot pass");
    }

    private static byte[] securityObjectWithDiscovery(byte[] discoveryValue) throws Exception {
        var digestAlgorithm = fixtureChuidCms(currentChuidObjects.get("plain")).getSignerInfos()
                .getSigners().iterator().next().getDigestAlgorithmID();
        var hash = java.security.MessageDigest.getInstance(digestAlgorithm.getAlgorithm().getId());
        var groups = new org.bouncycastle.asn1.icao.DataGroupHash[]{
                new org.bouncycastle.asn1.icao.DataGroupHash(1, new DEROctetString(hash.digest(ccc))),
                new org.bouncycastle.asn1.icao.DataGroupHash(11, new DEROctetString(hash.digest(discoveryValue)))};
        var lds = new org.bouncycastle.asn1.icao.LDSSecurityObject(digestAlgorithm, groups);
        byte[] raw = signedSecurityObject("plain", new byte[]{1, (byte) 0xdb, 0, 11, 0x60, 0x50}, lds);
        byte[] encoded = fixtureValue(raw, 0xbb);
        var cms = new CMSSignedData(encoded);
        assertFixtureCmsValid(cms, assertFixtureCmsValid(fixtureChuidCms(currentChuidObjects.get("plain"))));
        assertTrue(cms.getCertificates().getMatches(null).isEmpty());
        var decoded = org.bouncycastle.asn1.icao.LDSSecurityObject.getInstance(cms.getSignedContent().getContent());
        assertEquals(digestAlgorithm, decoded.getDigestAlgorithmIdentifier());
        assertArrayEquals(hash.digest(ccc), decoded.getDatagroupHash()[0].getDataGroupHashValue().getOctets());
        assertArrayEquals(hash.digest(discoveryValue), decoded.getDatagroupHash()[1].getDataGroupHashValue().getOctets());
        return raw;
    }

    @ParameterizedTest(name="CMS certificate/signer counts: {0}, row {1}")
    @MethodSource("cmsConsumerRoutes")
    void cmsCertificateAndSignerCountsUseOriginalCases(String database, int row) throws Exception {
        byte[] control = cmsConsumerObject(row, "plain");
        byte[] relatedChuid = row == 324 ? currentChuidObjects.get("plain") : null;
        String algorithmMethod = database.startsWith("PIV-I_") ? "CMS_Test_23" : "CMS_Test_23_current";
        CMSSignedData good = fixtureCms(row, control);
        X509CertificateHolder external = row == 324
                ? assertFixtureCmsValid(fixtureChuidCms(relatedChuid)) : null;
        assertFixtureCmsValid(good, external);
        assertEquals(row == 324 ? 0 : 1, good.getCertificates().getMatches(null).size());
        run(database, row, algorithmMethod, control, TestExecutionResult.Status.SUCCESSFUL, "", null, relatedChuid);

        byte[] extraCertificate = cmsConsumerObject(row, "plain", "extra-certificate");
        CMSSignedData changed = fixtureCms(row, extraCertificate);
        assertEquals(1, changed.getSignerInfos().size());
        assertEquals(row == 324 ? 1 : 2, changed.getCertificates().getMatches(null).size());
        // The extra certificate does not change or invalidate the actual signature.
        if (row == 324) assertFixtureCmsValid(changed);
        else assertFixtureCmsValid(changed, null);
        if (row == 324) {
            run(database, 323, "CMS_Test_21", control, TestExecutionResult.Status.SUCCESSFUL, "", null, relatedChuid);
            run(database, 323, "CMS_Test_21", extraCertificate, TestExecutionResult.Status.FAILED,
                    "Certificate(s) are present and shouldn't", null, relatedChuid);
        } else {
            var result = run(database, row, algorithmMethod, extraCertificate,
                    TestExecutionResult.Status.FAILED, "", null, null);
            Throwable cause = result.getThrowable().orElseThrow().getCause();
            assertTrue(cause instanceof ConformanceTestException, "Expected certificate-bag rejection: " + cause);
            assertTrue(cause.getMessage().startsWith("More than one cert found in "));
        }
        SignedPIVDataObject counted = new SignedPIVDataObject();
        assertEquals(0, counted.getCertCount());
        counted.setAsymmetricSignature(changed);
        assertEquals(row == 324 ? 1 : 2, counted.getCertCount());

        byte[] twoSigners = cmsConsumerObject(row, "plain", "two-signers");
        CMSSignedData doubled = fixtureCms(row, twoSigners);
        assertEquals(2, doubled.getSignerInfos().size());
        assertEquals(good.getCertificates().getMatches(null).size(), doubled.getCertificates().getMatches(null).size());
        X509CertificateHolder signerCertificate = external == null ? assertFixtureCmsValid(good) : external;
        for (var signer : doubled.getSignerInfos().getSigners())
            assertTrue(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signerCertificate)));
        if (row == 324) {
            run(database, 326, "CMS_Test_14", control, TestExecutionResult.Status.SUCCESSFUL, "", null, relatedChuid);
            run(database, 326, "CMS_Test_14", twoSigners, TestExecutionResult.Status.FAILED,
                    "Object signature does not verify", null, relatedChuid);
        } else {
            int countRow = row == 269 ? 266 : row == 286 ? 282 : row == 306 ? 302 : 334;
            run(database, countRow, "CMS_Test_7", control, true, "");
            run(database, countRow, "CMS_Test_7", twoSigners, false, "Number of signers is not 1 (one)");
        }
    }

    @ParameterizedTest(name="CMS signer relationship: {0}, row {1}")
    @MethodSource("cmsConsumerRoutes")
    void cmsSignerRelationshipsUseOriginalCases(String database, int row) throws Exception {
        int signatureRow = row == 269 ? 274 : row == 286 ? 291 : row == 306 ? 311 : row == 324 ? 326 : 343;
        byte[] control = cmsConsumerObject(row, "plain");
        byte[] relatedChuid = row == 324 ? currentChuidObjects.get("plain") : null;
        X509CertificateHolder expected = assertFixtureCmsValid(fixtureCms(row, control), row == 324
                ? assertFixtureCmsValid(fixtureChuidCms(relatedChuid)) : null);
        run(database, signatureRow, "CMS_Test_14", control,
                TestExecutionResult.Status.SUCCESSFUL, "", null, relatedChuid);
        byte[] wrongIdentifier = cmsConsumerObject(row, "plain", "wrong-identifier");
        CMSSignedData changed = fixtureCms(row, wrongIdentifier);
        var signer = changed.getSignerInfos().getSigners().iterator().next();
        assertFalse(signer.getSID().match(expected));
        // SID is outside the signed attributes. Verify the signed bytes and payload
        // independently so this negative isolates certificate identification.
        var verification = java.security.Signature.getInstance("SHA256withRSA", "SunRsaSign");
        verification.initVerify(new JcaX509CertificateConverter().setProvider("SUN").getCertificate(expected));
        verification.update(signer.getEncodedSignedAttributes());
        assertTrue(verification.verify(signer.getSignature()));
        assertArrayEquals(java.security.MessageDigest.getInstance("SHA-256").digest(
                        (byte[]) changed.getSignedContent().getContent()), ASN1OctetString.getInstance(
                        signer.getSignedAttributes().get(org.bouncycastle.asn1.cms.CMSAttributes.messageDigest)
                                .getAttrValues().getObjectAt(0)).getOctets());
        run(database, signatureRow, "CMS_Test_14", wrongIdentifier,
                TestExecutionResult.Status.FAILED, "Object signature does not verify", null, relatedChuid);
        if (row != 269 && row != 324) {
            byte[] fallback = cmsConsumerObject(row, "plain", "omit-certificate");
            assertFixtureCmsValid(fixtureCms(row, fallback), expected);
            run(database, signatureRow, "CMS_Test_14", fallback,
                    TestExecutionResult.Status.SUCCESSFUL, "", null, currentChuidObjects.get("plain"));
            run(database, signatureRow, "CMS_Test_14", fallback,
                    TestExecutionResult.Status.FAILED, "Object signature does not verify", null, chuid);
        }
    }

    @ParameterizedTest(name="PSS valid parameters in {0}")
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void pssValidParametersThroughExistingAtoms(String database) throws Exception {
        // RFC 4055 section 3.1 recommends matching MGF/message hashes, but
        // permits the independently identified hashes. FIPS 186-5 5.4(g)
        // permits salt lengths from zero through the message hash length.
        for (String hash : List.of("SHA-256", "SHA-384")) {
            for (String mgf : List.of("SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512")) {
                for (int salt : new int[]{0, hash.equals("SHA-256") ? 32 : 48}) {
                    byte[] raw = pssCertificate(hash, mgf, salt);
                    for (int row : new int[]{350, 383, 406, 429})
                        run(database, row, "sp800_78_Test_3_current", raw, true, "");
                }
            }
        }
    }

    @ParameterizedTest(name="PSS excessive salt in {0}")
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void pssExcessiveSaltThroughExistingAtoms(String database) throws Exception {
        // These signatures verify under PKCS #1; FIPS 186-5 imposes the
        // additional salt bound. They must fail the parameter assertion.
        for (String hash : List.of("SHA-256", "SHA-384")) {
            byte[] raw = pssCertificate(hash, hash, hash.equals("SHA-256") ? 33 : 49);
            for (int row : new int[]{350, 383, 406, 429})
                run(database, row, "sp800_78_Test_3_current", raw, false,
                        "SP800-78.3 current: RSA-PSS salt length");
        }
    }

    @ParameterizedTest(name="CHUID PSS salt bounds in {0}")
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void pssChuidSaltBoundsThroughExistingAtom(String database) throws Exception {
        for (String hash : List.of("sha256", "sha384")) {
            for (String salt : List.of("zero", "max", "excess"))
                run(database, 468, "sp800_78_Test_3_current",
                        currentChuidObjects.get("cms-pss-" + hash + "-" + salt),
                        !salt.equals("excess"), "SP800-78.3 current: RSA-PSS salt length");
        }
    }

    @ParameterizedTest(name="PSS invalid trailer in {0}")
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void pssInvalidTrailerThroughExistingAtoms(String database) throws Exception {
        var parameters = java.security.AlgorithmParameters.getInstance("RSASSA-PSS", "SunRsaSign");
        parameters.init(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 2));
        // An intentional encoding violation, not a signature-valid certificate.
        byte[] raw = encodedCertificate(null, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS,
                ASN1Primitive.fromByteArray(parameters.getEncoded())));
        // SUN rejects this encoding while decoding the certificate; BC exposes
        // the parameters to the atom. Both must give the intended assertion,
        // rather than an incidental null-certificate logging exception.
        String reason = Boolean.getBoolean("cct.regressionBC")
                ? "SP800-78.3 current: RSA-PSS trailer field must be 1"
                : "SP800-78.3 current: certificate could not be decoded";
        for (int row : new int[]{350, 383, 406, 429})
            run(database, row, "sp800_78_Test_3_current", raw, false, reason);
    }

    @ParameterizedTest(name="production CHUID CMS signature: {0}")
    @ValueSource(strings={"plain", "cms-sha384", "cms-rsa1024-sha256", "cms-rsa3072-sha256", "cms-rsa4096-sha384", "cms-sha1"})
    void currentChuidSignatureAlgorithmThroughExistingAtom(String kind) throws Exception {
        run(468, "sp800_78_Test_3_current", currentChuidObjects.get(kind),
                !kind.equals("cms-sha1") && !kind.equals("cms-rsa1024-sha256"), "SP800-78.3 current:");
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void currentChuidSignatureRejectionsUseTheIntendedAssertion(String database) throws Exception {
        run(database, 468, "sp800_78_Test_3_current", currentChuidObjects.get("plain"), true, "");
        run(database, 468, "sp800_78_Test_3_current", currentChuidObjects.get("cms-rsa3072-sha256"), true, "");
        run(database, 468, "sp800_78_Test_3_current", currentChuidObjects.get("cms-rsa1024-sha256"), false,
                "SP800-78.3 current: RSA CMS signer key must be 2048, 3072 or 4096 bits through 2030");
        run(database, 468, "sp800_78_Test_3_current", currentChuidObjects.get("cms-combined-rsa-oid"), false,
                "SP800-78.3 current: unsupported CMS signature algorithm 1.2.840.113549.1.1.11");
        run(database, 468, "sp800_78_Test_3_current", currentChuidObjects.get("cms-corrupt-signature"), false,
                "SP800-78.3 current: CMS signature does not verify");
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void remainingCmsDeclarationsReachTheirOwnAssertions(String database) throws Exception {
        String method = "sp800_78_Test_3_current";
        run(database, 468, method, currentChuidObjects.get("plain"), true, "");
        run(database, 468, method, cmsConsumerObject(269, "plain", "two-signers"), false,
                "SP800-78.3 current: exactly one CMS signer is required");
        byte[] unsigned = APDUUtils.getTLV(APDUConstants.DATA, fixtureFields(currentChuidObjects.get("plain"))
                .stream().filter(f -> !f.isTag(new BerTag(0x3e)))
                .map(f -> APDUUtils.getTLV(f.getTag().bytes, f.getBytesValue()))
                .reduce(new byte[0], ExistingCctRegressionTest::concat));
        run(database, 468, method, unsigned, false, "SP800-78.3 current: CMS signature is missing");
        for (String mutation : List.of("pss-digest-mismatch", "ecdsa-digest-mismatch", "ecdsa-null", "rsa-with-ec-key")) {
            String kind = mutation.startsWith("pss") ? "cms-pss-sha256-max" : "cms-p256-sha256";
            run(database, 468, method, currentChuidObjects.get(kind), true, "");
            byte[] changed = cmsConsumerObject(269, kind, mutation);
            if (mutation.equals("ecdsa-null")) assertFixtureCmsValid(fixtureChuidCms(changed));
            String reason = switch (mutation) {
                case "pss-digest-mismatch" -> "CMS PSS digest and parameters differ";
                case "ecdsa-digest-mismatch" -> "CMS ECDSA signature and digest differ";
                case "ecdsa-null" -> "ECDSA CMS signature parameters must be absent";
                case "rsa-with-ec-key" -> "RSA CMS signature requires an RSA signer key";
                default -> throw new AssertionError(mutation);
            };
            run(database, 468, method, changed, false, "SP800-78.3 current: " + reason);
        }
        // The two inconsistent digest sets deliberately retain the original
        // signature/attributes: these are declaration violations, not full CMS controls.
        for (String mutation : List.of("extra-sha1-digest", "missing-selected-digest"))
            run(database, 269, "CMS_Test_23_current", cmsConsumerObject(269, "plain", mutation), false,
                    mutation.equals("extra-sha1-digest") ? "Unsupported digest algorithm" : "2.16.840.1.101.3.4.2.1 is not a supported digest algorithm");
        for (int row : new int[]{350, 383, 406, 429})
            run(database, row, method, pssCertificate("SHA-1", "SHA-1", 20), false,
                    "SP800-78.3 current: RSA-PSS digest must be SHA-256 or SHA-384");
    }

    @ParameterizedTest(name="production CMS digest/key row {0}: {1}")
    @CsvSource({"269,plain,true", "269,cms-rsa4096-sha384,true", "269,cms-p256-sha256,true",
            "269,cms-p384-sha384,true", "269,cms-p256-sha384,false", "269,cms-p384-sha256,false",
            "269,cms-p521-sha384,false", "269,cms-sha1,false"})
    void currentCmsDigestAndSignerKeyThroughExistingAtom(int row, String kind, boolean pass) throws Exception {
        for (String database : List.of("PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"))
        run(database, row, "CMS_Test_23_current", currentChuidObjects.get(kind), pass,
                kind.equals("cms-sha1") ? "Unsupported digest algorithm" : kind.equals("cms-p521-sha384")
                        ? "521 is an invalid key length" : kind.equals("cms-p256-sha384") || kind.equals("cms-p384-sha256")
                        ? "EC signer curve and digest are incompatible" : "");
    }

    @ParameterizedTest(name="shared CMS row in {0}")
    @ValueSource(strings={"PIV_ICAM_Test_Cards.db", "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"})
    void cmsCurveDigestPairingPreservesOtherProfiles(String database) throws Exception {
        String method = database.startsWith("PIV-I_") ? "CMS_Test_23" : "CMS_Test_23_current";
        run(database, 269, method, currentChuidObjects.get("cms-p256-sha256"), true, "");
        run(database, 269, method, currentChuidObjects.get("cms-p256-sha384"), false,
                "EC signer curve and digest are incompatible");
    }

    static Stream<Arguments> currentKeyProfileCases() {
        return IntStream.of(351, 352, 384, 385, 407, 408, 430, 431).boxed().flatMap(row -> Stream.of(
                "rsa2048", "rsa3072", "p256", "p384", "rsa1024", "rsaExponent3", "p521")
                .map(kind -> Arguments.of(row, kind)));
    }

    @ParameterizedTest(name="production row {0}: current PIV key {1}")
    @MethodSource("currentKeyProfileCases")
    void currentKeyProfileThroughExistingAtom(int row, String kind) throws Exception {
        boolean pass = Set.of("rsa2048", "rsa3072", "p256", "p384").contains(kind);
        for (String database : List.of("PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"))
        run(database, row, "sp800_78_Test_1_current", keyProfileCertificates.get(kind),
                pass, "SP800-78.1:");
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void rsaSubjectPublicKeyIdentifierUsesTable4(String database) throws Exception {
        // SP 800-78-5 section 3.2.2/Table 4: subject-key and signature OIDs are distinct.
        assertAll(IntStream.of(351, 352, 384, 385, 407, 408, 430, 431).mapToObj(row -> () -> {
            run(database, row, "sp800_78_Test_1_current", keyProfileCertificates.get("rsaEncryptionSubjectKey"), true, "");
            run(database, row, "sp800_78_Test_1_current", keyProfileCertificates.get("rsaPssSubjectKey"), false,
                    "SP800-78.1: subject public key algorithm identifier must be rsaEncryption or id-ecPublicKey");
        }));
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void remainingKeyAndPssBoundariesUseExistingCases(String database) throws Exception {
        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");
        dsa.initialize(2048);
        KeyPair subject = dsa.generateKeyPair();
        byte[] dsaCertificate = subjectKeyCertificate(subject,
                SubjectPublicKeyInfo.getInstance(subject.getPublic().getEncoded()).getAlgorithm());
        byte[] largeRsa = APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{0x70}, cmsCertificates.get("cms-rsa4096-sha256").getEncoded()),
                new byte[]{0x71, 1, 0, (byte) 0xfe, 0}));
        for (int row : new int[]{351, 352, 384, 385, 407, 408, 430, 431}) {
            run(database, row, "sp800_78_Test_1_current", keyProfileCertificates.get("rsa2048"), true, "");
            run(database, row, "sp800_78_Test_1_current", dsaCertificate, false,
                    "SP800-78.1: subject public key algorithm identifier must be rsaEncryption or id-ecPublicKey");
            run(database, row, "sp800_78_Test_1_current", largeRsa, false,
                    "SP800-78.1: RSA modulus must be 2048 or 3072 bits through 2030");
        }
        for (int row : new int[]{350, 383, 406, 429}) {
            run(database, row, "sp800_78_Test_3_current", pssCertificate("SHA-256", "SHA-256", 32), true, "");
            for (ASN1Encodable parameters : new ASN1Encodable[]{null, DERNull.INSTANCE})
                run(database, row, "sp800_78_Test_3_current",
                        encodedCertificate(null, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, parameters)), false,
                        parameters == null || !Boolean.getBoolean("cct.regressionBC")
                                ? "SP800-78.3 current: RSA-PSS parameters are required"
                                : "SP800-78.3 current: malformed RSA-PSS parameters");
            run(database, row, "sp800_78_Test_3_current", pssCertificate("SHA-256", "MD5", 32), false,
                    Boolean.getBoolean("cct.regressionBC")
                            ? "SP800-78.3 current: RSA-PSS MGF1 digest is not supported by RFC 4055"
                            : "SP800-78.3 current: certificate could not be decoded");
        }
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void encodedEcKeysReachTheIntendedChecks(String database) throws Exception {
        boolean bc = Boolean.getBoolean("cct.regressionBC");
        for (int row : new int[]{351, 352, 384, 385, 407, 408, 430, 431}) {
            run(database, row, "sp800_78_Test_1_current", keyProfileCertificates.get("p256"), true, "");
            run(database, row, "sp800_78_Test_1_current", keyProfileCertificates.get("ecExplicitParameters"), false,
                    bc ? "SP800-78.1: EC key must use named curve P-256 or P-384"
                            : "SP800-78.1: certificate could not be decoded");
            run(database, row, "sp800_78_Test_1_current", keyProfileCertificates.get("ecDhIdentifier"), false,
                    bc ? "SP800-78.1: subject public key algorithm identifier must be rsaEncryption or id-ecPublicKey"
                            : "SP800-78.1: certificate could not be decoded");
        }
    }

    @ParameterizedTest
    @CsvSource({"PIV_Production_Cards.db,269", "PIV_ICAM_Test_Cards.db,269",
            "PIV_Production_Cards.db,468", "PIV_ICAM_Test_Cards.db,468",
            "PIV-I_Production_Cards.db,269", "PIV-I_ICAM_Test_Cards.db,269"})
    void cmsSignerRequiresAnApprovedNamedCurve(String database, int row) throws Exception {
        // 78-5 Table 2 and 78-4 Table 3-2 name the curves; field size is insufficient.
        String method = row == 468 ? "sp800_78_Test_3_current"
                : database.startsWith("PIV-I_") ? "CMS_Test_23" : "CMS_Test_23_current";
        run(database, row, method, currentChuidObjects.get("cms-p256-sha256"), true, "");
        run(database, row, method, currentChuidObjects.get("cms-p384-sha384"), true, "");
        String reason = row == 269 ? "EC signer must use named curve P-256 or P-384"
                : "SP800-78.3 current: ECDSA CMS signer must use named curve P-256 or P-384";
        run(database, row, method, currentChuidObjects.get("cms-brainpool256-sha256"), false, reason);
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void rsaCmsParametersMustBeNull(String database) throws Exception {
        // RFC 3370 section 3.2 / RFC 8017: rsaEncryption requires NULL.
        // RFC 4055's combined RSA-SHA2 certificate exception is a different identifier.
        run(database, 468, "sp800_78_Test_3_current", currentChuidObjects.get("plain"), true, "");
        run(database, 468, "sp800_78_Test_3_current", currentChuidObjects.get("cms-rsa-absent-parameters"), false,
                "SP800-78.3 current: RSA CMS signature parameters must be NULL");
    }

    @Test
    void cryptoAuditFixturesAreValid() throws Exception {
        // Independent ASN.1 and signature checks: no CCT atom or conformance helper.
        var provider = new BouncyCastleProvider();
        var positive = fixtureCertificate(keyProfileCertificates.get("rsaEncryptionSubjectKey"));
        var negative = fixtureCertificate(keyProfileCertificates.get("rsaPssSubjectKey"));
        assertEquals(PKCSObjectIdentifiers.rsaEncryption, positive.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm());
        assertEquals(DERNull.INSTANCE, positive.getSubjectPublicKeyInfo().getAlgorithm().getParameters());
        assertEquals(PKCSObjectIdentifiers.id_RSASSA_PSS, negative.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm());
        assertNull(negative.getSubjectPublicKeyInfo().getAlgorithm().getParameters());
        var publicKey = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(
                positive.getSubjectPublicKeyInfo().parsePublicKey());
        assertEquals(2048, publicKey.getModulus().bitLength());
        assertEquals(RSAKeyGenParameterSpec.F4, publicKey.getPublicExponent());
        assertEquals(positive.getSubjectPublicKeyInfo().getPublicKeyData(), negative.getSubjectPublicKeyInfo().getPublicKeyData());
        ASN1Sequence a = ASN1Sequence.getInstance(positive.toASN1Structure().getTBSCertificate());
        ASN1Sequence b = ASN1Sequence.getInstance(negative.toASN1Structure().getTBSCertificate());
        assertEquals(a.size(), b.size());
        int changed = 0;
        for (int i = 0; i < a.size(); i++) {
            if (!a.getObjectAt(i).equals(b.getObjectAt(i))) {
                assertEquals(positive.getSubjectPublicKeyInfo().toASN1Primitive(), a.getObjectAt(i).toASN1Primitive());
                assertEquals(negative.getSubjectPublicKeyInfo().toASN1Primitive(), b.getObjectAt(i).toASN1Primitive());
                changed++;
            }
        }
        assertEquals(1, changed, "Only the SPKI algorithm changes in TBSCertificate");
        var issuerVerifier = new JcaContentVerifierProviderBuilder().setProvider(provider).build(sanSigningKey.getPublic());
        assertTrue(positive.isSignatureValid(issuerVerifier));
        assertTrue(negative.isSignatureValid(issuerVerifier));

        for (var curve : Map.of("cms-p256-sha256", "1.2.840.10045.3.1.7",
                "cms-p384-sha384", "1.3.132.0.34",
                "cms-brainpool256-sha256", "1.3.36.3.3.2.8.1.1.7").entrySet()) {
            var cms = fixtureChuidCms(currentChuidObjects.get(curve.getKey()));
            var cert = assertFixtureCmsValid(cms);
            var spki = cert.getSubjectPublicKeyInfo();
            assertEquals("1.2.840.10045.2.1", spki.getAlgorithm().getAlgorithm().getId());
            assertEquals(curve.getValue(), ASN1ObjectIdentifier.getInstance(spki.getAlgorithm().getParameters()).getId());
            var key = new JcaX509CertificateConverter().setProvider(provider).getCertificate(cert).getPublicKey();
            assertEquals(curve.getKey().contains("p384") ? 384 : 256,
                    ((ECPublicKey) key).getParams().getCurve().getField().getFieldSize());
        }

        var cmsPositive = fixtureChuidCms(currentChuidObjects.get("plain"));
        var cmsNegative = fixtureChuidCms(currentChuidObjects.get("cms-rsa-absent-parameters"));
        assertFixtureCmsValid(cmsPositive);
        assertFixtureCmsValid(cmsNegative);
        var goodSigner = cmsPositive.getSignerInfos().getSigners().iterator().next();
        var badSigner = cmsNegative.getSignerInfos().getSigners().iterator().next();
        assertEquals(PKCSObjectIdentifiers.rsaEncryption.getId(), goodSigner.getEncryptionAlgOID());
        assertEquals(goodSigner.getEncryptionAlgOID(), badSigner.getEncryptionAlgOID());
        assertArrayEquals(new byte[]{5, 0}, goodSigner.getEncryptionAlgParams());
        assertNull(badSigner.getEncryptionAlgParams());
        assertArrayEquals(goodSigner.getSignature(), badSigner.getSignature());
        assertArrayEquals((byte[]) cmsPositive.getSignedContent().getContent(),
                (byte[]) cmsNegative.getSignedContent().getContent());
        SignedData goodData = SignedData.getInstance(cmsPositive.toASN1Structure().getContent());
        SignedData badData = SignedData.getInstance(cmsNegative.toASN1Structure().getContent());
        assertEquals(goodData.getCertificates(), badData.getCertificates());
        assertEquals(goodData.getDigestAlgorithms(), badData.getDigestAlgorithms());
        assertEquals(goodSigner.getSID(), badSigner.getSID());
        assertEquals(goodSigner.getDigestAlgorithmID(), badSigner.getDigestAlgorithmID());
        assertArrayEquals(goodSigner.getEncodedSignedAttributes(), badSigner.getEncodedSignedAttributes());
    }

    private static List<BerTlv> fixtureFields(byte[] raw) {
        byte[] body = new BerTlvParser().parse(raw).find(new BerTag(APDUConstants.DATA)).getBytesValue();
        return new BerTlvParser().parse(body).getList();
    }

    private static byte[] fixtureValue(byte[] raw, int tag) {
        return fixtureFields(raw).stream().filter(field -> field.isTag(new BerTag(tag)))
                .findFirst().orElseThrow().getBytesValue();
    }

    private static byte[] printedFixture() throws Exception {
        return Files.readAllBytes(Path.of(System.getProperty("cct.repository"),
                "cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/synthetic/printed.bin"));
    }

    private static byte[] cmsConsumerObject(int row, String kind) throws Exception {
        return cmsConsumerObject(row, kind, null);
    }

    private static byte[] cmsConsumerObject(int row, String kind, String mutation) throws Exception {
        if (row == 269) return mutation == null ? currentChuidObjects.get(kind)
                : chuidWithCms(currentChuidObjects.get(kind), mutateFixtureCms(
                        fixtureChuidCms(currentChuidObjects.get(kind)).getEncoded(), mutation));
        String identity = row + ":" + kind + ":" + mutation;
        if (cmsConsumerObjects.containsKey(identity)) return cmsConsumerObjects.get(identity);
        byte[] raw;
        if (row == 324) {
            // 73-5 section 3.1.7: same signer as CHUID, whose certificate supplies verification.
            var digestAlgorithm = fixtureChuidCms(currentChuidObjects.get(kind)).getSignerInfos()
                    .getSigners().iterator().next().getDigestAlgorithmID();
            var hash = java.security.MessageDigest.getInstance(digestAlgorithm.getAlgorithm().getId());
            var lds = new org.bouncycastle.asn1.icao.LDSSecurityObject(
                    digestAlgorithm,
                    new org.bouncycastle.asn1.icao.DataGroupHash[]{
                            new org.bouncycastle.asn1.icao.DataGroupHash(1, new DEROctetString(hash.digest(ccc))),
                            new org.bouncycastle.asn1.icao.DataGroupHash(2, new DEROctetString(hash.digest(printedFixture())))});
            raw = signedSecurityObject(kind, new byte[]{1, (byte) 0xdb, 0, 2, 0x30, 1}, lds);
            if (mutation != null) raw = APDUUtils.getTLV(APDUConstants.DATA, concat(
                    APDUUtils.getTLV(new byte[]{(byte) 0xba}, fixtureValue(raw, 0xba)),
                    concat(APDUUtils.getTLV(new byte[]{(byte) 0xbb}, mutateFixtureCms(fixtureValue(raw, 0xbb), mutation)),
                            new byte[]{(byte) 0xfe, 0})));
        } else {
            // Reuse existing header records; iris bytes are opaque test data, not an iris image.
            byte[] record;
            if (row == 338) record = "CCT synthetic iris CMS payload".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            else {
                byte[] template = row == 306 ? facialImage : APDUUtils.getTLV(APDUConstants.DATA,
                        Files.readAllBytes(Path.of(System.getProperty("cct.repository"),
                                "cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/synthetic/fingerprint-header.bin")));
                byte[] biometric = fixtureValue(template, 0xbc);
                record = Arrays.copyOfRange(biometric, 88, 88 + ByteBuffer.wrap(biometric).getInt(2));
            }
            byte[] header = new byte[88];
            header[0] = 3; header[1] = 0x0d;
            ByteBuffer.wrap(header).putInt(2, record.length)
                    .putShort(8, (short) (row == 338 ? 0x0101 : 0x001b))
                    .putShort(10, (short) (row == 286 ? 0x0201 : row == 306 ? 0x0501 : 0x0009));
            byte[] date = {20, 24, 1, 1, 0, 0, 0, 'Z'};
            for (int offset : new int[]{12, 20, 28}) System.arraycopy(date, 0, header, offset, date.length);
            header[29] = 29;
            header[38] = (byte) (row == 286 ? 8 : row == 306 ? 2 : 16);
            header[39] = (byte) (row == 286 ? 0x80 : row == 306 ? 0x20 : 0x40);
            header[40] = row == 286 ? 0 : (byte) -2;
            byte[] creator = "CCT regression".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            System.arraycopy(creator, 0, header, 41, creator.length);
            System.arraycopy(fixtureValue(chuid, 0x30), 0, header, 59, 25);
            var generator = cmsGenerator(kind, true, true);
            byte[] cms = null;
            // 76-2 Table 14 note 3 explicitly permits iteration when signature lengths vary.
            for (int attempt = 0; attempt < 128; attempt++) {
                byte[] signed = concat(header, record);
                byte[] encoded = generator.generate(new CMSProcessableByteArray(
                        new ASN1ObjectIdentifier("2.16.840.1.101.3.6.2"), signed), false).getEncoded();
                encoded = mutateFixtureCms(encoded, mutation);
                assertTrue(encoded.length < Short.MAX_VALUE);
                if (Short.toUnsignedInt(ByteBuffer.wrap(header).getShort(6)) == encoded.length) {
                    cms = encoded;
                    break;
                }
                ByteBuffer.wrap(header).putShort(6, (short) encoded.length);
            }
            assertNotNull(cms, "Signed CBEFF header must record its actual signature length");
            raw = APDUUtils.getTLV(APDUConstants.DATA, concat(APDUUtils.getTLV(new byte[]{(byte) 0xbc},
                    concat(concat(header, record), cms)), new byte[]{(byte) 0xfe, 0}));
        }
        cmsConsumerObjects.put(identity, raw);
        return raw;
    }

    private static byte[] signedSecurityObject(String kind, byte[] mapping,
            org.bouncycastle.asn1.icao.LDSSecurityObject lds) throws Exception {
        byte[] cms = cmsGenerator(kind, false, false).generate(new CMSProcessableByteArray(
                new ASN1ObjectIdentifier("2.23.136.1.1.1"), lds.getEncoded()), true).getEncoded();
        return APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{(byte) 0xba}, mapping),
                concat(APDUUtils.getTLV(new byte[]{(byte) 0xbb}, cms), new byte[]{(byte) 0xfe, 0})));
    }

    private static CMSSignedData fixtureCms(int row, byte[] raw) throws Exception {
        if (row == 269) return fixtureChuidCms(raw);
        if (row == 324) return new CMSSignedData(fixtureValue(raw, 0xbb));
        byte[] biometric = fixtureValue(raw, 0xbc);
        int signatureOffset = 88 + ByteBuffer.wrap(biometric).getInt(2);
        assertEquals(biometric.length - signatureOffset, Short.toUnsignedInt(ByteBuffer.wrap(biometric).getShort(6)));
        return new CMSSignedData(new CMSProcessableByteArray(Arrays.copyOf(biometric, signatureOffset)),
                Arrays.copyOfRange(biometric, signatureOffset, biometric.length));
    }

    private static byte[] mutateFixtureCms(byte[] encoded, String mutation) throws Exception {
        if (mutation == null) return encoded;
        ContentInfo content = ContentInfo.getInstance(encoded);
        SignedData data = SignedData.getInstance(content.getContent());
        ASN1Set certificates = data.getCertificates();
        ASN1Set signers = data.getSignerInfos();
        ASN1Set digests = data.getDigestAlgorithms();
        if (mutation.equals("extra-certificate")) {
            ASN1EncodableVector bag = new ASN1EncodableVector();
            if (certificates != null) for (ASN1Encodable certificate : certificates) bag.add(certificate);
            // SO's one deliberately forbidden certificate is its matching CHUID signer.
            X509CertificateHolder extra = certificates == null
                    ? new X509CertificateHolder(cmsCertificates.get("plain").getEncoded())
                    : fixtureCertificate(keyProfileCertificates.get("rsa2048"));
            bag.add(extra.toASN1Structure());
            certificates = new DERSet(bag);
        } else if (mutation.equals("omit-certificate")) certificates = null;
        else if (mutation.equals("two-signers")) signers = new DERSet(new ASN1Encodable[]{signers.getObjectAt(0), signers.getObjectAt(0)});
        else if (mutation.equals("wrong-identifier")) {
            SignerInfo signer = SignerInfo.getInstance(signers.getObjectAt(0));
            var sid = org.bouncycastle.asn1.cms.IssuerAndSerialNumber.getInstance(signer.getSID().getId());
            signers = new DERSet(new SignerInfo(new org.bouncycastle.asn1.cms.SignerIdentifier(
                    new org.bouncycastle.asn1.cms.IssuerAndSerialNumber(sid.getName(), sid.getSerialNumber().getValue().add(BigInteger.ONE))),
                    signer.getDigestAlgorithm(), signer.getAuthenticatedAttributes(), signer.getDigestEncryptionAlgorithm(),
                    signer.getEncryptedDigest(), signer.getUnauthenticatedAttributes()));
        } else if (Set.of("pss-digest-mismatch", "ecdsa-digest-mismatch", "ecdsa-null", "rsa-with-ec-key").contains(mutation)) {
            SignerInfo original = SignerInfo.getInstance(signers.getObjectAt(0));
            AlgorithmIdentifier algorithm = switch (mutation) {
                case "pss-digest-mismatch" -> new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS,
                        new org.bouncycastle.asn1.pkcs.RSASSAPSSparams(
                                new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2")),
                                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1,
                                        new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"))),
                                new ASN1Integer(32), new ASN1Integer(1)));
                case "ecdsa-digest-mismatch" -> new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.3"));
                case "ecdsa-null" -> new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"), DERNull.INSTANCE);
                case "rsa-with-ec-key" -> new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
                default -> throw new AssertionError(mutation);
            };
            signers = new DERSet(new SignerInfo(original.getSID(), original.getDigestAlgorithm(),
                    original.getAuthenticatedAttributes(), algorithm, original.getEncryptedDigest(), original.getUnauthenticatedAttributes()));
        } else if (mutation.equals("extra-sha1-digest")) {
            digests = new DERSet(new ASN1Encodable[]{digests.getObjectAt(0),
                    new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"))});
        } else if (mutation.equals("missing-selected-digest")) digests = new DERSet();
        else throw new IllegalArgumentException(mutation);
        return new ContentInfo(content.getContentType(), new SignedData(digests,
                data.getEncapContentInfo(), certificates, data.getCRLs(), signers)).getEncoded();
    }

    private static X509CertificateHolder fixtureCertificate(byte[] raw) throws Exception {
        return new X509CertificateHolder(fixtureFields(raw).stream()
                .filter(field -> field.isTag(new BerTag(new byte[]{0x70})))
                .findFirst().orElseThrow().getBytesValue());
    }

    private static CMSSignedData fixtureChuidCms(byte[] raw) throws Exception {
        var content = new java.io.ByteArrayOutputStream();
        byte[] signature = null;
        for (BerTlv field : fixtureFields(raw)) {
            if (field.isTag(new BerTag(new byte[]{0x3e}))) signature = field.getBytesValue();
            else if (!field.isTag(new BerTag(new byte[]{(byte) 0xee})))
                content.writeBytes(APDUUtils.getTLV(field.getTag().bytes, field.getBytesValue()));
        }
        assertNotNull(signature);
        return new CMSSignedData(new CMSProcessableByteArray(content.toByteArray()), signature);
    }

    private static X509CertificateHolder assertFixtureCmsValid(CMSSignedData cms) throws Exception {
        return assertFixtureCmsValid(cms, null);
    }

    private static X509CertificateHolder assertFixtureCmsValid(CMSSignedData cms,
            X509CertificateHolder externalSigner) throws Exception {
        assertEquals(1, cms.getSignerInfos().size());
        var signer = cms.getSignerInfos().getSigners().iterator().next();
        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> matches = cms.getCertificates().getMatches(signer.getSID());
        assertEquals(externalSigner == null ? 1 : 0, matches.size(),
                "The signer certificate must come from the expected embedded or CHUID source");
        X509CertificateHolder cert = externalSigner == null ? matches.iterator().next() : externalSigner;
        assertTrue(signer.getSID().match(cert), "SignerIdentifier must match its certificate");
        var provider = new BouncyCastleProvider();
        assertTrue(cert.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(provider)
                .build(cert.getSubjectPublicKeyInfo())), "Fixture signer certificate must verify");
        assertTrue(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(provider).build(cert)),
                "CMS signed attributes, message digest and signature must verify independently of CCT");
        return cert;
    }

    private static byte[] chuidWithRsaCmsParameters(byte[] raw, ASN1Encodable parameters) throws Exception {
        ContentInfo content = ContentInfo.getInstance(fixtureChuidCms(raw).getEncoded());
        SignedData data = SignedData.getInstance(content.getContent());
        SignerInfo signer = SignerInfo.getInstance(data.getSignerInfos().getObjectAt(0));
        SignerInfo changed = new SignerInfo(signer.getSID(), signer.getDigestAlgorithm(),
                signer.getAuthenticatedAttributes(), new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, parameters),
                signer.getEncryptedDigest(), signer.getUnauthenticatedAttributes());
        return chuidWithCms(raw, new ContentInfo(content.getContentType(), new SignedData(data.getDigestAlgorithms(),
                data.getEncapContentInfo(), data.getCertificates(), data.getCRLs(), new DERSet(changed))).getEncoded());
    }

    private static byte[] chuidWithCms(byte[] raw, byte[] cms) {
        var fields = fixtureFields(raw);
        var encoded = new java.io.ByteArrayOutputStream();
        for (BerTlv field : fields) {
            byte[] value = field.getBytesValue();
            if (field.isTag(new BerTag(new byte[]{0x3e}))) {
                value = cms;
            }
            encoded.writeBytes(APDUUtils.getTLV(field.getTag().bytes, value));
        }
        return APDUUtils.getTLV(APDUConstants.DATA, encoded.toByteArray());
    }

    @Test
    void dataModelAuditFixturesAreValid() throws Exception {
        for (String kind : List.of("plain", "EE", "32", "33", "unknown", "guid-first", "guid-delayed",
                "holder-absent", "holder-v1", "holder-v5", "holder-variant", "holder-short", "holder-before-date",
                "date-month-13", "date-nonleap", "date-short", "date-nondigit", "date-nonascii", "date-leap")) {
            byte[] raw = currentChuidObjects.get(kind);
            assertFixtureCmsValid(fixtureChuidCms(raw));
            if (kind.startsWith("holder-") && !kind.equals("holder-absent")) {
                byte[] holder = fixtureValue(raw, 0x36);
                assertEquals(kind.equals("holder-short") ? 15 : 16, holder.length);
                assertEquals(kind.equals("holder-v1") ? 1 : kind.equals("holder-v5") ? 5 : 4, (holder[6] & 0xf0) >>> 4);
                assertEquals(kind.equals("holder-variant") ? 0 : 2, (holder[8] & 0xc0) >>> 6);
            }
        }
        // EE is outside the signed content. Its addition must not alter either
        // signed bytes or the deterministic RSA signature of the plain object.
        var plain = fixtureChuidCms(currentChuidObjects.get("plain"));
        var ee = fixtureChuidCms(currentChuidObjects.get("EE"));
        assertArrayEquals((byte[]) plain.getSignedContent().getContent(), (byte[]) ee.getSignedContent().getContent());
        assertArrayEquals(plain.getSignerInfos().getSigners().iterator().next().getSignature(),
                ee.getSignerInfos().getSigners().iterator().next().getSignature());
        byte[] changed = currentChuidObjects.get("plain").clone();
        byte[] date = fixtureValue(changed, 0x35);
        int index = -1;
        for (int i = 0; i <= changed.length - date.length; i++)
            if (Arrays.equals(date, Arrays.copyOfRange(changed, i, i + date.length))) { index = i; break; }
        assertTrue(index >= 0);
        changed[index + 7] ^= 1;
        var corrupted = fixtureChuidCms(changed);
        var signer = corrupted.getSignerInfos().getSigners().iterator().next();
        var certificate = corrupted.getCertificates().getMatches(signer.getSID()).iterator().next();
        assertThrows(org.bouncycastle.cms.CMSSignerDigestMismatchException.class,
                () -> signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider())
                        .build((X509CertificateHolder) certificate)));
    }

    @ParameterizedTest(name="current CCC: {0}")
    @ValueSource(strings={"plain", "E3", "B4"})
    void currentCccThroughExistingAtom(String kind) throws Exception {
        for (String database : List.of("PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"))
            run(database, 11, "sp800_73_5_Test_4", cccWithOptional(kind), kind.equals("plain"),
                    "SP800-73-5 CCC: eliminated tag " + kind + " is present");
    }

    @Test void historicalCccStillPermitsDeprecatedOptionalFields() throws Exception {
        for (String database : List.of("PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"))
            run(database, 11, "sp800_73_4_Test_4", cccWithOptional("both"), true, "");
    }

    @ParameterizedTest
    @ValueSource(strings = {"PIV_Production_Cards.db", "PIV-I_Production_Cards.db"})
    void cccRejectsAnUnlistedLeadingTagThroughExistingCase(String database) throws Exception {
        run(database, 14, "sp800_73_4_Test_56", cccWithOptional("plain"), true, "");
        run(database, 14, "sp800_73_4_Test_56", cccWithOptional("F8-first"), false,
                "Unlisted or out-of-order tag");
    }

    static Stream<Arguments> currentChuidCases() {
        return Stream.of(
                Arguments.of(23, "sp800_73_5_Test_43", "plain", true, ""),
                Arguments.of(23, "sp800_73_5_Test_43", "EE", false, "SP800-73-5 CHUID:"),
                Arguments.of(23, "sp800_73_5_Test_43", "guid-first", false, "SP800-73-5 CHUID:"),
                Arguments.of(24, "sp800_73_5_Test_11", "plain", true, ""),
                Arguments.of(24, "sp800_73_5_Test_11", "32", false, "SP800-73-5 CHUID:"),
                Arguments.of(24, "sp800_73_5_Test_11", "33", false, "SP800-73-5 CHUID:"),
                Arguments.of(26, "sp800_73_5_Test_45", "plain", true, ""),
                Arguments.of(26, "sp800_73_5_Test_45", "32", false, "SP800-73-5 CHUID:"),
                Arguments.of(26, "sp800_73_5_Test_45", "33", false, "SP800-73-5 CHUID:"),
                Arguments.of(26, "sp800_73_5_Test_45", "guid-delayed", false,
                        "SP800-73-5 CHUID: tag 34 must immediately follow tag 30"),
                Arguments.of(35, "sp800_73_5_Test_9", "plain", true, ""),
                Arguments.of(35, "sp800_73_5_Test_9", "EE", false, "SP800-73-5 CHUID:"),
                Arguments.of(36, "sp800_73_5_Test_17", "plain", true, ""),
                Arguments.of(36, "sp800_73_5_Test_17", "holder-absent", true, ""),
                Arguments.of(36, "sp800_73_5_Test_17", "EE", false, "SP800-73-5 CHUID:"),
                Arguments.of(36, "sp800_73_5_Test_17", "32", false, "SP800-73-5 CHUID:"),
                Arguments.of(36, "sp800_73_5_Test_17", "33", false, "SP800-73-5 CHUID:"),
                Arguments.of(36, "sp800_73_5_Test_17", "unknown", false, "SP800-73-5 CHUID:"));
    }

    @ParameterizedTest(name="production CHUID row {0}: {2}") @MethodSource("currentChuidCases")
    void currentChuidThroughExistingAtom(int row, String method, String kind, boolean pass,
                                         String failurePrefix) throws Exception {
        for (String database : List.of("PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"))
            run(database, row, method, currentChuidObjects.get(kind), pass, failurePrefix);
    }

    @Test void historicalChuidStillPermitsDeprecatedFields() throws Exception {
        run("PIV-I_Production_Cards.db", 35, "sp800_73_4_Test_9", currentChuidObjects.get("EE"), true, "");
        run("PIV-I_Production_Cards.db", 24, "sp800_73_4_Test_11", currentChuidObjects.get("32"), true, "");
        run("PIV-I_Production_Cards.db", 24, "sp800_73_4_Test_11", currentChuidObjects.get("33"), true, "");
    }

    static Stream<Arguments> currentHolderUuidCases() {
        return IntStream.of(29, 40).boxed().flatMap(row -> Stream.of(
                Arguments.of(row, "plain", true),
                Arguments.of(row, "holder-absent", true),
                Arguments.of(row, "holder-v1", false),
                Arguments.of(row, "holder-v5", false),
                Arguments.of(row, "holder-variant", false),
                Arguments.of(row, "holder-short", false),
                Arguments.of(row, "holder-before-date", false)));
    }

    @ParameterizedTest(name="production holder UUID row {0}: {1}") @MethodSource("currentHolderUuidCases")
    void currentHolderUuidThroughExistingAtom(int row, String kind, boolean pass) throws Exception {
        for (String database : List.of("PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"))
            run(database, row, "sp800_73_5_Test_13", currentChuidObjects.get(kind), pass, "SP800-73-5 CHUID:");
    }

    @Test void historicalHolderUuidStillPermitsOlderVersions() throws Exception {
        run("PIV-I_Production_Cards.db", 40, "sp800_73_4_Test_13",
                currentChuidObjects.get("holder-v1"), true, "");
        run("PIV-I_Production_Cards.db", 40, "sp800_73_4_Test_13",
                currentChuidObjects.get("holder-v5"), true, "");
    }

    static Stream<Arguments> currentCertificateContainerCases() {
        return Stream.of(
                Arguments.of(51, "sp800_73_5_Test_20"), Arguments.of(95, "sp800_73_5_Test_20"),
                Arguments.of(107, "sp800_73_5_Test_20"), Arguments.of(119, "sp800_73_5_Test_20"),
                Arguments.of(52, "sp800_73_5_Test_21"), Arguments.of(97, "sp800_73_5_Test_21"),
                Arguments.of(108, "sp800_73_5_Test_21"), Arguments.of(120, "sp800_73_5_Test_21"),
                Arguments.of(53, "sp800_73_5_Test_22"), Arguments.of(96, "sp800_73_5_Test_22"),
                Arguments.of(109, "sp800_73_5_Test_22"), Arguments.of(121, "sp800_73_5_Test_22"));
    }

    @ParameterizedTest(name="production active certificate row {0}: {1}")
    @MethodSource("currentCertificateContainerCases")
    void currentCertificateContainerThroughExistingAtom(int row, String method) throws Exception {
        run(row, method, certificateContainerWithField(null), true, "");
        run(row, method, certificateContainerWithField((byte) 0x72), false, "SP800-73-5 X509:");
        if (method.endsWith("22"))
            run(row, method, certificateContainerWithField((byte) 0x73), false, "SP800-73-5 X509:");
    }

    @Test void historicalCertificateContainerStillPermitsMscuid() throws Exception {
        byte[] withMscuid = certificateContainerWithField((byte) 0x72);
        run("PIV-I_Production_Cards.db", 51, "sp800_73_4_Test_20", withMscuid, true, "");
        run("PIV-I_Production_Cards.db", 52, "sp800_73_4_Test_21", withMscuid, true, "");
        run("PIV-I_Production_Cards.db", 53, "sp800_73_4_Test_22", withMscuid, true, "");
    }

    private static byte[] certificateContainerWithField(Byte field) {
        byte[] valid = keyProfileCertificates.get("rsa2048");
        BerTlvs outer = new BerTlvParser(new CCTTlvLogger(ExistingCctRegressionTest.class)).parse(valid);
        byte[] body = outer.getList().get(0).getBytesValue();
        assertEquals((byte) 0xfe, body[body.length - 2]);
        assertEquals(0, body[body.length - 1]);
        byte[] added = field == null ? new byte[0] : APDUUtils.getTLV(new byte[]{field}, new byte[]{1});
        return APDUUtils.getTLV(APDUConstants.DATA,
                concat(concat(Arrays.copyOf(body, body.length - 2), added), new byte[]{(byte) 0xfe, 0}));
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void activeCertificatePresenceAndOrderingUseOriginalCases(String database) throws Exception {
        byte[] valid = certificateContainerWithField(null);
        byte[] cert = APDUUtils.getTLV(new byte[]{0x70}, fixtureValue(valid, 0x70));
        byte[] info = new byte[]{0x71, 1, 0}, end = new byte[]{(byte) 0xfe, 0};
        for (int row : new int[]{50, 94, 106, 118}) {
            run(database, row, "sp800_73_4_Test_19", valid, true, "");
            // Missing certificate is rejected deliberately by the existing decoder.
            var missing = run(database, row, "sp800_73_4_Test_19",
                    APDUUtils.getTLV(APDUConstants.DATA, concat(info, end)),
                    TestExecutionResult.Status.FAILED, "", null, null);
            assertTrue(missing.getThrowable().orElseThrow().getCause() instanceof ConformanceTestException);
            assertTrue(missing.getThrowable().orElseThrow().getCause().getMessage().startsWith("Failed to decode object for OID "));
            run(database, row, "sp800_73_4_Test_19",
                    APDUUtils.getTLV(APDUConstants.DATA, concat(cert, end)), false, "Certificate container: tag 71 is required");
            run(database, row, "sp800_73_4_Test_19",
                    APDUUtils.getTLV(APDUConstants.DATA, concat(info, concat(cert, end))), false, "Certificate container: tag 71 must immediately follow tag 70");
        }
        for (int row : new int[]{52, 97, 108, 120}) {
            run(database, row, "sp800_73_5_Test_21", valid, true, "");
            run(database, row, "sp800_73_5_Test_21",
                    APDUUtils.getTLV(APDUConstants.DATA, concat(cert, concat(end, info))), false,
                    "SP800-73-5 X509: tag 0xFE must immediately follow tag 0x71");
            run(database, row, "sp800_73_5_Test_21",
                    APDUUtils.getTLV(APDUConstants.DATA, concat(cert, info)), false,
                    "SP800-73-5 X509: tag 0xFE must immediately follow tag 0x71");
        }
    }

    @ParameterizedTest
    @ValueSource(strings={"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
            "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"})
    void sharedMembershipUsesEachExistingContainer(String database) throws Exception {
        // Includes disabled ICAM routes as explicit diagnostics.
        for (int row : new int[]{14, 21, 49, 61, 69, 83, 93, 105, 117, 129, 145}) {
            byte[] valid = switch (row) {
                case 14 -> cccWithOptional("plain");
                case 21 -> currentChuidObjects.get("plain");
                case 49, 93, 105, 117 -> keyProfileCertificates.get("rsa2048");
                case 61 -> cmsConsumerObject(286, "plain");
                case 83 -> cmsConsumerObject(306, "plain");
                case 129 -> cmsConsumerObject(324, "plain");
                case 69 -> printedContainerFixture();
                case 145 -> Files.readAllBytes(Path.of(System.getProperty("cct.repository"),
                        "cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/synthetic/discovery.bin"));
                default -> throw new AssertionError(row);
            };
            run(database, row, "sp800_73_4_Test_56", valid, true, "");
            BerTlv outer = new BerTlvParser().parse(valid).getList().get(0);
            byte[] unknown = APDUUtils.getTLV(outer.getTag().bytes,
                    concat(new byte[]{(byte) 0xf8, 0}, outer.getBytesValue()));
            run(database, row, "sp800_73_4_Test_56", unknown, false, "Unlisted or out-of-order tag");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void keyHistoryConditionalFieldsUseOriginalCase(String database) throws Exception {
        String method = "sp800_73_4_Test_57";
        KeyHistoryObject reused = new KeyHistoryObject();
        reused.setOID(APDUConstants.KEY_HISTORY_OBJECT_OID);
        reused.setContainerName(APDUConstants.getFileNameForOid(APDUConstants.KEY_HISTORY_OBJECT_OID));
        reused.setBytes(keyHistory(0, 1, "http://example.com/" + "0".repeat(64), true));
        assertTrue(reused.decode());
        assertNotNull(reused.getOffCardCertUrl());
        reused.setBytes(keyHistory(0, 0, null, true));
        assertTrue(reused.decode());
        assertNull(reused.getOffCardCertUrl());
        assertEquals(0, reused.getKeysWithOffCardCerts());
        assertEquals(3, reused.getTagList().size());
        reused.setBytes(APDUUtils.getTLV(APDUConstants.DATA, new byte[]{(byte) 0xc2, 1, 0, (byte) 0xfe, 0}));
        assertFalse(reused.decode());
        assertEquals(-1, reused.getKeysWithOnCardCerts(), "Prior successful decoding cannot supply a missing C1");
        byte[] control = keyHistory(0, 0, null, true);
        // Literal BER lengths/values establish these fixtures without the CCT decoder.
        assertArrayEquals(java.util.HexFormat.of().parseHex("5308c10100c20100fe00"), control);
        run(database, 150, method, control, true, "");
        for (String missingField : List.of("5305c20100fe00", "5305c10100fe00")) {
            var result = run(database, 150, method, java.util.HexFormat.of().parseHex(missingField),
                    TestExecutionResult.Status.FAILED, "", null, null);
            // Missing mandatory counts deliberately return false from decode().
            // An unrelated exception or a later field assertion is not this evidence.
            Throwable cause = result.getThrowable().orElseThrow().getCause();
            assertTrue(cause instanceof ConformanceTestException, "Expected deliberate decode rejection: " + cause);
            assertEquals("Failed to decode object for OID " + APDUConstants.KEY_HISTORY_OBJECT_OID,
                    cause.getMessage());
        }
        // Table 20 fixes both counter widths at one byte and FE at zero bytes.
        for (String badWidth : List.of("5307c100c20100fe00", "5309c1020000c20100fe00",
                "5307c10100c200fe00", "5309c10100c2020000fe00", "5309c10100c20100fe0100"))
            run(database, 150, method, java.util.HexFormat.of().parseHex(badWidth), false,
                    "SP800-73 Key History: field length exceeds Table 20");
        for (String badOrder : List.of("5308c20100c10100fe00", "530bc10100c10100c20100fe00"))
            run(database, 150, method, java.util.HexFormat.of().parseHex(badOrder), false,
                    "SP800-73 Key History: expected C1, C2, conditional F3, FE in order");
        String url = "http://example.com/" + "0".repeat(64);
        run(database, 150, method, keyHistory(0, 1, url, true), true, "");
        run(database, 150, method, keyHistory(0, 1, "http://example.com./" + "0".repeat(64), true), true, "");
        run(database, 150, method, keyHistory(0, 1, "http://123.example.com/" + "0".repeat(64), true), true, "");
        for (String literal : List.of("127.0.0.1", "192.0.2.1"))
            run(database, 150, method, keyHistory(0, 1, "http://" + literal + "/" + "0".repeat(64), true),
                    false, "SP800-73 Key History: offCardCertURL host must be a DNS name");
        run(database, 150, method, keyHistory(1, 0, null, true), true, "");
        run(database, 150, method, keyHistory(1, 0, url, true), true, "");
        for (int onCard : new int[]{0, 10, 20})
            run(database, 150, method, keyHistory(onCard, 20 - onCard, onCard == 20 ? null : url, true),
                    true, "");
        String longestUrl = "http://" + "a".repeat(42) + ".com/" + "0".repeat(64);
        assertEquals(118, longestUrl.getBytes(java.nio.charset.StandardCharsets.US_ASCII).length);
        assertEquals("a".repeat(42) + ".com", java.net.URI.create(longestUrl).getHost());
        run(database, 150, method, keyHistory(0, 1, longestUrl, true), true, "");
        run(database, 150, method, keyHistory(0, 1, longestUrl.replace(".com", "a.com"), true), false,
                "SP800-73 Key History: field length exceeds Table 20");
        run(database, 150, method, keyHistory(0, 1, "http://example.com/" + "aB".repeat(32), true), true, "");
        for (String hash : List.of("0".repeat(63), "0".repeat(65), "0".repeat(63) + "G"))
            run(database, 150, method, keyHistory(0, 1, "http://example.com/" + hash, true), false,
                    "SP800-73 Key History: offCardCertURL must be an HTTP");
        run(database, 150, method, keyHistory(0, 1, null, true), false,
                "SP800-73 Key History: offCardCertURL is required");
        run(database, 150, method, keyHistory(0, 0, url, true), false,
                "SP800-73 Key History: offCardCertURL must be absent");
        run(database, 150, method, keyHistory(21, 0, null, true), false,
                "SP800-73 Key History: retired key count");
        run(database, 150, method, keyHistory(10, 11, url, true), false,
                "SP800-73 Key History: retired key count");
        run(database, 150, method, keyHistory(0, 1, "https://example.com/" + "0".repeat(64), true),
                false, "SP800-73 Key History: offCardCertURL must be an HTTP");
        run(database, 150, method, keyHistory(0, 1, "http://bad..example/" + "0".repeat(64), true),
                false, "SP800-73 Key History: offCardCertURL must be an HTTP");
        run(database, 150, method, keyHistory(0, 1, "http://example.com../" + "0".repeat(64), true),
                false, "SP800-73 Key History: offCardCertURL must be an HTTP");
        run(database, 150, method, keyHistory(0, 1, "http://./" + "0".repeat(64), true),
                false, "SP800-73 Key History: offCardCertURL must be an HTTP");
        run(database, 150, method, keyHistory(0, 0, null, false), false,
                "SP800-73 Key History: expected C1, C2, conditional F3, FE");
        byte[] unknownField = APDUUtils.getTLV(APDUConstants.DATA,
                java.util.HexFormat.of().parseHex("f800c10100c20100fe00"));
        run(database, 150, method, unknownField, false,
                "SP800-73 Key History: expected C1, C2, conditional F3, FE in order");
        byte[] longC1 = APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{(byte) 0xc1}, new byte[]{0, 0}),
                concat(APDUUtils.getTLV(new byte[]{(byte) 0xc2}, new byte[]{0}),
                        new byte[]{(byte) 0xfe, 0})));
        run(database, 150, method, longC1, false,
                "SP800-73 Key History: field length exceeds Table 20");
        run(database, 150, method, null, TestExecutionResult.Status.ABORTED,
                PlaceholderTests.UNSUPPORTED_MESSAGE);
        run(database, 150, method, keyHistory(0, 0, null, true),
                TestExecutionResult.Status.FAILED, "Failed to retrieve data object",
                MiddlewareStatus.PIV_CONNECTION_FAILURE);
    }

    private static byte[] keyHistory(int onCard, int offCard, String url, boolean includeFe) {
        byte[] body = concat(APDUUtils.getTLV(new byte[]{(byte) 0xc1}, new byte[]{(byte) onCard}),
                APDUUtils.getTLV(new byte[]{(byte) 0xc2}, new byte[]{(byte) offCard}));
        if (url != null) body = concat(body, APDUUtils.getTLV(new byte[]{(byte) 0xf3},
                url.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        if (includeFe) body = concat(body, new byte[]{(byte) 0xfe, 0});
        return APDUUtils.getTLV(APDUConstants.DATA, body);
    }

    @ParameterizedTest(name="certificate policy field: {0}, row {1}")
    @MethodSource("policyRoutes")
    void certificatePolicyFieldsDoNotDependOnPathBuilding(String database, int row) throws Exception {
        // Reproduce the installed tool's trust-file layout for the old atom too.
        // The synthetic issuing root is deliberately outside that operator trust set.
        Path installedStore = Path.of("x509-certs/cacerts.jks");
        Files.createDirectories(installedStore.getParent());
        if (!Files.exists(installedStore)) Files.copy(Path.of(System.getProperty("cct.repository"),
                "conformancelib/src/main/resources/x509-certs/cacerts.jks"), installedStore);
        List<String> policies;
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:file:" + Path.of(
                System.getProperty("cct.repository"), "conformancelib/testdata", database) + "?mode=ro")) {
            TestCaseModel testCase = new TestCaseModel(new ConformanceTestDatabase(connection));
            testCase.retrieveForId(row);
            var step = testCase.getSteps().stream().filter(s -> s.getTestMethodName().equals("PKIX_Test_6")).findFirst().orElseThrow();
            String entry = step.getParameters().stream().filter(p -> p.startsWith(testCase.getContainer() + ":")).findFirst().orElseThrow();
            policies = Arrays.asList(entry.substring(entry.indexOf(':') + 1).split("\\|"));
        }
        KeyPair issuerKey = sanSigningKey;
        X500Name issuer = new X500Name("CN=CCT policy fixture CA");
        KeyPair subjectKey = cmsKeys.get("plain");
        X500Name subject = new X500Name("CN=CCT policy fixture leaf");
        X509CertificateHolder root = policyCertificate(issuerKey, issuer, issuerKey, issuer, true, List.of(), null);
        for (String policy : policies) {
            X509CertificateHolder cert = policyCertificate(subjectKey, subject, issuerKey, issuer, false, List.of(policy), null);
            assertTrue(cert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(root.getSubjectPublicKeyInfo())));
            assertEquals(policy, CertificatePolicies.fromExtensions(cert.getExtensions()).getPolicyInformation()[0].getPolicyIdentifier().getId());
            run(database, row, "PKIX_Test_6", policyObject(row, cert, subjectKey), true, "");
        }
        for (List<String> invalid : List.of(List.<String>of(), List.of("1.2.3.4"), List.of("2.5.29.32.0"))) {
            X509CertificateHolder cert = policyCertificate(subjectKey, subject, issuerKey, issuer, false, invalid, null);
            assertTrue(cert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(root.getSubjectPublicKeyInfo())));
            run(database, row, "PKIX_Test_6", policyObject(row, cert, subjectKey), false,
                    "Certificate does not assert a required policy OID");
        }
    }

    static Stream<Arguments> policyRoutes() {
        return Stream.of("PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
                "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db").flatMap(database ->
                IntStream.of(359, 394, 417, 437, 479).mapToObj(row -> Arguments.of(database, row)));
    }

    @Test
    void validatorRequiresRequestedPathPoliciesAndPreservesMappings() throws Exception {
        String issuerPolicy = "1.2.3.4", subjectPolicy = "1.2.3.5";
        KeyPair rootKey = rsa(2048, RSAKeyGenParameterSpec.F4), leafKey = sanSigningKey;
        assertFalse(Arrays.equals(rootKey.getPublic().getEncoded(), leafKey.getPublic().getEncoded()));
        X500Name rootName = new X500Name("CN=CCT path root"), leafName = new X500Name("CN=CCT path leaf");
        var root = policyCertificate(rootKey, rootName, rootKey, rootName, true, List.of(), null);
        var good = policyCertificate(leafKey, leafName, rootKey, rootName, false, List.of(issuerPolicy), null);
        var wrong = policyCertificate(leafKey, leafName, rootKey, rootName, false, List.of(subjectPolicy), null);
        var absent = policyCertificate(leafKey, leafName, rootKey, rootName, false, List.of(), null);
        var converter = new JcaX509CertificateConverter();
        for (var cert : List.of(root, good, wrong, absent))
            assertTrue(cert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(root.getSubjectPublicKeyInfo())));
        Validator validator = new Validator();
        String provider = Boolean.getBoolean("cct.regressionBC") ? "BC" : "SunRsaSign";
        validator.setProvider(provider); validator.setCertPathBuilder(provider);
        validator.setDownloadAia(false); validator.setCaFileName(null);
        assertTrue(validator.isValid(converter.getCertificate(good), issuerPolicy, converter.getCertificate(root)));
        assertNotNull(validator.getCertPath());
        assertFalse(validator.isValid(converter.getCertificate(wrong), issuerPolicy, converter.getCertificate(root)),
                "A valid signature is insufficient when the requested path policy is absent");
        assertNull(validator.getCertPath(), "A failed validation must not retain an earlier path");
        assertFalse(validator.isValid(converter.getCertificate(absent), issuerPolicy, converter.getCertificate(root)));
        assertTrue(validator.isValid(converter.getCertificate(good), issuerPolicy + "|" + subjectPolicy, converter.getCertificate(root)));
        assertTrue(validator.isValid(converter.getCertificate(absent), null, converter.getCertificate(root)),
                "No requested policy remains an unconstrained path-validation API call");
        var unrelatedRoot = policyCertificate(leafKey, rootName, leafKey, rootName, true, List.of(), null);
        assertTrue(unrelatedRoot.isSignatureValid(new JcaContentVerifierProviderBuilder().build(unrelatedRoot.getSubjectPublicKeyInfo())));
        assertFalse(validator.isValid(converter.getCertificate(good), issuerPolicy, converter.getCertificate(unrelatedRoot)),
                "An unrelated trusted key cannot validate the leaf signature");

        KeyPair intermediateKey = rsa(2048, RSAKeyGenParameterSpec.F4);
        assertFalse(Arrays.equals(rootKey.getPublic().getEncoded(), intermediateKey.getPublic().getEncoded()));
        X500Name intermediateName = new X500Name("CN=CCT mapping CA");
        ASN1Encodable mapping = new DERSequence(new DERSequence(new ASN1Encodable[]{
                new ASN1ObjectIdentifier(issuerPolicy), new ASN1ObjectIdentifier(subjectPolicy)}));
        var intermediate = policyCertificate(intermediateKey, intermediateName, rootKey, rootName, true, List.of(issuerPolicy), mapping);
        var mappedLeaf = policyCertificate(leafKey, leafName, intermediateKey, intermediateName, false, List.of(subjectPolicy), null);
        assertTrue(intermediate.isSignatureValid(new JcaContentVerifierProviderBuilder().build(root.getSubjectPublicKeyInfo())));
        assertTrue(mappedLeaf.isSignatureValid(new JcaContentVerifierProviderBuilder().build(intermediate.getSubjectPublicKeyInfo())));
        Path temporary = Files.createTempDirectory("cct-policy-chain-");
        try {
            var bundle = new CMSSignedDataGenerator();
            bundle.addCertificates(new org.bouncycastle.util.CollectionStore<>(List.of(intermediate)));
            Files.write(temporary.resolve("chain.p7c"), bundle.generate(new CMSProcessableByteArray(new byte[0])).getEncoded());
            validator.setCaPathString(temporary.toString()); validator.setCaFileName("chain.p7c");
            assertTrue(validator.isValid(converter.getCertificate(mappedLeaf), issuerPolicy, converter.getCertificate(root)),
                    "Initial issuer-domain policy must map to the leaf subject-domain policy");
            assertFalse(validator.isValid(converter.getCertificate(mappedLeaf), subjectPolicy, converter.getCertificate(root)),
                    "Leaf policy is not interchangeable with the initial issuer-domain policy");
            validator.setCaFileName(null);
            validator.getKeyStore().setCertificateEntry("cct-mapping-intermediate", converter.getCertificate(intermediate));
            assertTrue(validator.isValid(converter.getCertificate(mappedLeaf), issuerPolicy, converter.getCertificate(root)),
                    "A stored intermediate must remain available without a separately configured bundle");
            validator.getKeyStore().setCertificateEntry("cct-unrelated-root", converter.getCertificate(unrelatedRoot));
            var unrelatedLeaf = policyCertificate(leafKey, leafName, leafKey, rootName, false, List.of(issuerPolicy), null);
            assertFalse(validator.isValid(converter.getCertificate(unrelatedLeaf), issuerPolicy, converter.getCertificate(root)),
                    "Issuer candidates must not be promoted to trust anchors");
        } finally {
            Files.deleteIfExists(temporary.resolve("chain.p7c")); Files.delete(temporary);
        }
    }

    private static X509CertificateHolder policyCertificate(KeyPair subjectKey, X500Name subject, KeyPair issuerKey,
            X500Name issuer, boolean ca, List<String> policies, ASN1Encodable mapping) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(subject.equals(issuer) ? 1 : ca ? 2 : 3),
                new java.util.Date(1704067200000L), new java.util.Date(1893456000000L), subject, subjectKey.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        if (!policies.isEmpty()) builder.addExtension(Extension.certificatePolicies, false,
                new CertificatePolicies(policies.stream().map(p -> new PolicyInformation(new ASN1ObjectIdentifier(p))).toArray(PolicyInformation[]::new)));
        if (mapping != null) builder.addExtension(Extension.policyMappings, true, mapping);
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.getPrivate()));
    }

    private static byte[] policyObject(int row, X509CertificateHolder certificate, KeyPair key) throws Exception {
        if (row != 479) return APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{0x70}, certificate.getEncoded()), new byte[]{0x71, 1, 0, (byte) 0xfe, 0}));
        var generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build()).build(
                new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate()), certificate));
        generator.addCertificates(new org.bouncycastle.util.CollectionStore<>(List.of(certificate)));
        byte[] content = (byte[]) fixtureChuidCms(currentChuidObjects.get("plain")).getSignedContent().getContent();
        byte[] encoded = generator.generate(new CMSProcessableByteArray(new ASN1ObjectIdentifier("2.16.840.1.101.3.6.1"), content), false).getEncoded();
        byte[] raw = chuidWithCms(currentChuidObjects.get("plain"), encoded);
        var signature = fixtureChuidCms(raw).getSignerInfos().getSigners().iterator().next();
        assertTrue(signature.getSID().match(certificate));
        assertTrue(signature.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificate)));
        return raw;
    }

    private static byte[] signedCurrentChuid(CardHolderUniqueIdentifier fixture, String kind) throws Exception {
        byte[] fascn = APDUUtils.getTLV(new byte[]{0x30}, fixture.getfASCN());
        byte[] guid = APDUUtils.getTLV(new byte[]{0x34}, fixture.getgUID());
        String dateText = switch (kind) {
            case "date-month-13" -> "20321302";
            case "date-nonleap" -> "20330229";
            case "date-short" -> "2032122";
            case "date-leap" -> "20320229";
            case "date-nondigit", "date-nonascii" -> "2032120A";
            default -> kind.startsWith("date-value-") ? kind.substring("date-value-".length()) : "20321202";
        };
        byte[] dateBytes = dateText.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        if (kind.equals("date-nonascii")) dateBytes[7] = (byte) 0xb2;
        byte[] date = APDUUtils.getTLV(new byte[]{0x35}, dateBytes);
        byte[] holderValue = fixture.getCardholderUUID();
        if (holderValue != null) holderValue = holderValue.clone();
        if (kind.equals("holder-v1")) holderValue[6] = (byte) ((holderValue[6] & 0x0f) | 0x10);
        if (kind.equals("holder-v5")) holderValue[6] = (byte) ((holderValue[6] & 0x0f) | 0x50);
        if (kind.equals("holder-variant")) holderValue[8] = (byte) (holderValue[8] & 0x3f);
        if (kind.equals("holder-short")) holderValue = Arrays.copyOf(holderValue, 15);
        byte[] holder = kind.equals("holder-absent") || holderValue == null ? new byte[0]
                : APDUUtils.getTLV(new byte[]{0x36}, holderValue);
        byte[] before = kind.equals("EE") ? APDUUtils.getTLV(new byte[]{(byte) 0xee}, new byte[2]) : new byte[0];
        byte[] between = switch (kind) {
            case "32" -> APDUUtils.getTLV(new byte[]{0x32}, new byte[4]);
            case "33" -> APDUUtils.getTLV(new byte[]{0x33}, new byte[9]);
            case "unknown" -> APDUUtils.getTLV(new byte[]{0x37}, new byte[1]);
            default -> new byte[0];
        };
        byte[] fields = kind.equals("guid-first") ? concat(guid, fascn) : concat(fascn, concat(between, guid));
        byte[] datedFields = kind.equals("holder-before-date") ? concat(holder, date) : concat(date, holder);
        if (kind.equals("guid-delayed")) {
            fields = concat(fascn, concat(date, guid));
            datedFields = holder;
        }
        byte[] signedContent = concat(concat(fields, datedFields), new byte[]{(byte) 0xfe, 0});

        String ecCurve = kind.startsWith("cms-p256-") ? "secp256r1"
                : kind.startsWith("cms-p384-") ? "secp384r1"
                : kind.equals("cms-p521-sha384") ? "secp521r1"
                : kind.equals("cms-brainpool256-sha256") ? "brainpoolP256r1" : null;
        boolean brainpool = kind.equals("cms-brainpool256-sha256");
        KeyPair key = ecCurve != null ? ec(ecCurve)
                : kind.startsWith("cms-rsa4096-") ? rsa(4096, RSAKeyGenParameterSpec.F4)
                : kind.startsWith("cms-rsa3072-") ? rsa(3072, RSAKeyGenParameterSpec.F4)
                : kind.startsWith("cms-rsa1024-") ? rsa(1024, RSAKeyGenParameterSpec.F4) : sanSigningKey;
        X500Name name = new X500Name("CN=CCT CHUID regression signer");
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(100),
                new java.util.Date(1704067200000L), new java.util.Date(1893456000000L), name, key.getPublic());
        var certificateSigner = new JcaContentSignerBuilder(ecCurve == null ? "SHA256withRSA"
                : ecCurve.equals("secp256r1") || brainpool ? "SHA256withECDSA" : "SHA384withECDSA");
        var converter = new JcaX509CertificateConverter();
        if (brainpool) { certificateSigner.setProvider("BC"); converter.setProvider("BC"); }
        X509Certificate signer = converter.getCertificate(builder.build(certificateSigner.build(key.getPrivate())));
        cmsKeys.put(kind, key);
        cmsCertificates.put(kind, signer);
        CMSSignedDataGenerator generator = cmsGenerator(kind, true, false);
        byte[] cms = generator.generate(new CMSProcessableByteArray(
                new ASN1ObjectIdentifier("2.16.840.1.101.3.6.1"), signedContent), false).getEncoded();
        CMSSignedData detached = new CMSSignedData(new CMSProcessableByteArray(signedContent), cms);
        var verifier = new JcaSimpleSignerInfoVerifierBuilder();
        if (brainpool) verifier.setProvider("BC");
        assertTrue(detached.getSignerInfos().getSigners().iterator().next()
                .verify(verifier.build(signer)),
                "Synthetic CHUID CMS signature must be cryptographically valid: " + kind);
        if (kind.equals("cms-corrupt-signature")) {
            ContentInfo content = ContentInfo.getInstance(ASN1Primitive.fromByteArray(cms));
            SignedData data = SignedData.getInstance(content.getContent());
            SignerInfo original = SignerInfo.getInstance(data.getSignerInfos().getObjectAt(0));
            byte[] signature = original.getEncryptedDigest().getOctets().clone();
            signature[signature.length - 1] ^= 1;
            SignerInfo corrupted = new SignerInfo(original.getSID(), original.getDigestAlgorithm(),
                    original.getAuthenticatedAttributes(), original.getDigestEncryptionAlgorithm(),
                    new DEROctetString(signature), original.getUnauthenticatedAttributes());
            cms = new ContentInfo(content.getContentType(), new SignedData(data.getDigestAlgorithms(),
                    data.getEncapContentInfo(), data.getCertificates(), data.getCRLs(), new DERSet(corrupted)))
                    .getEncoded();
        }
        byte[] raw = APDUUtils.getTLV(APDUConstants.DATA, concat(concat(before, fields),
                concat(datedFields, concat(APDUUtils.getTLV(new byte[]{0x3e}, cms), new byte[]{(byte) 0xfe, 0}))));
        CardHolderUniqueIdentifier decoded = new CardHolderUniqueIdentifier();
        decoded.setOID(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
        decoded.setBytes(raw);
        assertTrue(decoded.decode(), "CHUID vector must decode before testing current fields: " + kind);
        if (kind.equals("cms-corrupt-signature"))
            assertFalse(decoded.verifySignature(), "Signature-only mutation must invalidate the signature");
        // The SUN verification engine does not support Brainpool. Its signature
        // was verified explicitly with BC above; decoding still must succeed.
        else if (!kind.equals("cms-sha1") && !(brainpool && !Boolean.getBoolean("cct.regressionBC")))
            assertTrue(decoded.verifySignature(), "CHUID vector must retain a valid CMS signature: " + kind);
        return raw;
    }

    private static CMSSignedDataGenerator cmsGenerator(String kind, boolean includeCertificate,
            boolean biometric) throws Exception {
        KeyPair key = cmsKeys.get(kind);
        X509Certificate signer = cmsCertificates.get(kind);
        assertNotNull(key, "The matching CHUID signer must already exist");
        assertNotNull(signer);
        boolean ecKey = key.getPublic() instanceof ECPublicKey;
        boolean brainpool = kind.equals("cms-brainpool256-sha256");
        X500Name name = X500Name.getInstance(signer.getSubjectX500Principal().getEncoded());
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ASN1ObjectIdentifier pivSignerDn = new ASN1ObjectIdentifier("2.16.840.1.101.3.6.5");
        String algorithm = ecKey ? (kind.endsWith("sha256") ? "SHA256withECDSA" : "SHA384withECDSA")
                : kind.equals("cms-sha384") || kind.equals("cms-rsa4096-sha384") ? "SHA384withRSA"
                : kind.equals("cms-sha1") ? "SHA1withRSA" : "SHA256withRSA";
        CMSSignatureEncryptionAlgorithmFinder rsaPkcs1 = signatureAlgorithm ->
                kind.equals("cms-combined-rsa-oid") ? signatureAlgorithm
                        : new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
        boolean pss = kind.startsWith("cms-pss-");
        String pssHash = kind.contains("sha256") ? "SHA-256" : "SHA-384";
        int pssSalt = kind.endsWith("zero") ? 0 : (kind.contains("sha256") ? 32 : 48)
                + (kind.endsWith("excess") ? 1 : 0);
        var cmsSigner = new JcaContentSignerBuilder(algorithm);
        if (brainpool) cmsSigner.setProvider("BC");
        var contentSigner = pss ? pssSigner(key.getPrivate(), pssHash, pssHash, pssSalt)
                : cmsSigner.build(key.getPrivate());
        SignerInfoGeneratorBuilder signerBuilder = ecKey || pss
                ? new SignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                : new SignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build(), rsaPkcs1);
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(new Attribute(pivSignerDn, new DERSet(name)));
        attributes.add(new Attribute(org.bouncycastle.asn1.cms.CMSAttributes.signingTime,
                new DERSet(new org.bouncycastle.asn1.cms.Time(new java.util.Date(1735689600000L)))));
        if (biometric) {
            attributes.add(new Attribute(new ASN1ObjectIdentifier("2.16.840.1.101.3.6.6"),
                    new DERSet(new DEROctetString(fixtureValue(chuid, 0x30)))));
            attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.1.16.4"),
                    new DERSet(new DEROctetString(fixtureValue(chuid, 0x34)))));
        }
        generator.addSignerInfoGenerator(signerBuilder
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)))
                .build(contentSigner,
                        new X509CertificateHolder(signer.getEncoded())));
        if (includeCertificate) generator.addCertificates(new JcaCertStore(List.of(signer)));
        return generator;
    }

    private static byte[] cccWithOptional(String kind) {
        byte[] body = Arrays.copyOf(ccc, ccc.length - 2); // Replace final FE 00 after optional fields.
        if (kind.equals("E3") || kind.equals("both"))
            body = concat(body, APDUUtils.getTLV(new byte[]{(byte) 0xe3}, new byte[48]));
        if (kind.equals("B4") || kind.equals("both"))
            body = concat(body, APDUUtils.getTLV(new byte[]{(byte) 0xb4}, new byte[48]));
        if (kind.equals("F8-first"))
            body = concat(APDUUtils.getTLV(new byte[]{(byte) 0xf8}, new byte[]{1}), body);
        return APDUUtils.getTLV(APDUConstants.DATA, concat(body, new byte[]{(byte) 0xfe, 0}));
    }

    private static KeyPair rsa(int bits, BigInteger exponent) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(new RSAKeyGenParameterSpec(bits, exponent));
        return generator.generateKeyPair();
    }

    private static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator generator = curve.startsWith("brainpool") ? KeyPairGenerator.getInstance("EC", "BC")
                : KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static byte[] currentCertificate(KeyPair keyPair) throws Exception {
        String signature = keyPair.getPrivate().getAlgorithm().equals("RSA")
                ? "SHA256withRSA"
                : ((ECPublicKey) keyPair.getPublic()).getParams().getCurve().getField().getFieldSize() == 256
                    ? "SHA256withECDSA" : "SHA384withECDSA";
        return currentCertificate(keyPair, signature);
    }

    private static byte[] currentCertificate(KeyPair keyPair, String signature) throws Exception {
        return currentCertificate(keyPair, signature, false);
    }

    private static byte[] subjectKeyCertificate(KeyPair subject, AlgorithmIdentifier algorithm) throws Exception {
        var original = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(subject.getPublic().getEncoded());
        var restricted = new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                algorithm, original.getPublicKeyData().getBytes());
        var builder = new org.bouncycastle.cert.X509v3CertificateBuilder(
                new X500Name("CN=CCT SPKI regression issuer"), BigInteger.valueOf(77),
                new java.util.Date(1704067200000L), new java.util.Date(1893456000000L),
                new X500Name("CN=CCT RSA subject"), restricted);
        X509CertificateHolder signed = builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(sanSigningKey.getPrivate()));
        assertTrue(signed.isSignatureValid(new JcaContentVerifierProviderBuilder()
                .setProvider(new BouncyCastleProvider()).build(sanSigningKey.getPublic())));
        return APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{0x70}, signed.getEncoded()), new byte[]{0x71, 1, 0, (byte) 0xfe, 0}));
    }

    private static byte[] currentCertificate(KeyPair keyPair, String signature, boolean explicitNullParameters) throws Exception {
        return currentCertificate(keyPair, signature, explicitNullParameters, null);
    }

    private static byte[] currentCertificate(KeyPair keyPair, String signature, boolean explicitNullParameters,
                                             AuthorityInformationAccess aia) throws Exception {
        X500Name name = new X500Name("CN=CCT SP800-78-5 regression");
        java.util.Date notBefore = new java.util.Date(1704067200000L);
        java.util.Date notAfter = new java.util.Date(1893456000000L);
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(
                keyProfileCertificates.size() + 1L), notBefore, notAfter, name, keyPair.getPublic());
        if (aia != null) builder.addExtension(Extension.authorityInfoAccess, false, aia);
        var delegate = new JcaContentSignerBuilder(signature).build(keyPair.getPrivate());
        org.bouncycastle.operator.ContentSigner signer = explicitNullParameters
                ? new org.bouncycastle.operator.ContentSigner() {
                    public AlgorithmIdentifier getAlgorithmIdentifier() {
                        return new AlgorithmIdentifier(delegate.getAlgorithmIdentifier().getAlgorithm(), DERNull.INSTANCE);
                    }
                    public java.io.OutputStream getOutputStream() { return delegate.getOutputStream(); }
                    public byte[] getSignature() { return delegate.getSignature(); }
                } : delegate;
        X509Certificate generated = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        generated.verify(keyPair.getPublic());
        return APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{0x70}, generated.getEncoded()),
                new byte[]{0x71, 1, 0, (byte) 0xfe, 0}));
    }

    private static byte[] pssCertificate(String hash, String mgfHash, int saltLength) throws Exception {
        X500Name name = new X500Name("CN=CCT PSS parameter regression");
        if (mgfHash.equals("MD5")) {
            // Intentionally disallowed RFC4055 MGF hash, with an otherwise
            // mathematical PSS signature. Keys remain ephemeral test data.
            var algorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS,
                    new org.bouncycastle.asn1.pkcs.RSASSAPSSparams(
                            new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1")),
                            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1,
                                    new AlgorithmIdentifier(PKCSObjectIdentifiers.md5, DERNull.INSTANCE)),
                            new ASN1Integer(saltLength), new ASN1Integer(1)));
            var bytes = new java.io.ByteArrayOutputStream();
            var signer = new org.bouncycastle.crypto.signers.PSSSigner(
                    new org.bouncycastle.crypto.engines.RSABlindedEngine(),
                    new org.bouncycastle.crypto.digests.SHA256Digest(),
                    new org.bouncycastle.crypto.digests.MD5Digest(), saltLength);
            signer.init(true, org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(sanSigningKey.getPrivate().getEncoded()));
            var signed = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                    new java.util.Date(1704067200000L), new java.util.Date(1893456000000L),
                    name, sanSigningKey.getPublic()).build(new org.bouncycastle.operator.ContentSigner() {
                public AlgorithmIdentifier getAlgorithmIdentifier() { return algorithm; }
                public java.io.OutputStream getOutputStream() { return bytes; }
                public byte[] getSignature() {
                    byte[] message = bytes.toByteArray();
                    signer.update(message, 0, message.length);
                    try { return signer.generateSignature(); }
                    catch (org.bouncycastle.crypto.CryptoException e) { throw new IllegalStateException(e); }
                }
            });
            signer.init(false, org.bouncycastle.crypto.util.PublicKeyFactory.createKey(sanSigningKey.getPublic().getEncoded()));
            byte[] tbs = signed.toASN1Structure().getTBSCertificate().getEncoded();
            signer.update(tbs, 0, tbs.length);
            assertTrue(signer.verifySignature(signed.getSignature()));
            if (!Boolean.getBoolean("cct.regressionBC")) {
                var rejection = assertThrows(java.security.cert.CertificateException.class,
                        () -> CertificateFactory.getInstance("X.509", "SUN").generateCertificate(
                                new java.io.ByteArrayInputStream(signed.getEncoded())));
                assertTrue(rejection.getMessage().contains("Unrecognized message digest algorithm MD5"));
            }
            return APDUUtils.getTLV(APDUConstants.DATA, concat(
                    APDUUtils.getTLV(new byte[]{0x70}, signed.getEncoded()), new byte[]{0x71, 1, 0, (byte) 0xfe, 0}));
        }
        X509Certificate generated = new JcaX509CertificateConverter().setProvider("SUN").getCertificate(
                new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                        new java.util.Date(1704067200000L), new java.util.Date(1893456000000L),
                        name, sanSigningKey.getPublic()).build(
                                pssSigner(sanSigningKey.getPrivate(), hash, mgfHash, saltLength)));
        generated.verify(sanSigningKey.getPublic(), "SunRsaSign");
        return APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{0x70}, generated.getEncoded()),
                new byte[]{0x71, 1, 0, (byte) 0xfe, 0}));
    }

    private static org.bouncycastle.operator.ContentSigner pssSigner(java.security.PrivateKey key,
            String hash, String mgfHash, int saltLength) throws Exception {
        PSSParameterSpec spec = new PSSParameterSpec(hash, "MGF1",
                new MGF1ParameterSpec(mgfHash), saltLength, 1);
        var parameters = java.security.AlgorithmParameters.getInstance("RSASSA-PSS", "SunRsaSign");
        parameters.init(spec);
        AlgorithmIdentifier algorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS,
                ASN1Primitive.fromByteArray(parameters.getEncoded()));
        var bytes = new java.io.ByteArrayOutputStream();
        var signature = java.security.Signature.getInstance("RSASSA-PSS", "SunRsaSign");
        signature.setParameter(spec);
        signature.initSign(key);
        return new org.bouncycastle.operator.ContentSigner() {
            public AlgorithmIdentifier getAlgorithmIdentifier() { return algorithm; }
            public java.io.OutputStream getOutputStream() { return bytes; }
            public byte[] getSignature() {
                try {
                    signature.update(bytes.toByteArray());
                    return signature.sign();
                } catch (java.security.GeneralSecurityException e) { throw new IllegalStateException(e); }
            }
        };
    }

    private static byte[] encodedCertificate(GeneralName[] names, AlgorithmIdentifier algorithm) throws Exception {
        // Invalid identifiers are encoding-only negatives. Valid SHA-256
        // identifiers retain a verifiable certificate signature.
        X500Name name = new X500Name("CN=CCT signature identifier regression");
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(4243),
                new java.util.Date(1704067200000L), new java.util.Date(1893456000000L),
                name, sanSigningKey.getPublic());
        if (names != null) builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
        var delegate = new JcaContentSignerBuilder("SHA256withRSA").build(sanSigningKey.getPrivate());
        var signed = builder.build(new org.bouncycastle.operator.ContentSigner() {
            public AlgorithmIdentifier getAlgorithmIdentifier() { return algorithm; }
            public java.io.OutputStream getOutputStream() { return delegate.getOutputStream(); }
            public byte[] getSignature() { return delegate.getSignature(); }
        });
        assertEquals(algorithm, signed.getSignatureAlgorithm());
        var verifier = java.security.Signature.getInstance("SHA256withRSA");
        verifier.initVerify(sanSigningKey.getPublic());
        verifier.update(signed.toASN1Structure().getTBSCertificate().getEncoded());
        assertTrue(verifier.verify(signed.getSignature()), "Fixture TBS must retain its actual RSA signature");
        return APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{0x70}, signed.getEncoded()), new byte[]{0x71, 1, 0, (byte) 0xfe, 0}));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static void run(int id, String expectedMethod, byte[] raw, boolean pass, String failurePrefix) throws Exception {
        run("PIV_Production_Cards.db", id, expectedMethod, raw, pass, failurePrefix);
    }

    private static byte[] facialRecordObject(int features, int images, int field, int value) throws Exception {
        byte[] biometric = fixtureValue(cmsConsumerObject(306, "plain"), 0xbc);
        byte[] original = Arrays.copyOfRange(biometric, 88, 88 + ByteBuffer.wrap(biometric).getInt(2));
        int blocks = Math.max(1, images);
        byte[] record = new byte[14 + blocks * (32 + 8 * features)];
        System.arraycopy(original, 0, record, 0, 14);
        ByteBuffer.wrap(record).putInt(8, record.length).putShort(12, (short) images);
        for (int image = 0; image < blocks; image++) {
            int start = 14 + image * (32 + 8 * features);
            System.arraycopy(original, 14, record, start, 20);
            System.arraycopy(original, 34, record, start + 20 + 8 * features, 12);
            ByteBuffer.wrap(record).putInt(start, 32 + 8 * features).putShort(start + 4, (short) features);
            if (image == images - 1 && field >= 0) record[start + 20 + 8 * features + field] = (byte) value;
        }
        // Synthetic feature slots and absent pixels are header/offset evidence,
        // not a full INCITS image. The complete encoded envelope is signed.
        assertEquals(record.length, ByteBuffer.wrap(record).getInt(8));
        assertEquals(images, Short.toUnsignedInt(ByteBuffer.wrap(record).getShort(12)));
        byte[] header = Arrays.copyOf(biometric, 88);
        ByteBuffer.wrap(header).putInt(2, record.length);
        var generator = cmsGenerator("plain", true, true);
        byte[] cms = null;
        for (int attempt = 0; attempt < 3; attempt++) {
            cms = generator.generate(new CMSProcessableByteArray(
                    new ASN1ObjectIdentifier("2.16.840.1.101.3.6.2"), concat(header, record)), false).getEncoded();
            if (Short.toUnsignedInt(ByteBuffer.wrap(header).getShort(6)) == cms.length) break;
            ByteBuffer.wrap(header).putShort(6, (short) cms.length);
        }
        assertEquals(cms.length, Short.toUnsignedInt(ByteBuffer.wrap(header).getShort(6)));
        byte[] raw = APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{(byte) 0xbc}, concat(concat(header, record), cms)), new byte[]{(byte) 0xfe, 0}));
        assertFixtureCmsValid(fixtureCms(306, raw));
        return raw;
    }

    @ParameterizedTest
    @ValueSource(strings = {"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db"})
    void facialImageFieldsUseExistingAtoms(String database) throws Exception {
        byte[] header = new byte[]{0x46, 0x41, 0x43, 0x00, 0x30, 0x31, 0x30, 0x00};
        int record = -1;
        for (int i = 0; i <= facialImage.length - header.length; i++) {
            if (Arrays.equals(Arrays.copyOfRange(facialImage, i, i + header.length), header)) {
                assertEquals(-1, record, "Expected one FAC record");
                record = i;
            }
        }
        assertTrue(record >= 0, "Synthetic face header must contain a FAC record");
        int[] ids = {251, 252, 253, 254};
        int[] offsets = {34, 35, 40, 41};
        int[] invalid = {0, 2, 0, 3};
        String[] messages = {"Facial image type is not 1", "Facial image data type is not 1 or 0",
                "Image color space is not 1", "Facial image source type is not 2 or 6"};
        for (int i = 0; i < ids.length; i++) {
            String method = "sp800_76Test_" + (34 + i);
            run(database, ids[i], method, facialImage, true, "");
            byte[] changed = facialImage.clone();
            changed[record + offsets[i]] = (byte) invalid[i];
            run(database, ids[i], method, changed, false, messages[i]);
            if (ids[i] == 252 || ids[i] == 254) {
                byte[] alternative = facialImage.clone();
                alternative[record + offsets[i]] = (byte) (ids[i] == 252 ? 0 : 6);
                run(database, ids[i], method, alternative, true, "");
            }
            int relative = offsets[i] - 34;
            for (int features : new int[]{1, 256, 257}) {
                run(database, ids[i], method, facialRecordObject(features, 1, -1, 0), true, "");
                run(database, ids[i], method, facialRecordObject(features, 1, relative, invalid[i]), false, messages[i]);
            }
            run(database, ids[i], method, facialRecordObject(0, 2, relative, invalid[i]),
                    TestExecutionResult.Status.ABORTED, "facial records containing multiple images", null);
            run(database, ids[i], method, facialRecordObject(0, 0, -1, 0), false,
                    "Facial record must contain at least one image");
            // Table 12 uses unsigned big-endian numbers. Declaring 256 feature
            // points cannot leave the image-info fields at the zero-point offset.
            // This deliberately inconsistent header must fail the bounds check.
            byte[] truncatedFeatures = facialImage.clone();
            truncatedFeatures[record + 18] = 1;
            truncatedFeatures[record + 19] = 0;
            run(database, ids[i], method, truncatedFeatures, false,
                    "Facial image record is too short for the declared feature-point count");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"PIV_Production_Cards.db", "PIV_ICAM_Test_Cards.db",
            "PIV-I_Production_Cards.db", "PIV-I_ICAM_Test_Cards.db"})
    void enabledPlaceholdersCannotPass(String database) throws Exception {
        Path path = Path.of(System.getProperty("cct.repository"), "conformancelib/testdata", database);
        int checked = 0;
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:file:" + path + "?mode=ro");
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("SELECT tc.Id FROM TestCases tc "
                     + "JOIN TestsToSteps ts ON ts.TestId = tc.Id "
                     + "JOIN TestSteps step ON step.Id = ts.TestStepId "
                     + "WHERE tc.Enabled = 1 AND step.Method = 'PlaceholderTest_1' ORDER BY tc.Id")) {
            while (rows.next()) {
                run(database, rows.getInt(1), "PlaceholderTest_1", chuid,
                        TestExecutionResult.Status.ABORTED, PlaceholderTests.UNSUPPORTED_MESSAGE);
                checked++;
            }
        }
        assertTrue(checked > 0, "The profile must exercise at least one unresolved placeholder");
    }

    private static void run(String database, int id, String expectedMethod, byte[] raw,
                            boolean pass, String failurePrefix) throws Exception {
        run(database, id, expectedMethod, raw,
                pass ? TestExecutionResult.Status.SUCCESSFUL : TestExecutionResult.Status.FAILED, failurePrefix);
    }

    private static void run(String database, int id, String expectedMethod, byte[] raw,
                            TestExecutionResult.Status expectedStatus, String failurePrefix) throws Exception {
        run(database, id, expectedMethod, raw, expectedStatus, failurePrefix, null);
    }

    private static void run(String database, int id, String expectedMethod, byte[] raw,
                            TestExecutionResult.Status expectedStatus, String failurePrefix,
                            MiddlewareStatus retrievalFailure) throws Exception {
        run(database, id, expectedMethod, raw, expectedStatus, failurePrefix, retrievalFailure, null);
    }

    private static TestExecutionResult run(String database, int id, String expectedMethod, byte[] raw,
                            TestExecutionResult.Status expectedStatus, String failurePrefix,
                            MiddlewareStatus retrievalFailure, byte[] relatedChuid) throws Exception {
        return run(database, id, expectedMethod, raw, expectedStatus, failurePrefix,
                retrievalFailure, relatedChuid, Map.of());
    }

    private static TestExecutionResult run(String database, int id, String expectedMethod, byte[] raw,
                            TestExecutionResult.Status expectedStatus, String failurePrefix,
                            MiddlewareStatus retrievalFailure, byte[] relatedChuid,
                            Map<String, byte[]> additionalObjects) throws Exception {
        Path path = Path.of(System.getProperty("cct.repository"), "conformancelib/testdata", database);
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:file:" + path + "?mode=ro")) {
            TestCaseModel row = new TestCaseModel(new ConformanceTestDatabase(connection));
            row.retrieveForId(id);
            TestStepModel step = row.getSteps().stream().filter(s -> expectedMethod.equals(s.getTestMethodName()))
                    .reduce((a,b) -> { throw new AssertionError("Duplicate database step"); }).orElseThrow();
            var method = Arrays.stream(Class.forName(step.getTestClassName()).getDeclaredMethods())
                    .filter(m -> m.getName().equals(step.getTestMethodName())).findFirst().orElseThrow();
            String selector = step.getTestClassName() + "#" + method.getName() + "("
                    + Arrays.stream(method.getParameterTypes()).map(Class::getName).collect(Collectors.joining(", ")) + ")";
            Map<String,byte[]> objects = new HashMap<>(additionalObjects);
            objects.put(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, relatedChuid == null ? chuid : relatedChuid);
            objects.put(APDUConstants.getStringForFieldNamed(row.getContainer()), raw);
            var result = execute(selector, row.getContainer(), step.getParameters(), objects, retrievalFailure);
            assertEquals(expectedStatus, result.getStatus(), row.getIdentifier() + ": " + result);
            if (expectedStatus != TestExecutionResult.Status.SUCCESSFUL) {
                Throwable failure = result.getThrowable().orElseThrow();
                if (expectedStatus == TestExecutionResult.Status.FAILED)
                    assertTrue(failure instanceof AssertionError,
                            "Setup/decode errors do not prove the intended failure: " + failure);
                if (expectedStatus == TestExecutionResult.Status.ABORTED)
                    assertTrue(failure instanceof PlaceholderTests.UnsupportedConformanceException,
                            "Unsupported cases must use the typed result: " + failure);
                assertTrue(expectedStatus == TestExecutionResult.Status.ABORTED
                                ? failure.getMessage().contains(failurePrefix)
                                : failure.getMessage().startsWith(failurePrefix),
                        "Wrong assertion: " + failure);
            }
            return result;
        }
    }

    private static TestExecutionResult execute(String method, String container, List<String> arguments,
                                       Map<String,byte[]> objects, MiddlewareStatus retrievalFailure) {
        CardSettingsSingleton card = CardSettingsSingleton.getInstance();
        ParameterProviderSingleton parameters = ParameterProviderSingleton.getInstance();
        card.reset(); parameters.reset();
        DataModelSingleton.getInstance().reset();
        card.setTerminal(new CardTerminal() {
            public String getName() { return "Synthetic evidence only"; }
            public Card connect(String protocol) { throw new AssertionError("Physical connection forbidden"); }
            public boolean isCardPresent() { return true; }
            public boolean waitForCardPresent(long timeout) { throw new AssertionError("Physical wait forbidden"); }
            public boolean waitForCardAbsent(long timeout) { throw new AssertionError("Physical wait forbidden"); }
        });
        card.setCardHandle(new CardHandle());
        card.setLastLoginStatus(CardSettingsSingleton.LOGIN_STATUS.LOGIN_SUCCESS);
        card.setPivHandle(new DefaultPIVApplication() {
            @Override public MiddlewareStatus pivGetData(CardHandle handle, String oid, PIVDataObject object) {
                if (retrievalFailure != null && oid.equals(APDUConstants.getStringForFieldNamed(container)))
                    return retrievalFailure;
                byte[] raw = objects.get(oid);
                if (raw == null) return MiddlewareStatus.PIV_DATA_OBJECT_NOT_FOUND;
                object.setOID(oid);
                object.setContainerName(APDUConstants.getFileNameForOid(oid));
                object.setBytes(raw.clone());
                return MiddlewareStatus.PIV_OK;
            }
        });
        parameters.addContainer(method, container);
        parameters.addNamedParameter(method, arguments);
        List<TestExecutionResult> results = new ArrayList<>();
        try {
            // Normal runs acquire CHUID before Security Object checks. Preserve that
            // real decoder/cache relationship for this otherwise isolated atom.
            if (container.equals("SECURITY_OBJECT_OID") || (method.contains("#CMS_Test_14(")
                    && !container.equals("CARD_HOLDER_UNIQUE_IDENTIFIER_OID")))
                assertNotNull(AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID));
            LauncherFactory.create().execute(LauncherDiscoveryRequestBuilder.request()
                    .selectors(DiscoverySelectors.selectMethod(method)).build(), new TestExecutionListener() {
                @Override public void executionFinished(TestIdentifier id, TestExecutionResult result) {
                    if (id.isTest()) results.add(result);
                    else assertNotEquals(TestExecutionResult.Status.FAILED, result.getStatus(),
                            "JUnit container/setup failure: " + result.getThrowable());
                }
            });
            assertEquals(1, results.size(), "Exactly one database atom must execute");
            return results.get(0);
        } finally {
            card.reset(); parameters.reset();
            DataModelSingleton.getInstance().reset();
        }
    }

}
