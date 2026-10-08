package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.cardlib.card.client.*;
import gov.gsa.pivconformance.conformancelib.configuration.*;
import gov.gsa.pivconformance.cardlib.tlv.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
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
    private static String cardUrn;
    private static String holderUrn;
    private static KeyPair sanSigningKey;
    private static X509CertificateHolder certificate;
    private static final Map<String, byte[]> keyProfileCertificates = new HashMap<>();
    private static final Map<String, byte[]> currentChuidObjects = new HashMap<>();
    private static boolean addedProvider;

    @BeforeAll static void fixtures() throws Exception {
        // BC exposes encoded NULL parameters; SUN normalizes them to null.
        if (Boolean.getBoolean("cct.regressionBC")) {
            assertNull(Security.getProvider("BC"), "Run in an isolated test worker");
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
            addedProvider = true;
        }
        Path root = Path.of(System.getProperty("cct.repository"));
        Path golden = root.resolve("cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/"
                + "gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/8 - CHUID Object");
        chuid = APDUUtils.getTLV(APDUConstants.DATA, Files.readAllBytes(golden));
        ccc = Files.readAllBytes(golden.resolveSibling("7 - CCC"));
        CardCapabilityContainer decodedCcc = new CardCapabilityContainer();
        decodedCcc.setOID(APDUConstants.CARD_CAPABILITY_CONTAINER_OID);
        decodedCcc.setContainerName(APDUConstants.getFileNameForOid(APDUConstants.CARD_CAPABILITY_CONTAINER_OID));
        decodedCcc.setBytes(APDUUtils.getTLV(APDUConstants.DATA, ccc));
        assertTrue(decodedCcc.decode(), "Existing golden CCC must decode before testing current fields");
        CardHolderUniqueIdentifier decoded = new CardHolderUniqueIdentifier();
        decoded.setOID(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
        decoded.setBytes(chuid);
        assertTrue(decoded.decode(), "Existing golden CHUID must decode before testing UUID equality");
        ByteBuffer guid = ByteBuffer.wrap(decoded.getgUID());
        cardUrn = "urn:uuid:" + new UUID(guid.getLong(), guid.getLong());
        ByteBuffer holderBytes = ByteBuffer.wrap(decoded.getCardholderUUID());
        holderUrn = "urn:uuid:" + new UUID(holderBytes.getLong(), holderBytes.getLong());
        sanSigningKey = rsa(2048, RSAKeyGenParameterSpec.F4);
        for (String kind : List.of("plain", "EE", "32", "33", "unknown", "guid-first",
                "holder-absent", "holder-v1", "holder-v5", "holder-variant", "holder-short", "holder-before-date"))
            currentChuidObjects.put(kind, signedCurrentChuid(decoded, kind));
        try (var in = Files.newInputStream(golden.resolveSibling("3 - ICAM_PIV_Auth_SP_800-73-4.crt"))) {
            certificate = new X509CertificateHolder(CertificateFactory.getInstance("X.509")
                    .generateCertificate(in).getEncoded());
        }
        keyProfileCertificates.put("rsa2048", currentCertificate(rsa(2048, RSAKeyGenParameterSpec.F4)));
        keyProfileCertificates.put("rsa3072", currentCertificate(rsa(3072, RSAKeyGenParameterSpec.F4)));
        // A fixed, self-signed weak-key certificate is the intentional negative
        // input; the regression suite never generates or uses a weak private key.
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
    }

    @AfterAll static void restoreProvider() { if (addedProvider) Security.removeProvider("BC"); }

    static Stream<Arguments> uuidCases() {
        return IntStream.of(369, 451).boxed().flatMap(row -> Stream.of(
                "match", "uppercase", "mismatch", "missing", "bare", "short", "wrong-name-type",
                "holder-before-card", "holder-after-card", "unrelated-uri-before-card")
                .map(kind -> Arguments.of(row, kind)));
    }

    @ParameterizedTest(name="production row {0}: UUID {1}") @MethodSource("uuidCases")
    void uuidThroughExistingAtom(int row, String kind) throws Exception {
        GeneralName match = new GeneralName(GeneralName.uniformResourceIdentifier, cardUrn);
        GeneralName holder = new GeneralName(GeneralName.uniformResourceIdentifier,
                "urn:uuid:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        GeneralName[] names = switch (kind) {
            case "match" -> new GeneralName[]{match};
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
        boolean pass = Set.of("match", "uppercase", "unrelated-uri-before-card").contains(kind)
                || (row == 451 && Set.of("holder-before-card", "holder-after-card").contains(kind));
        String failure = row == 369 && Set.of("holder-before-card", "holder-after-card").contains(kind)
                ? "PKIX.27 current:" : "PKIX.27:";
        run(row, "PKIX_Test_27_current", encodedCertificate(names, certificate.getSignatureAlgorithm()),
                pass, failure);
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
        run(369, "PKIX_Test_27_current", signed, pass, "PKIX.27 current:");
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

    private static byte[] signedCertificateWithSan(GeneralName[] names) throws Exception {
        X500Name name = new X500Name("CN=CCT PIV Authentication SAN regression");
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(4242),
                new java.util.Date(1704067200000L), new java.util.Date(1893456000000L),
                name, sanSigningKey.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
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
        run(row, "sp800_78_Test_3", encodedCertificate(null, algorithm),
                kind.equals("null") || kind.equals("absent"), "SP800-78.3:");
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
        run(row, "sp800_78_Test_1_current", keyProfileCertificates.get(kind),
                pass, "SP800-78.1:");
    }

    @ParameterizedTest(name="current CCC: {0}")
    @ValueSource(strings={"plain", "E3", "B4"})
    void currentCccThroughExistingAtom(String kind) throws Exception {
        run(11, "sp800_73_5_Test_4", cccWithOptional(kind), kind.equals("plain"),
                "SP800-73-5 CCC:");
    }

    @Test void historicalCccStillPermitsDeprecatedOptionalFields() throws Exception {
        run("PIV-I_Production_Cards.db", 11, "sp800_73_4_Test_4",
                cccWithOptional("both"), true, "");
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
                Arguments.of(35, "sp800_73_5_Test_9", "plain", true, ""),
                Arguments.of(35, "sp800_73_5_Test_9", "EE", false, "SP800-73-5 CHUID:"),
                Arguments.of(36, "sp800_73_5_Test_17", "plain", true, ""),
                Arguments.of(36, "sp800_73_5_Test_17", "EE", false, "SP800-73-5 CHUID:"),
                Arguments.of(36, "sp800_73_5_Test_17", "32", false, "SP800-73-5 CHUID:"),
                Arguments.of(36, "sp800_73_5_Test_17", "33", false, "SP800-73-5 CHUID:"),
                Arguments.of(36, "sp800_73_5_Test_17", "unknown", false, "SP800-73-5 CHUID:"));
    }

    @ParameterizedTest(name="production CHUID row {0}: {2}") @MethodSource("currentChuidCases")
    void currentChuidThroughExistingAtom(int row, String method, String kind, boolean pass,
                                         String failurePrefix) throws Exception {
        run(row, method, currentChuidObjects.get(kind), pass, failurePrefix);
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
        run(row, "sp800_73_5_Test_13", currentChuidObjects.get(kind), pass, "SP800-73-5 CHUID:");
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

    private static byte[] signedCurrentChuid(CardHolderUniqueIdentifier golden, String kind) throws Exception {
        byte[] fascn = APDUUtils.getTLV(new byte[]{0x30}, golden.getfASCN());
        byte[] guid = APDUUtils.getTLV(new byte[]{0x34}, golden.getgUID());
        byte[] date = APDUUtils.getTLV(new byte[]{0x35}, "20321202".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[] holderValue = golden.getCardholderUUID();
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
        byte[] signedContent = concat(concat(fields, datedFields), new byte[]{(byte) 0xfe, 0});

        KeyPair key = rsa(2048, RSAKeyGenParameterSpec.F4);
        X500Name name = new X500Name("CN=CCT CHUID regression signer");
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(100),
                new java.util.Date(1704067200000L), new java.util.Date(1893456000000L), name, key.getPublic());
        X509Certificate signer = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())));
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
                .build("SHA256withRSA", key.getPrivate(), signer));
        generator.addCertificates(new JcaCertStore(List.of(signer)));
        byte[] cms = generator.generate(new CMSProcessableByteArray(signedContent), false).getEncoded();
        byte[] raw = APDUUtils.getTLV(APDUConstants.DATA, concat(concat(before, fields),
                concat(datedFields, concat(APDUUtils.getTLV(new byte[]{0x3e}, cms), new byte[]{(byte) 0xfe, 0}))));
        CardHolderUniqueIdentifier decoded = new CardHolderUniqueIdentifier();
        decoded.setOID(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
        decoded.setBytes(raw);
        assertTrue(decoded.decode(), "CHUID vector must decode before testing current fields: " + kind);
        assertTrue(decoded.verifySignature(), "CHUID vector must retain a valid CMS signature: " + kind);
        return raw;
    }

    private static byte[] cccWithOptional(String kind) {
        byte[] body = Arrays.copyOf(ccc, ccc.length - 2); // Replace final FE 00 after optional fields.
        if (kind.equals("E3") || kind.equals("both"))
            body = concat(body, APDUUtils.getTLV(new byte[]{(byte) 0xe3}, new byte[48]));
        if (kind.equals("B4") || kind.equals("both"))
            body = concat(body, APDUUtils.getTLV(new byte[]{(byte) 0xb4}, new byte[48]));
        return APDUUtils.getTLV(APDUConstants.DATA, concat(body, new byte[]{(byte) 0xfe, 0}));
    }

    private static KeyPair rsa(int bits, BigInteger exponent) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(new RSAKeyGenParameterSpec(bits, exponent));
        return generator.generateKeyPair();
    }

    private static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static byte[] currentCertificate(KeyPair keyPair) throws Exception {
        X500Name name = new X500Name("CN=CCT SP800-78-5 regression");
        java.util.Date notBefore = new java.util.Date(1704067200000L);
        java.util.Date notAfter = new java.util.Date(1893456000000L);
        String signature = keyPair.getPrivate().getAlgorithm().equals("RSA")
                ? "SHA256withRSA" : "SHA384withECDSA";
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(
                keyProfileCertificates.size() + 1L), notBefore, notAfter, name, keyPair.getPublic());
        X509Certificate generated = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder(signature).build(keyPair.getPrivate())));
        generated.verify(keyPair.getPublic());
        return APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{0x70}, generated.getEncoded()),
                new byte[]{0x71, 1, 0, (byte) 0xfe, 0}));
    }

    private static byte[] encodedCertificate(GeneralName[] names, AlgorithmIdentifier algorithm) throws Exception {
        var original = certificate.toASN1Structure();
        ASN1Sequence tbs = ASN1Sequence.getInstance(original.getTBSCertificate().toASN1Primitive());
        ASN1EncodableVector fields = new ASN1EncodableVector();
        for (int i = 0; i < tbs.size(); i++) {
            ASN1Encodable field = tbs.getObjectAt(i);
            if (i == 2) field = algorithm; // v3 TBSCertificate.signature
            if (field instanceof ASN1TaggedObject && ((ASN1TaggedObject) field).getTagNo() == 3) {
                ExtensionsGenerator extensions = new ExtensionsGenerator();
                for (ASN1ObjectIdentifier oid : certificate.getExtensions().getExtensionOIDs())
                    if (!oid.equals(Extension.subjectAlternativeName)) extensions.addExtension(certificate.getExtension(oid));
                if (names != null) extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
                field = new DERTaggedObject(true, 3, extensions.generate());
            }
            fields.add(field);
        }
        byte[] der = new DERSequence(new ASN1Encodable[]{new DERSequence(fields), algorithm,
                original.getSignature()}).getEncoded();
        return APDUUtils.getTLV(APDUConstants.DATA, concat(
                APDUUtils.getTLV(new byte[]{0x70}, der), new byte[]{0x71, 1, 0, (byte) 0xfe, 0}));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static void run(int id, String expectedMethod, byte[] raw, boolean pass, String failurePrefix) throws Exception {
        run("PIV_Production_Cards.db", id, expectedMethod, raw, pass, failurePrefix);
    }

    private static void run(String database, int id, String expectedMethod, byte[] raw,
                            boolean pass, String failurePrefix) throws Exception {
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
            Map<String,byte[]> objects = new HashMap<>();
            objects.put(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, chuid);
            objects.put(APDUConstants.getStringForFieldNamed(row.getContainer()), raw);
            var result = execute(selector, row.getContainer(), step.getParameters(), objects);
            assertEquals(pass ? TestExecutionResult.Status.SUCCESSFUL : TestExecutionResult.Status.FAILED,
                    result.getStatus(), row.getIdentifier() + ": " + result);
            if (!pass) {
                Throwable failure = result.getThrowable().orElseThrow();
                assertTrue(failure instanceof AssertionError, "Setup/decode errors do not prove the intended failure: " + failure);
                assertTrue(failure.getMessage().startsWith(failurePrefix), "Wrong assertion: " + failure);
            }
        }
    }

    private static TestExecutionResult execute(String method, String container, List<String> arguments,
                                       Map<String,byte[]> objects) {
        CardSettingsSingleton card = CardSettingsSingleton.getInstance();
        ParameterProviderSingleton parameters = ParameterProviderSingleton.getInstance();
        card.reset(); parameters.reset();
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
        } finally { card.reset(); parameters.reset(); }
    }

}
