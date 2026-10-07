package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.cardlib.card.client.*;
import gov.gsa.pivconformance.conformancelib.configuration.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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
    private static X509CertificateHolder certificate;
    private static final Map<String, byte[]> keyProfileCertificates = new HashMap<>();
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
        try (var in = Files.newInputStream(golden.resolveSibling("3 - ICAM_PIV_Auth_SP_800-73-4.crt"))) {
            certificate = new X509CertificateHolder(CertificateFactory.getInstance("X.509")
                    .generateCertificate(in).getEncoded());
        }
        keyProfileCertificates.put("rsa2048", currentCertificate(rsa(2048, RSAKeyGenParameterSpec.F4)));
        keyProfileCertificates.put("rsa3072", currentCertificate(rsa(3072, RSAKeyGenParameterSpec.F4)));
        keyProfileCertificates.put("rsa1024", currentCertificate(rsa(1024, RSAKeyGenParameterSpec.F4)));
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
        boolean pass = Set.of("match", "uppercase", "holder-before-card", "holder-after-card",
                "unrelated-uri-before-card").contains(kind);
        run(row, "PKIX_Test_27", encodedCertificate(names, certificate.getSignatureAlgorithm()),
                pass, "PKIX.27:");
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
            Map<String,byte[]> objects = Map.of(APDUConstants.getStringForFieldNamed(row.getContainer()), raw,
                    APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, chuid);
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
