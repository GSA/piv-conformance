package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.conformancelib.utilities.CandidatePathValidation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

@Tag("SyntheticCertificateEvidence")
public class SyntheticCertificateEvidenceTest {
    static { Security.addProvider(new BouncyCastleProvider()); }
    static final Instant TIME=Instant.parse("2026-09-30T12:00:00Z");
    static final String BASE="standards/synthetic-certificates/";
    static final String[] POLICIES={"2.16.840.1.101.3.2.1.3.18","2.16.840.1.101.3.2.1.3.7","2.16.840.1.101.3.2.1.3.7","2.16.840.1.101.3.2.1.3.2","2.16.840.1.101.3.2.1.3.18","2.16.840.1.101.3.2.1.3.6","2.16.840.1.101.3.2.1.3.18","2.16.840.1.101.3.2.1.48.13","2.16.840.1.101.3.2.1.48.9","2.16.840.1.101.3.2.1.48.11","2.16.840.1.101.3.2.1.48.4","2.16.840.1.101.3.2.1.48.9"};
    static byte[] bytes(String name) throws IOException {
        try (InputStream input=SyntheticCertificateEvidenceTest.class.getClassLoader().getResourceAsStream(BASE+name)) {
            assertNotNull(input,"missing synthetic fixture "+name); return input.readAllBytes();
        }
    }
    static X509Certificate cert(String file,String provider) throws Exception {
        return (X509Certificate)CertificateFactory.getInstance("X.509",provider).generateCertificate(new ByteArrayInputStream(bytes(file)));
    }
    static Stream<Arguments> policies() {
        List<Arguments> args=new ArrayList<>();
        for (String provider:List.of("SUN","BC")) for(int i=0;i<POLICIES.length;i++) args.add(Arguments.of(provider,String.format("policy-%02d.der",i+1),POLICIES[i]));
        return args.stream();
    }
    static Stream<Arguments> providers() { return Stream.of(Arguments.of("SUN"),Arguments.of("BC")); }
    @ParameterizedTest(name="{0} {1}") @MethodSource("policies")
    void positivePath(String provider,String file,String policy) throws Exception {
        X509Certificate leaf=cert(file,provider),root=cert("root.der",provider);
        leaf.checkValidity(Date.from(TIME)); leaf.verify(root.getPublicKey());
        assertEquals(List.of(leaf),CandidatePathValidation.validate(leaf,root,List.of(),policy,TIME,provider).getCertificates());
    }
    @ParameterizedTest(name="{0} {1}") @MethodSource("policies")
    void wrongPolicy(String provider,String file,String policy) throws Exception {
        X509Certificate leaf=cert(file,provider),root=cert("root.der",provider);
        // Prove setup and signature valid before changing ONLY the requested policy.
        assertNotNull(CandidatePathValidation.validate(leaf,root,List.of(),policy,TIME,provider));
        assertThrows(CertPathBuilderException.class,()->CandidatePathValidation.validate(leaf,root,List.of(),"1.2.3.4.999",TIME,provider));
    }
    @ParameterizedTest @MethodSource("providers")
    void missingPolicy(String provider) throws Exception {
        X509Certificate leaf=cert("no-policy.der",provider),root=cert("root.der",provider);
        leaf.checkValidity(Date.from(TIME)); leaf.verify(root.getPublicKey());
        assertNull(leaf.getExtensionValue("2.5.29.32"));
        assertThrows(CertPathBuilderException.class,()->CandidatePathValidation.validate(leaf,root,List.of(),POLICIES[0],TIME,provider));
    }
    @ParameterizedTest @MethodSource("providers")
    void validityBoundary(String provider) throws Exception {
        X509Certificate leaf=cert("policy-01.der",provider),root=cert("root.der",provider);
        for(Instant t:List.of(leaf.getNotBefore().toInstant(),leaf.getNotAfter().toInstant()))
            assertNotNull(CandidatePathValidation.validate(leaf,root,List.of(),POLICIES[0],t,provider));
        for(Instant t:List.of(leaf.getNotBefore().toInstant().minusSeconds(1),leaf.getNotAfter().toInstant().plusSeconds(1)))
            assertThrows(CertPathBuilderException.class,()->CandidatePathValidation.validate(leaf,root,List.of(),POLICIES[0],t,provider));
    }
    @ParameterizedTest @MethodSource("providers")
    void expired(String provider) throws Exception {
        X509Certificate leaf=cert("expired.der",provider),root=cert("root.der",provider);
        leaf.verify(root.getPublicKey());
        assertThrows(CertificateExpiredException.class,()->leaf.checkValidity(Date.from(TIME)));
        assertThrows(CertPathBuilderException.class,()->CandidatePathValidation.validate(leaf,root,List.of(),POLICIES[0],TIME,provider));
    }
    @ParameterizedTest @MethodSource("providers")
    void badSignature(String provider) throws Exception {
        X509Certificate leaf=cert("bad-signature.der",provider),root=cert("root.der",provider);
        leaf.checkValidity(Date.from(TIME));
        assertThrows(SignatureException.class,()->leaf.verify(root.getPublicKey()));
        assertThrows(CertPathBuilderException.class,()->CandidatePathValidation.validate(leaf,root,List.of(),POLICIES[0],TIME,provider));
    }
    @ParameterizedTest @MethodSource("providers")
    void malformed(String provider) throws Exception {
        assertThrows(CertificateException.class,()->cert("malformed.der",provider));
    }
    static Stream<Arguments> hashes() throws Exception {
        return new String(bytes("MANIFEST.tsv"),java.nio.charset.StandardCharsets.US_ASCII).lines()
                .filter(s->!s.startsWith("#")&&!s.isBlank()).map(s->{String[] f=s.split("\t");return Arguments.of(f[0],f[1]);}).toList().stream();
    }
    @ParameterizedTest(name="immutable {0}") @MethodSource("hashes")
    void immutableBytes(String file,String hash) throws Exception {
        assertEquals(hash,HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes(file))));
    }
}
