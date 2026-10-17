package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.conformancelib.utilities.Validator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import javax.net.ssl.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real loopback HTTPS, no external services or permissive trust/hostname callbacks.
 * Tests run serially in the isolated Gradle worker and restore its TLS defaults.
 */
@Tag("Sun")
public class ValidatorTlsTest {
    @TempDir Path directory;

    private record Identity(KeyPair keys, X509Certificate certificate) { }

    private static Identity identity(String ip) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        X500Name name = new X500Name("CN=CCT loopback test");
        Instant now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(3600)), name, keys.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.iPAddress, ip)));
        var holder = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate()));
        return new Identity(keys, new JcaX509CertificateConverter().getCertificate(holder));
    }

    private static SSLContext context(Identity server, X509Certificate trusted) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        KeyManager[] keys = null;
        if (server != null) {
            store.setKeyEntry("server", server.keys.getPrivate(), new char[0],
                    new java.security.cert.Certificate[]{server.certificate});
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(store, new char[0]);
            keys = factory.getKeyManagers();
        }
        store.setCertificateEntry("trusted", trusted);
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(store);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys, trust.getTrustManagers(), null);
        return context;
    }

    @ParameterizedTest(name="CA bundle HTTPS: {0}")
    @ValueSource(strings={"trusted", "untrusted", "wrong-host"})
    void bundleDownloadPreservesTlsValidation(String scenario) throws Exception {
        Identity server = identity(scenario.equals("wrong-host") ? "127.0.0.2" : "127.0.0.1");
        X509Certificate trusted = scenario.equals("untrusted") ? identity("127.0.0.1").certificate : server.certificate;
        SSLSocketFactory originalFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
        HostnameVerifier originalVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
        SSLSocketFactory testFactory = context(null, trusted).getSocketFactory();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        byte[] bundle = CertificateFactory.getInstance("X.509").generateCertPath(List.of(server.certificate)).getEncoded("PKCS7");
        try (SSLServerSocket listener = (SSLServerSocket) context(server, server.certificate).getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            listener.setSoTimeout(5000);
            HttpsURLConnection.setDefaultSSLSocketFactory(testFactory);
            Future<?> response = executor.submit(() -> {
                try (SSLSocket socket = (SSLSocket) listener.accept()) {
                    socket.setSoTimeout(5000);
                    socket.startHandshake();
                    BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
                    String line;
                    while ((line = input.readLine()) != null && !line.isEmpty()) { }
                    if (line != null) {
                        OutputStream out = socket.getOutputStream();
                        out.write(("HTTP/1.1 200 OK\r\nContent-Length: " + bundle.length + "\r\nConnection: close\r\n\r\n")
                                .getBytes(StandardCharsets.US_ASCII));
                        out.write(bundle);
                        out.flush();
                    }
                } catch (SSLException | java.net.SocketException expectedRejection) {
                    if (scenario.equals("trusted")) throw new RuntimeException(expectedRejection);
                } catch (IOException e) { throw new RuntimeException(e); }
            });
            Path output = directory.resolve("bundle.p7b");
            var method = Validator.class.getDeclaredMethod("getCertBundle", String.class, String.class);
            method.setAccessible(true);
            Validator validator = new Validator("SunRsaSign");
            String url = "https://127.0.0.1:" + listener.getLocalPort() + "/bundle.p7b";
            if (scenario.equals("trusted")) {
                CertStore result = (CertStore) method.invoke(validator, url, output.toString());
                assertNotNull(result);
                assertEquals(Set.of(server.certificate), new HashSet<>(result.getCertificates(null)));
                assertArrayEquals(bundle, Files.readAllBytes(output));
            } else {
                InvocationTargetException failure = assertThrows(InvocationTargetException.class,
                        () -> method.invoke(validator, url, output.toString()));
                assertTrue(failure.getCause() instanceof ConformanceTestException, failure.toString());
                String message = failure.getCause().getMessage();
                assertTrue(message.contains(scenario.equals("untrusted") ? "PKIX path" : "subject alternative"), message);
                assertFalse(Files.exists(output), "Rejected HTTPS must not write an untrusted CA bundle");
            }
            response.get(5, TimeUnit.SECONDS);
            assertSame(testFactory, HttpsURLConnection.getDefaultSSLSocketFactory(), "Downloader changed JVM trust defaults");
            assertSame(originalVerifier, HttpsURLConnection.getDefaultHostnameVerifier(), "Downloader changed hostname validation");
        } finally {
            HttpsURLConnection.setDefaultSSLSocketFactory(originalFactory);
            HttpsURLConnection.setDefaultHostnameVerifier(originalVerifier);
            executor.shutdownNow();
        }
    }
}
