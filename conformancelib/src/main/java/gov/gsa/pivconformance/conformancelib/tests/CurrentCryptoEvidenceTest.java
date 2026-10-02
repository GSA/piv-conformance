package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.conformancelib.utilities.CurrentCrypto;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

@Tag("CurrentCandidateEvidence")
public class CurrentCryptoEvidenceTest {
    static Stream<Arguments> vectors() throws IOException {
        try (InputStream input = CurrentCryptoEvidenceTest.class.getClassLoader().getResourceAsStream("standards/current-crypto.tsv")) {
            assertNotNull(input);
            return new String(input.readAllBytes(),StandardCharsets.UTF_8).lines()
                    .filter(s -> !s.startsWith("#") && !s.isBlank()).map(s -> {
                        String[] f=s.split("\t",-1);
                        return Arguments.of(f[0],f[1],f[2],HexFormat.of().parseHex(f[3]));
                    }).toList().stream();
        }
    }
    @ParameterizedTest(name="{0}") @MethodSource("vectors")
    void algorithmEvidence(String id,String method,String expected,byte[] input) {
        Runnable check=()-> {
            switch (method) {
                case "cardKey" -> CurrentCrypto.cardKey(input);
                case "signatureAlgorithm" -> CurrentCrypto.signatureAlgorithm(input);
                default -> throw new IllegalArgumentException(method);
            }
        };
        if (expected.equals("PASS")) assertDoesNotThrow(check::run,id);
        else {
            AssertionError error=assertThrows(AssertionError.class,check::run,id);
            assertTrue(error.getMessage().startsWith(expected+":"),id+": "+error.getMessage());
        }
    }
}
