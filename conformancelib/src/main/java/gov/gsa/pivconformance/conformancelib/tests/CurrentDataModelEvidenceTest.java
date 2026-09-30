package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.conformancelib.utilities.CurrentDataModel;
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
public class CurrentDataModelEvidenceTest {
    static Stream<Arguments> vectors() throws IOException {
        try (InputStream input = CurrentDataModelEvidenceTest.class.getClassLoader().getResourceAsStream("standards/current-data-model.tsv")) {
            assertNotNull(input, "missing deterministic vector corpus");
            String text = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            return text.lines().filter(s -> !s.startsWith("#") && !s.isBlank()).map(s -> {
                String[] f = s.split("\t", -1);
                return Arguments.of(f[0],f[1],f[2],HexFormat.of().parseHex(f[3]));
            }).toList().stream();
        }
    }

    @ParameterizedTest(name="{0}") @MethodSource("vectors")
    void structuralEvidence(String id, String method, String expected, byte[] bytes) {
        Runnable check = () -> {
            switch (method) {
                case "ccc" -> CurrentDataModel.ccc(bytes);
                case "chuid" -> CurrentDataModel.chuid(bytes);
                case "certificateObject" -> CurrentDataModel.certificateObject(bytes);
                case "securityObject" -> CurrentDataModel.securityObject(bytes);
                case "keyHistory" -> CurrentDataModel.keyHistory(bytes);
                default -> throw new IllegalArgumentException("Unknown vector method: " + method);
            }
        };
        if (expected.equals("PASS")) assertDoesNotThrow(check::run, id);
        else {
            AssertionError failure = assertThrows(AssertionError.class, check::run, id);
            assertTrue(failure.getMessage().startsWith(expected + ":"),
                    "Wrong failure reason for " + id + ": " + failure.getMessage());
        }
    }
}
