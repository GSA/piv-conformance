package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.cardlib.card.client.*;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterProviderSingleton;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.launcher.*;
import org.junit.platform.launcher.core.*;
import javax.smartcardio.*;
import java.nio.file.*;
import java.sql.*;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises generated database mappings, argument provider and raw acquisition.
 * The fake terminal cannot connect or transmit; no physical card or PIN is used.
 */
@Tag("CurrentCandidateEvidence")
public class CurrentExecutionEvidenceTest {
    private record Row(String id, String className, String method, String container) { }

    private static List<Row> rows() throws Exception {
        Path path = Path.of(System.getProperty("cct.candidateDatabase"));
        assertTrue(Files.isRegularFile(path), "Generate the candidate database before running evidence");
        try (Connection db = DriverManager.getConnection("jdbc:sqlite:file:" + path + "?mode=ro")) {
            try (var result = db.createStatement().executeQuery("SELECT Profile,Readiness FROM StandardsProfile")) {
                assertTrue(result.next());
                assertEquals("CURRENT_2026_CANDIDATE", result.getString(1));
                assertEquals("NOT_YET_READY", result.getString(2));
            }
            List<Row> rows = new ArrayList<>();
            try (var result = db.createStatement().executeQuery("SELECT c.TestCaseIdentifier,s.Class,s.Method,c.TestCaseContainer FROM TestCases c JOIN TestsToSteps l ON l.TestId=c.Id JOIN TestSteps s ON s.Id=l.TestStepId WHERE c.Enabled=1 ORDER BY c.Id")) {
                while (result.next()) rows.add(new Row(result.getString(1),result.getString(2),result.getString(3),result.getString(4)));
            }
            assertEquals(13, rows.size(), "Update execution evidence when candidate scope changes");
            return rows;
        }
    }

    private static TestExecutionResult execute(Row row, Map<String,byte[]> objects) {
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
                object.setBytes(raw.clone());
                return MiddlewareStatus.PIV_OK;
            }
        });
        String method = row.className + "#" + row.method + "(java.lang.String, org.junit.jupiter.api.TestReporter)";
        parameters.addContainer(method, row.container);
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

    static Stream<Arguments> vectors() throws Exception { return CurrentDataModelEvidenceTest.vectors(); }

    @ParameterizedTest(name="entry point: {0}") @MethodSource("vectors")
    void dataThroughDatabase(String id, String method, String expected, byte[] raw) throws Exception {
        List<Row> selected = rows().stream().filter(r -> r.method.equals(method)).toList();
        assertFalse(selected.isEmpty(), "No candidate DB entry for " + method);
        for (Row row : selected) {
            var result = execute(row, Map.of(APDUConstants.getStringForFieldNamed(row.container), raw));
            assertResult(result, expected);
        }
    }

    private static void assertResult(TestExecutionResult result, String expected) {
        if (expected.equals("PASS")) assertEquals(TestExecutionResult.Status.SUCCESSFUL,result.getStatus(),result.toString());
        else {
            assertEquals(TestExecutionResult.Status.FAILED,result.getStatus(),result.toString());
            Throwable failure=result.getThrowable().orElseThrow();
            assertTrue(failure instanceof AssertionError, "Failure must be an assertion, not setup: " + failure);
            assertTrue(failure.getMessage().startsWith(expected+":"), "Wrong failure reason: " + failure);
        }
    }

    static Stream<Arguments> missingRows() throws Exception {
        return rows().stream().map(r -> Arguments.of(r.id, r));
    }

    @ParameterizedTest(name="absent object: {0}") @MethodSource("missingRows")
    void absenceNeverBecomesPass(String id, Row row) {
        var result = execute(row, Map.of());
        if (row.method.equals("keyHistory")) assertEquals(TestExecutionResult.Status.ABORTED, result.getStatus());
        else assertResult(result,"CANDIDATE-INPUT");
    }
}
