package gov.gsa.pivconformance.conformancelib.utilities;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TestRunLogControllerLifecycleTest {
	private static final String CSV_HEADER = "Date,Test Id,Description,Expected Result,Actual Result"
			+ System.lineSeparator();

	@TempDir
	Path tempDirectory;

	@Test
	void resetsBaseLogsBeforeEveryRunWithoutCarryingPreviousResults() throws Exception {
		Path csv = tempDirectory.resolve("logs/conformancelog/conformance_results.csv");
		Path apdu = tempDirectory.resolve("logs/apdu/apdu_transmission.log");

		TestRunLogController.resetLogFile(csv, true);
		TestRunLogController.resetLogFile(apdu, false);
		Files.writeString(csv, "first-run-result" + System.lineSeparator(), StandardCharsets.UTF_8,
				StandardOpenOption.APPEND);
		Files.writeString(apdu, "first-run-apdu", StandardCharsets.UTF_8, StandardOpenOption.APPEND);

		TestRunLogController.resetLogFile(csv, true);
		TestRunLogController.resetLogFile(apdu, false);

		assertEquals(CSV_HEADER, Files.readString(csv, StandardCharsets.UTF_8));
		assertEquals("", Files.readString(apdu, StandardCharsets.UTF_8));
	}
}
