package gov.gsa.pivconformance.gui;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

/** Pass/fail counts read without changing the legacy conformance CSV format. */
public final class RunResultsSummary {
	private final int m_passed;
	private final int m_failed;
	private final int m_total;

	private RunResultsSummary(int passed, int failed, int total) {
		m_passed = passed;
		m_failed = failed;
		m_total = total;
	}

	public static RunResultsSummary fromCsv(Path csvPath) throws IOException {
		int passed = 0;
		int failed = 0;
		int total = 0;
		try (Reader reader = Files.newBufferedReader(csvPath, StandardCharsets.UTF_8);
				CSVParser parser = CSVFormat.DEFAULT.withFirstRecordAsHeader().parse(reader)) {
			if (!parser.getHeaderMap().containsKey("Actual Result")) {
				throw new IOException("Conformance CSV is missing the Actual Result column: " + csvPath);
			}
			for (CSVRecord record : parser) {
				String result = record.get("Actual Result").trim();
				if ("Pass".equalsIgnoreCase(result)) {
					passed++;
				} else {
					failed++;
				}
				total++;
			}
		}
		return new RunResultsSummary(passed, failed, total);
	}

	public int getPassed() { return m_passed; }
	public int getFailed() { return m_failed; }
	public int getTotal() { return m_total; }
}
