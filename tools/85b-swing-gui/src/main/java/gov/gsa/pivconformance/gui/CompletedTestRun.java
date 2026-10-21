package gov.gsa.pivconformance.gui;

import java.nio.file.Path;
import java.util.Objects;

/** Immutable inputs identifying one completed CCT run. */
final class CompletedTestRun {
	private final Path m_resultsDirectory;
	private final Path m_databasePath;
	private final String m_timeStampPrefix;
	private final RunResults m_results;

	CompletedTestRun(Path resultsDirectory, Path databasePath, String timeStampPrefix) {
		this(resultsDirectory, databasePath, timeStampPrefix, null);
	}

	CompletedTestRun(Path resultsDirectory, Path databasePath, String timeStampPrefix, RunResults results) {
		m_resultsDirectory = Objects.requireNonNull(resultsDirectory, "resultsDirectory").toAbsolutePath().normalize();
		m_databasePath = Objects.requireNonNull(databasePath, "databasePath").toAbsolutePath().normalize();
		m_timeStampPrefix = Objects.requireNonNull(timeStampPrefix, "timeStampPrefix");
		m_results = results;
		if (m_timeStampPrefix.trim().isEmpty()) {
			throw new IllegalArgumentException("A completed run must have a timestamp prefix");
		}
	}

	Path getResultsDirectory() { return m_resultsDirectory; }
	Path getDatabasePath() { return m_databasePath; }
	String getTimeStampPrefix() { return m_timeStampPrefix; }
	RunResults getResults() { return m_results; }
	Path csvPath() {
		return m_resultsDirectory.resolve("logs/conformancelog").resolve(m_timeStampPrefix + "-conformance_results.csv");
	}
}
