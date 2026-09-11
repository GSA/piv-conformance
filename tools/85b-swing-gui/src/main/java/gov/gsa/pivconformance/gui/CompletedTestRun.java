package gov.gsa.pivconformance.gui;

import java.nio.file.Path;
import java.util.Objects;

/** Immutable inputs identifying one completed CCT run. */
final class CompletedTestRun {
	private final Path m_resultsDirectory;
	private final Path m_databasePath;
	private final String m_timeStampPrefix;

	CompletedTestRun(Path resultsDirectory, Path databasePath, String timeStampPrefix) {
		m_resultsDirectory = Objects.requireNonNull(resultsDirectory, "resultsDirectory").toAbsolutePath().normalize();
		m_databasePath = Objects.requireNonNull(databasePath, "databasePath").toAbsolutePath().normalize();
		m_timeStampPrefix = Objects.requireNonNull(timeStampPrefix, "timeStampPrefix");
		if (m_timeStampPrefix.trim().isEmpty()) {
			throw new IllegalArgumentException("A completed run must have a timestamp prefix");
		}
	}

	Path getResultsDirectory() { return m_resultsDirectory; }
	Path getDatabasePath() { return m_databasePath; }
	String getTimeStampPrefix() { return m_timeStampPrefix; }
}
