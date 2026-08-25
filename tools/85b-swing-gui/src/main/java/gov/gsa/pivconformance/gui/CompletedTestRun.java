package gov.gsa.pivconformance.gui;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Objects;

/** Immutable inputs identifying one successfully completed CCT run. */
public final class CompletedTestRun {
	private final Path m_resultsDirectory;
	private final Path m_databasePath;
	private final Path m_conformanceCsv;
	private final String m_timeStampPrefix;
	private final Instant m_startedAt;
	private final Instant m_finishedAt;
	private final RunResultsSummary m_summary;

	public CompletedTestRun(Path resultsDirectory, Path databasePath, Path conformanceCsv,
			String timeStampPrefix, Instant startedAt, Instant finishedAt, RunResultsSummary summary) {
		m_resultsDirectory = Objects.requireNonNull(resultsDirectory, "resultsDirectory").toAbsolutePath().normalize();
		m_databasePath = Objects.requireNonNull(databasePath, "databasePath").toAbsolutePath().normalize();
		m_conformanceCsv = Objects.requireNonNull(conformanceCsv, "conformanceCsv").toAbsolutePath().normalize();
		m_timeStampPrefix = Objects.requireNonNull(timeStampPrefix, "timeStampPrefix");
		m_startedAt = Objects.requireNonNull(startedAt, "startedAt");
		m_finishedAt = Objects.requireNonNull(finishedAt, "finishedAt");
		m_summary = Objects.requireNonNull(summary, "summary");
		if (m_timeStampPrefix.trim().isEmpty()) {
			throw new IllegalArgumentException("A completed run must have a timestamp prefix");
		}
	}

	public Path getResultsDirectory() { return m_resultsDirectory; }
	public Path getDatabasePath() { return m_databasePath; }
	public Path getConformanceCsv() { return m_conformanceCsv; }
	public String getTimeStampPrefix() { return m_timeStampPrefix; }
	public Instant getStartedAt() { return m_startedAt; }
	public Instant getFinishedAt() { return m_finishedAt; }
	public RunResultsSummary getSummary() { return m_summary; }
}
